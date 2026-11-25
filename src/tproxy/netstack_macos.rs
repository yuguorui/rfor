//! Userspace TCP and stateless UDP packet layer on top of `smoltcp` for macOS `utun`.

use anyhow::{anyhow, Result};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    IpAddress, IpCidr, IpListenEndpoint, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv4Repr,
    Ipv6Address, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket, UdpRepr, IPV4_HEADER_LEN,
    IPV6_HEADER_LEN, UDP_HEADER_LEN,
};
use std::cmp::Reverse;
use std::collections::hash_map::RandomState;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::hash::BuildHasher;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};

use super::utun_macos;

const STREAM_CHANNEL_SIZE: usize = 512;
const TOTAL_TCP_IN_QUEUE_BUDGET: usize = 4096;
const MIN_SHARD_IN_QUEUE: usize = 512;
const TOTAL_PENDING_EGRESS_BUDGET: usize = 2048;
const MIN_SHARD_PENDING_EGRESS: usize = 256;
const TOTAL_TCP_OUT_CHANNEL_BUDGET: usize = 4096;
const INGRESS_DRAIN_BATCH: usize = 64;
const MAX_ABORT_POLLS: u8 = 4;
const MAX_ZERO_DELAY_BACKOFF_MS: u64 = 50;

pub(crate) type UdpPacketMsg = (Vec<u8>, SocketAddr, SocketAddr);

#[derive(Debug, Clone)]
pub(crate) struct NetStackConfig {
    pub mtu: usize,
    pub shards: usize,
    pub tcp_rx_buf: usize,
    pub tcp_tx_buf: usize,
    pub max_tcp_sockets: usize,
    pub tcp_keepalive: Duration,
    pub tcp_timeout: Duration,
    pub syn_handshake_timeout: Duration,
    pub close_linger_timeout: Duration,
    pub time_wait_linger: Duration,
}

impl NetStackConfig {
    pub(crate) fn shard_count(&self) -> usize {
        self.shards.max(1)
    }

    pub(crate) fn shard_in_channel_size(&self) -> usize {
        TOTAL_TCP_IN_QUEUE_BUDGET
            .div_ceil(self.shard_count())
            .max(MIN_SHARD_IN_QUEUE)
    }

    pub(crate) fn shard_max_pending_egress(&self) -> usize {
        TOTAL_PENDING_EGRESS_BUDGET
            .div_ceil(self.shard_count())
            .max(MIN_SHARD_PENDING_EGRESS)
    }

    pub(crate) fn tcp_out_channel_size(&self) -> usize {
        TOTAL_TCP_OUT_CHANNEL_BUDGET
    }
}

impl Default for NetStackConfig {
    fn default() -> Self {
        let shards = std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 4))
            .unwrap_or(2);
        Self {
            mtu: utun_macos::UTUN_MTU as usize,
            shards,
            tcp_rx_buf: 64 * 1024,
            tcp_tx_buf: 64 * 1024,
            max_tcp_sockets: 2048,
            tcp_keepalive: Duration::from_secs(30),
            tcp_timeout: Duration::from_secs(120),
            syn_handshake_timeout: Duration::from_secs(15),
            close_linger_timeout: Duration::from_secs(10),
            time_wait_linger: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchOutcome {
    Sent,
    Ignored,
    Full,
    Closed,
}

fn mix_hash_bytes(state: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *state ^= b as u64;
        *state = state.wrapping_mul(0x100000001b3);
    }
}

fn tcp_tuple_shard(pkt: &[u8], seed: u64, shard_count: usize) -> Option<usize> {
    let version = pkt.first().map(|b| b >> 4)?;
    let (src_ip, dst_ip, ports) = match version {
        4 => {
            if pkt.len() < IPV4_HEADER_LEN || pkt[9] != 6 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < IPV4_HEADER_LEN || pkt.len() < ihl + 4 {
                return None;
            }
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff;
            if frag != 0 {
                return None;
            }
            (&pkt[12..16], &pkt[16..20], &pkt[ihl..ihl + 4])
        }
        6 => {
            if pkt.len() < IPV6_HEADER_LEN + 4 || pkt[6] != 6 {
                return None;
            }
            (&pkt[8..24], &pkt[24..40], &pkt[40..44])
        }
        _ => return None,
    };

    if shard_count <= 1 {
        return Some(0);
    }

    let mut h = seed ^ 0xcbf29ce484222325u64;
    mix_hash_bytes(&mut h, src_ip);
    mix_hash_bytes(&mut h, dst_ip);
    mix_hash_bytes(&mut h, ports);
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d049bb133111eb);
    h ^= h >> 31;
    Some((h as usize) % shard_count)
}

pub(crate) struct TcpIngressRouter {
    shards: Vec<mpsc::Sender<Vec<u8>>>,
    hash_seed: u64,
}

impl TcpIngressRouter {
    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub(crate) fn shard_for_packet(&self, pkt: &[u8]) -> Option<usize> {
        tcp_tuple_shard(pkt, self.hash_seed, self.shards.len())
    }

    pub(crate) fn try_dispatch(&self, pkt: &[u8]) -> DispatchOutcome {
        let Some(idx) = self.shard_for_packet(pkt) else {
            return DispatchOutcome::Ignored;
        };
        match self.shards[idx].try_send(pkt.to_vec()) {
            Ok(()) => DispatchOutcome::Sent,
            Err(mpsc::error::TrySendError::Full(_)) => DispatchOutcome::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => DispatchOutcome::Closed,
        }
    }

    #[cfg(test)]
    pub(crate) async fn send(&self, pkt: Vec<u8>) -> Result<usize> {
        let idx = self
            .shard_for_packet(&pkt)
            .ok_or_else(|| anyhow!("TCP packet could not be routed to a shard"))?;
        self.shards[idx]
            .send(pkt)
            .await
            .map_err(|_| anyhow!("TCP shard {} ingress channel closed", idx))?;
        Ok(idx)
    }
}

/// Return `true` if `pkt` is an IPv4 or IPv6 packet encapsulating TCP.
pub(crate) fn is_tcp_packet(pkt: &[u8]) -> bool {
    (pkt.len() >= IPV4_HEADER_LEN && (pkt[0] >> 4) == 4 && pkt[9] == 6)
        || (pkt.len() >= IPV6_HEADER_LEN && (pkt[0] >> 4) == 6 && pkt[6] == 6)
}

/// Return `true` if `pkt` is an IPv4 or IPv6 packet encapsulating UDP.
pub(crate) fn is_udp_packet(pkt: &[u8]) -> bool {
    (pkt.len() >= IPV4_HEADER_LEN && (pkt[0] >> 4) == 4 && pkt[9] == 17)
        || (pkt.len() >= IPV6_HEADER_LEN && (pkt[0] >> 4) == 6 && pkt[6] == 17)
}

fn is_valid_unicast_v4(addr: Ipv4Addr) -> bool {
    !(addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast())
}

fn is_valid_unicast_v6(addr: Ipv6Addr) -> bool {
    !(addr.is_unspecified() || addr.is_multicast())
}

/// Parse an IPv4 or IPv6 UDP packet into `(payload, src_addr, dst_addr)`.
/// Rejects malformed packets, IPv4 fragments, and non-unicast addresses.
pub(crate) fn parse_udp_packet(pkt: &[u8]) -> Option<UdpPacketMsg> {
    let version = IpVersion::of_packet(pkt.first().map(|_| pkt)?).ok()?;
    let (src_ip, dst_ip, l4_payload) = match version {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Udp || ip.more_frags() || ip.frag_offset() != 0 {
                return None;
            }
            let src = ip.src_addr();
            let dst = ip.dst_addr();
            if !is_valid_unicast_v4(src) || !is_valid_unicast_v4(dst) {
                return None;
            }
            (IpAddr::V4(src), IpAddr::V4(dst), ip.payload())
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let src = ip.src_addr();
            let dst = ip.dst_addr();
            if !is_valid_unicast_v6(src) || !is_valid_unicast_v6(dst) {
                return None;
            }
            (IpAddr::V6(src), IpAddr::V6(dst), ip.payload())
        }
    };

    let udp = UdpPacket::new_checked(l4_payload).ok()?;
    if udp.dst_port() == 0 {
        return None;
    }
    Some((
        udp.payload().to_vec(),
        SocketAddr::new(src_ip, udp.src_port()),
        SocketAddr::new(dst_ip, udp.dst_port()),
    ))
}

/// Encode an IPv4 or IPv6 UDP datagram with full IP and UDP checksums.
pub(crate) fn build_udp_packet(payload: &[u8], src: SocketAddr, dst: SocketAddr) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }
    let udp_len = UDP_HEADER_LEN.checked_add(payload.len())?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;
    let caps = ChecksumCapabilities::default();
    let udp_repr = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let total_len = IPV4_HEADER_LEN.checked_add(udp_len_u16 as usize)?;
            if u16::try_from(total_len).is_err() {
                return None;
            }
            let ip_repr = Ipv4Repr {
                src_addr: src_v4,
                dst_addr: dst_v4,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let mut pkt = vec![0u8; ip_repr.buffer_len() + udp_len];
            let (ip_buf, l4_buf) = pkt.split_at_mut(ip_repr.buffer_len());
            ip_repr.emit(&mut Ipv4Packet::new_unchecked(ip_buf), &caps);
            let mut udp_pkt = UdpPacket::new_unchecked(l4_buf);
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv4(src_v4),
                &IpAddress::Ipv4(dst_v4),
                payload.len(),
                |dst_payload| dst_payload.copy_from_slice(payload),
                &caps,
            );
            Some(pkt)
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let ip_repr = Ipv6Repr {
                src_addr: src_v6,
                dst_addr: dst_v6,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let mut pkt = vec![0u8; ip_repr.buffer_len() + udp_len];
            let (ip_buf, l4_buf) = pkt.split_at_mut(ip_repr.buffer_len());
            ip_repr.emit(&mut Ipv6Packet::new_unchecked(ip_buf));
            let mut udp_pkt = UdpPacket::new_unchecked(l4_buf);
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv6(src_v6),
                &IpAddress::Ipv6(dst_v6),
                payload.len(),
                |dst_payload| dst_payload.copy_from_slice(payload),
                &caps,
            );
            Some(pkt)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalfState {
    Open,
    Closing,
    Closed,
}

struct DirtyQueue {
    handles: Mutex<Vec<SocketHandle>>,
    notify: Notify,
}

impl DirtyQueue {
    fn new() -> Self {
        Self {
            handles: Mutex::new(Vec::new()),
            notify: Notify::new(),
        }
    }

    fn push(&self, handle: SocketHandle) {
        let mut q = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        let was_empty = q.is_empty();
        q.push(handle);
        drop(q);
        if was_empty {
            self.notify.notify_one();
        }
    }

    fn drain_into(&self, out: &mut Vec<SocketHandle>) {
        let mut q = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        out.append(&mut *q);
    }
}

struct TcpSocketControl {
    recv_buf: VecDeque<u8>,
    recv_cap: usize,
    recv_waker: Option<Waker>,
    recv_closed: bool,
    recv_aborted: bool,
    rx_backpressured: bool,

    send_buf: VecDeque<u8>,
    send_cap: usize,
    send_waker: Option<Waker>,
    send_state: HalfState,
    shutdown_called: bool,

    queued_dirty: bool,
    aborted: bool,
    dropped: bool,
    #[cfg(test)]
    established: bool,
}

impl TcpSocketControl {
    fn new(recv_cap: usize, send_cap: usize) -> Self {
        Self {
            recv_buf: VecDeque::new(),
            recv_cap,
            recv_waker: None,
            recv_closed: false,
            recv_aborted: false,
            rx_backpressured: false,
            send_buf: VecDeque::new(),
            send_cap,
            send_waker: None,
            send_state: HalfState::Open,
            shutdown_called: false,
            queued_dirty: false,
            aborted: false,
            dropped: false,
            #[cfg(test)]
            established: false,
        }
    }

    fn wake_recv(&mut self) {
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }

    fn wake_send(&mut self) {
        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
    }

    fn wake_all(&mut self) {
        self.wake_recv();
        self.wake_send();
    }
}

fn mark_dirty_locked(ctl: &mut TcpSocketControl) -> bool {
    if !ctl.queued_dirty {
        ctl.queued_dirty = true;
        true
    } else {
        false
    }
}

fn replace_waker(slot: &mut Option<Waker>, waker: &Waker) {
    if let Some(old) = slot.replace(waker.clone()) {
        if !old.will_wake(waker) {
            old.wake();
        }
    }
}

pub(crate) struct StackTcpStream {
    handle: SocketHandle,
    dirty: Arc<DirtyQueue>,
    control: Arc<Mutex<TcpSocketControl>>,
}

impl StackTcpStream {
    #[cfg(test)]
    fn is_established(&self) -> bool {
        self.control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .established
    }

    /// Abort the underlying TCP socket with `RST` instead of graceful `FIN`.
    pub(crate) fn abort(&self) {
        let need_push = {
            let mut ctl = self.control.lock().unwrap_or_else(|e| e.into_inner());
            ctl.aborted = true;
            ctl.send_buf.clear();
            ctl.recv_buf.clear();
            mark_dirty_locked(&mut ctl)
        };
        if need_push {
            self.dirty.push(self.handle);
        }
    }
}

impl Drop for StackTcpStream {
    fn drop(&mut self) {
        let need_push = {
            let mut ctl = self.control.lock().unwrap_or_else(|e| e.into_inner());
            ctl.dropped = true;
            ctl.recv_waker = None;
            ctl.send_waker = None;
            ctl.recv_buf.clear();
            if !ctl.aborted {
                // Dropping without shutdown/data/peer-EOF indicates an aborted
                // session (e.g. connect failure or DROP rule) that should send RST.
                if !ctl.shutdown_called && ctl.send_buf.is_empty() && !ctl.recv_closed {
                    ctl.aborted = true;
                } else if ctl.send_state == HalfState::Open {
                    ctl.send_state = HalfState::Closing;
                }
            }
            mark_dirty_locked(&mut ctl)
        };
        if need_push {
            self.dirty.push(self.handle);
        }
    }
}

impl AsyncRead for StackTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut ctl = self.control.lock().unwrap_or_else(|e| e.into_inner());
        if !ctl.recv_buf.is_empty() {
            let max_read = buf.remaining().min(ctl.recv_buf.len());
            let mut need_push = false;
            if max_read > 0 {
                let dst = buf.initialize_unfilled_to(max_read);
                let (first, second) = ctl.recv_buf.as_slices();
                let first_n = max_read.min(first.len());
                dst[..first_n].copy_from_slice(&first[..first_n]);
                if first_n < max_read {
                    let second_n = max_read - first_n;
                    dst[first_n..max_read].copy_from_slice(&second[..second_n]);
                }
                ctl.recv_buf.drain(..max_read);
                buf.advance(max_read);
                if ctl.rx_backpressured
                    && (ctl.recv_buf.len() <= ctl.recv_cap / 2 || ctl.recv_buf.is_empty())
                {
                    need_push = mark_dirty_locked(&mut ctl);
                }
            }
            drop(ctl);
            if need_push {
                self.dirty.push(self.handle);
            }
            return Poll::Ready(Ok(()));
        }

        if ctl.recv_aborted {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
        }
        if ctl.recv_closed {
            return Poll::Ready(Ok(()));
        }

        replace_waker(&mut ctl.recv_waker, cx.waker());
        let need_push = if ctl.rx_backpressured {
            mark_dirty_locked(&mut ctl)
        } else {
            false
        };
        drop(ctl);
        if need_push {
            self.dirty.push(self.handle);
        }
        Poll::Pending
    }
}

impl AsyncWrite for StackTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut ctl = self.control.lock().unwrap_or_else(|e| e.into_inner());
        if ctl.aborted || ctl.send_state != HalfState::Open {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }

        let avail = ctl.send_cap.saturating_sub(ctl.send_buf.len());
        if avail == 0 {
            replace_waker(&mut ctl.send_waker, cx.waker());
            return Poll::Pending;
        }

        let n = buf.len().min(avail);
        ctl.send_buf.extend(&buf[..n]);
        let need_push = if n > 0 {
            mark_dirty_locked(&mut ctl)
        } else {
            false
        };
        drop(ctl);
        if need_push {
            self.dirty.push(self.handle);
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut ctl = self.control.lock().unwrap_or_else(|e| e.into_inner());
        ctl.shutdown_called = true;
        if ctl.send_state == HalfState::Closed {
            return if ctl.aborted {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            } else {
                Poll::Ready(Ok(()))
            };
        }
        if ctl.aborted {
            ctl.send_state = HalfState::Closed;
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }

        if ctl.send_state == HalfState::Open {
            ctl.send_state = HalfState::Closing;
        }
        replace_waker(&mut ctl.send_waker, cx.waker());
        let need_push = mark_dirty_locked(&mut ctl);
        drop(ctl);
        if need_push {
            self.dirty.push(self.handle);
        }
        Poll::Pending
    }
}

pub(crate) struct TcpListener {
    stream_rx: mpsc::Receiver<(StackTcpStream, SocketAddr, SocketAddr)>,
}

impl TcpListener {
    pub(crate) async fn accept(&mut self) -> Option<(StackTcpStream, SocketAddr, SocketAddr)> {
        self.stream_rx.recv().await
    }
}

struct LoopbackIpDevice {
    ingress: VecDeque<Vec<u8>>,
    egress: VecDeque<Vec<u8>>,
    mtu: usize,
    max_pending_egress: usize,
}

impl LoopbackIpDevice {
    fn new(mtu: usize, max_pending_egress: usize) -> Self {
        Self {
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
            mtu,
            max_pending_egress: max_pending_egress.max(1),
        }
    }
}

struct IpRxToken(Vec<u8>);

impl RxToken for IpRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct IpTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl<'a> TxToken for IpTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.0.push_back(buf);
        res
    }
}

impl Device for LoopbackIpDevice {
    type RxToken<'a> = IpRxToken;
    type TxToken<'a> = IpTxToken<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.egress.len() >= self.max_pending_egress {
            return None;
        }
        let pkt = self.ingress.pop_front()?;
        Some((IpRxToken(pkt), IpTxToken(&mut self.egress)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.egress.len() >= self.max_pending_egress {
            return None;
        }
        Some(IpTxToken(&mut self.egress))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpTuple {
    src: SocketAddr,
    dst: SocketAddr,
}

struct SocketEntry {
    control: Arc<Mutex<TcpSocketControl>>,
    tuple: Option<TcpTuple>,
    created_at: Instant,
    had_tuple: bool,
    time_wait_since: Option<Instant>,
    closing_since: Option<Instant>,
    abort_polls: u8,
}

fn create_smoltcp_interface(device: &mut LoopbackIpDevice, now: SmolInstant) -> Result<Interface> {
    let mut cfg = InterfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
    cfg.random_seed = RandomState::new().hash_one(0u64);
    let mut iface = Interface::new(cfg, device, now);
    iface.update_ip_addrs(|ip_addrs| {
        let _ = ip_addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0));
        let _ = ip_addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0));
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        .map_err(|e| anyhow!("failed to configure smoltcp default IPv4 route: {:?}", e))?;
    iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
        .map_err(|e| anyhow!("failed to configure smoltcp default IPv6 route: {:?}", e))?;
    iface.set_any_ip(true);
    Ok(iface)
}

fn parse_tcp_syn_endpoints(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr, bool)> {
    let version = IpVersion::of_packet(pkt.first().map(|_| pkt)?).ok()?;
    let (src_ip, dst_ip, l4_payload) = match version {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp || ip.more_frags() || ip.frag_offset() != 0 {
                return None;
            }
            let src = ip.src_addr();
            let dst = ip.dst_addr();
            if !is_valid_unicast_v4(src) || !is_valid_unicast_v4(dst) {
                return None;
            }
            (IpAddr::V4(src), IpAddr::V4(dst), ip.payload())
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let src = ip.src_addr();
            let dst = ip.dst_addr();
            if !is_valid_unicast_v6(src) || !is_valid_unicast_v6(dst) {
                return None;
            }
            (IpAddr::V6(src), IpAddr::V6(dst), ip.payload())
        }
    };

    let tcp = TcpPacket::new_checked(l4_payload).ok()?;
    let is_pure_syn = tcp.syn() && !tcp.ack();
    Some((
        SocketAddr::new(src_ip, tcp.src_port()),
        SocketAddr::new(dst_ip, tcp.dst_port()),
        is_pure_syn,
    ))
}

pub(crate) struct TcpStack {
    config: NetStackConfig,
    dirty: Arc<DirtyQueue>,
    tcp_in_rx: mpsc::Receiver<Vec<u8>>,
    tcp_out_tx: mpsc::Sender<Vec<u8>>,
    stream_tx: mpsc::Sender<(StackTcpStream, SocketAddr, SocketAddr)>,
    device: LoopbackIpDevice,
    iface: Interface,
    socket_set: SocketSet<'static>,
    sockets: HashMap<SocketHandle, SocketEntry>,
    active_tuples: HashMap<TcpTuple, SocketHandle>,
    active_socket_count: Arc<AtomicUsize>,
    dirty_scratch: Vec<SocketHandle>,
    touched_scratch: Vec<SocketHandle>,
    pending_abort_reap: Vec<SocketHandle>,
    reap_deadlines: BinaryHeap<Reverse<(Instant, SocketHandle)>>,
    egress_congested: bool,
    last_poll_at: Instant,
    zero_delay_streak: u32,
}

fn create_tcp_stack_with_listener(
    config: NetStackConfig,
    tcp_in_rx: mpsc::Receiver<Vec<u8>>,
    tcp_out_tx: mpsc::Sender<Vec<u8>>,
    stream_tx: mpsc::Sender<(StackTcpStream, SocketAddr, SocketAddr)>,
    max_pending_egress: usize,
) -> Result<TcpStack> {
    let mut device = LoopbackIpDevice::new(config.mtu, max_pending_egress);
    let now_std = Instant::now();
    let iface = create_smoltcp_interface(&mut device, SmolInstant::from(now_std))?;

    Ok(TcpStack {
        config,
        dirty: Arc::new(DirtyQueue::new()),
        tcp_in_rx,
        tcp_out_tx,
        stream_tx,
        device,
        iface,
        socket_set: SocketSet::new(vec![]),
        sockets: HashMap::new(),
        active_tuples: HashMap::new(),
        active_socket_count: Arc::new(AtomicUsize::new(0)),
        dirty_scratch: Vec::new(),
        touched_scratch: Vec::new(),
        pending_abort_reap: Vec::new(),
        reap_deadlines: BinaryHeap::new(),
        egress_congested: false,
        last_poll_at: now_std,
        zero_delay_streak: 0,
    })
}

#[cfg(test)]
pub(crate) fn create_tcp_stack(
    config: NetStackConfig,
    tcp_in_rx: mpsc::Receiver<Vec<u8>>,
    tcp_out_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(TcpStack, TcpListener)> {
    let (stream_tx, stream_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
    let max_pending_egress = config.shard_max_pending_egress();
    let stack = create_tcp_stack_with_listener(
        config,
        tcp_in_rx,
        tcp_out_tx,
        stream_tx,
        max_pending_egress,
    )?;
    Ok((stack, TcpListener { stream_rx }))
}

pub(crate) fn create_sharded_tcp_stack(
    config: NetStackConfig,
    tcp_out_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(Vec<TcpStack>, TcpIngressRouter, TcpListener)> {
    let shard_count = config.shard_count();
    let per_shard_max = config.max_tcp_sockets.div_ceil(shard_count).max(1);
    let in_cap = config.shard_in_channel_size();
    let max_pending_egress = config.shard_max_pending_egress();
    let (stream_tx, stream_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
    let mut stacks = Vec::with_capacity(shard_count);
    let mut in_txs = Vec::with_capacity(shard_count);

    for _ in 0..shard_count {
        let (in_tx, in_rx) = mpsc::channel(in_cap);
        let shard_cfg = NetStackConfig {
            max_tcp_sockets: per_shard_max,
            shards: 1,
            ..config.clone()
        };
        let stack = create_tcp_stack_with_listener(
            shard_cfg,
            in_rx,
            tcp_out_tx.clone(),
            stream_tx.clone(),
            max_pending_egress,
        )?;
        stacks.push(stack);
        in_txs.push(in_tx);
    }

    let hash_seed = RandomState::new().hash_one(0x9e37_79b9_7f4a_7c15u64);
    Ok((
        stacks,
        TcpIngressRouter {
            shards: in_txs,
            hash_seed,
        },
        TcpListener { stream_rx },
    ))
}

fn may_recv_closed(state: TcpState) -> bool {
    !matches!(
        state,
        TcpState::Listen
            | TcpState::SynReceived
            | TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
    )
}

fn is_closing_state(state: TcpState) -> bool {
    matches!(
        state,
        TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing | TcpState::LastAck
    )
}

fn abort_socket_control(socket: &mut TcpSocket, ctl: &mut TcpSocketControl) {
    socket.abort();
    ctl.aborted = true;
    ctl.recv_aborted = true;
    ctl.recv_closed = true;
    ctl.send_state = HalfState::Closed;
    ctl.send_buf.clear();
    ctl.wake_all();
}

fn drain_socket_rx(socket: &mut TcpSocket, ctl: &mut TcpSocketControl) -> std::result::Result<bool, ()> {
    let mut did_drain = false;
    while socket.can_recv() {
        let avail = ctl.recv_cap.saturating_sub(ctl.recv_buf.len());
        if avail == 0 {
            break;
        }
        let recv_buf = &mut ctl.recv_buf;
        match socket.recv(|data| {
            let take = data.len().min(avail);
            recv_buf.extend(&data[..take]);
            (take, take)
        }) {
            Ok(0) => break,
            Ok(_) => did_drain = true,
            Err(_) => {
                abort_socket_control(socket, ctl);
                return Err(());
            }
        }
    }
    ctl.rx_backpressured = socket.can_recv();
    Ok(did_drain)
}

fn flush_socket_tx(socket: &mut TcpSocket, ctl: &mut TcpSocketControl) -> std::result::Result<bool, ()> {
    let mut did_send = false;
    while socket.can_send() && !ctl.send_buf.is_empty() {
        let n = {
            let (first, _) = ctl.send_buf.as_slices();
            if first.is_empty() {
                break;
            }
            socket.send_slice(first)
        };
        match n {
            Ok(0) => break,
            Ok(sent) => {
                ctl.send_buf.drain(..sent);
                did_send = true;
            }
            Err(_) => {
                abort_socket_control(socket, ctl);
                return Err(());
            }
        }
    }
    Ok(did_send)
}

impl TcpStack {
    #[cfg(test)]
    pub(crate) fn active_socket_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.active_socket_count)
    }

    fn remove_socket(&mut self, handle: SocketHandle) {
        if let Some(mut entry) = self.sockets.remove(&handle) {
            if let Some(tuple) = entry.tuple.take() {
                if self.active_tuples.get(&tuple) == Some(&handle) {
                    self.active_tuples.remove(&tuple);
                }
            }
            {
                let mut ctl = entry.control.lock().unwrap_or_else(|e| e.into_inner());
                ctl.recv_closed = true;
                ctl.send_state = HalfState::Closed;
                ctl.wake_all();
            }
            self.socket_set.remove(handle);
            self.active_socket_count
                .store(self.sockets.len(), Ordering::Release);
        }
    }

    fn handle_tcp_packet(&mut self, pkt: Vec<u8>, now: Instant) {
        let Some((src, dst, is_pure_syn)) = parse_tcp_syn_endpoints(&pkt) else {
            return;
        };

        let tuple = TcpTuple { src, dst };
        if is_pure_syn && dst.port() != 0 {
            if let Some(&existing_handle) = self.active_tuples.get(&tuple) {
                let can_replace = if self.sockets.contains_key(&existing_handle) {
                    let state = self
                        .socket_set
                        .get::<TcpSocket>(existing_handle)
                        .state();
                    matches!(state, TcpState::TimeWait | TcpState::Closed)
                } else {
                    true
                };
                if can_replace {
                    self.remove_socket(existing_handle);
                } else {
                    // Duplicate/retransmitted SYN for an already active 4-tuple:
                    // feed to smoltcp without spawning another socket or stream.
                    self.touched_scratch.push(existing_handle);
                    self.device.ingress.push_back(pkt);
                    return;
                }
            }

            if self.sockets.len() >= self.config.max_tcp_sockets {
                // Hand to smoltcp with no matching Listen socket so it emits RST.
                self.device.ingress.push_back(pkt);
                return;
            }

            let Ok(permit) = self.stream_tx.try_reserve() else {
                // Listener saturated or closed: feed packet without socket so smoltcp emits RST.
                self.device.ingress.push_back(pkt);
                return;
            };

            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; self.config.tcp_rx_buf]),
                TcpSocketBuffer::new(vec![0u8; self.config.tcp_tx_buf]),
            );
            socket.set_keep_alive(Some(self.config.tcp_keepalive.into()));
            socket.set_timeout(Some(self.config.tcp_timeout.into()));

            let listen_ep = IpListenEndpoint {
                addr: Some(IpAddress::from(dst.ip())),
                port: dst.port(),
            };
            if socket.listen(listen_ep).is_err() {
                drop(permit);
                return;
            }

            let control = Arc::new(Mutex::new(TcpSocketControl::new(
                self.config.tcp_rx_buf,
                self.config.tcp_tx_buf,
            )));
            let handle = self.socket_set.add(socket);
            let stream = StackTcpStream {
                handle,
                dirty: Arc::clone(&self.dirty),
                control: Arc::clone(&control),
            };
            permit.send((stream, src, dst));

            self.sockets.insert(
                handle,
                SocketEntry {
                    control,
                    tuple: Some(tuple),
                    created_at: now,
                    had_tuple: false,
                    time_wait_since: None,
                    closing_since: None,
                    abort_polls: 0,
                },
            );
            self.active_tuples.insert(tuple, handle);
            self.active_socket_count
                .store(self.sockets.len(), Ordering::Release);
            self.reap_deadlines
                .push(Reverse((now + self.config.syn_handshake_timeout, handle)));
            self.touched_scratch.push(handle);
        } else if let Some(&existing_handle) = self.active_tuples.get(&tuple) {
            self.touched_scratch.push(existing_handle);
        }

        self.device.ingress.push_back(pkt);
    }

    fn sync_handle_pre_poll(&mut self, handle: SocketHandle, now: Instant) -> bool {
        let Some(entry) = self.sockets.get_mut(&handle) else {
            return false;
        };
        let socket = self.socket_set.get_mut::<TcpSocket>(handle);
        let mut ctl = entry.control.lock().unwrap_or_else(|e| e.into_inner());
        ctl.queued_dirty = false;

        let state = socket.state();
        if state == TcpState::Listen {
            return ctl.aborted || ctl.dropped;
        }
        if matches!(state, TcpState::Closed | TcpState::TimeWait) {
            return false;
        }

        if ctl.aborted {
            abort_socket_control(socket, &mut ctl);
            self.pending_abort_reap.push(handle);
            return false;
        }

        let mut wake_recv = false;
        if !ctl.dropped && ctl.rx_backpressured {
            match drain_socket_rx(socket, &mut ctl) {
                Ok(drained) => wake_recv = drained,
                Err(()) => {
                    self.pending_abort_reap.push(handle);
                    return false;
                }
            }
        }
        if wake_recv {
            ctl.wake_recv();
        }

        let mut wake_send = match flush_socket_tx(socket, &mut ctl) {
            Ok(sent) => sent,
            Err(()) => {
                self.pending_abort_reap.push(handle);
                return false;
            }
        };

        // Complete half-close pre-poll when send_buf already flushed and 3-way handshake finished.
        if ctl.send_state == HalfState::Closing
            && ctl.send_buf.is_empty()
            && !matches!(socket.state(), TcpState::Listen | TcpState::SynReceived)
        {
            socket.close();
            ctl.send_state = HalfState::Closed;
            if entry.closing_since.is_none() {
                entry.closing_since = Some(now);
                self.reap_deadlines
                    .push(Reverse((now + self.config.close_linger_timeout, handle)));
            }
            wake_send = true;
        }

        if wake_send {
            ctl.wake_send();
        }

        if ctl.dropped && entry.closing_since.is_none() {
            entry.closing_since = Some(now);
            self.reap_deadlines
                .push(Reverse((now + self.config.close_linger_timeout, handle)));
        }

        false
    }

    fn sync_handle_post_poll(
        &mut self,
        handle: SocketHandle,
        now: Instant,
        check_timeouts: bool,
    ) -> (bool, bool) {
        let Some(entry) = self.sockets.get_mut(&handle) else {
            return (false, false);
        };
        let socket = self.socket_set.get_mut::<TcpSocket>(handle);
        let mut ctl = entry.control.lock().unwrap_or_else(|e| e.into_inner());
        ctl.queued_dirty = false;

        if socket.remote_endpoint().is_some() || socket.state() != TcpState::Listen {
            entry.had_tuple = true;
        }

        // Rule 1: Any Listen socket that already processed a tuple (SynReceived + RST)
        // or was aborted/dropped or timed out is a zombie and must be reaped.
        if socket.state() == TcpState::Listen {
            let timed_out = check_timeouts
                && now.saturating_duration_since(entry.created_at)
                    >= self.config.syn_handshake_timeout;
            let remove = entry.had_tuple || ctl.aborted || ctl.dropped || timed_out;
            if entry.had_tuple {
                ctl.recv_aborted = true;
            }
            return (remove, false);
        }

        // Rule 7: Drain socket RX buffer unless application already dropped the stream.
        let mut need_egress_poll = false;
        let mut wake_recv = false;
        if !ctl.dropped {
            match drain_socket_rx(socket, &mut ctl) {
                Ok(true) => {
                    wake_recv = true;
                    need_egress_poll = true;
                }
                Ok(false) => {}
                Err(()) => {
                    self.pending_abort_reap.push(handle);
                    return (false, true);
                }
            }
        }

        let state = socket.state();
        #[cfg(test)]
        if state == TcpState::Established {
            ctl.established = true;
        }

        // Rule 2: Closed sockets are reaped once pending RST has been dispatched
        // (`remote_endpoint().is_none()`) or after bounded retry polls.
        if state == TcpState::Closed {
            if !ctl.recv_closed {
                if !ctl.dropped && !ctl.shutdown_called {
                    ctl.recv_aborted = true;
                }
                ctl.recv_closed = true;
                wake_recv = true;
            }
            if ctl.send_state != HalfState::Closed {
                ctl.send_state = HalfState::Closed;
                ctl.wake_send();
            }
            if wake_recv {
                ctl.wake_recv();
            }

            if socket.remote_endpoint().is_none() || entry.abort_polls >= MAX_ABORT_POLLS {
                return (true, false);
            }
            entry.abort_polls = entry.abort_polls.saturating_add(1);
            self.pending_abort_reap.push(handle);
            return (false, true);
        }

        // Rule 3: TimeWait sockets reap cleanly without abort() (no spurious RST).
        if state == TcpState::TimeWait {
            if !ctl.recv_closed {
                ctl.recv_closed = true;
                wake_recv = true;
            }
            if ctl.send_state != HalfState::Closed {
                ctl.send_state = HalfState::Closed;
                ctl.wake_send();
            }
            if wake_recv {
                ctl.wake_recv();
            }
            let tw_since = if let Some(ts) = entry.time_wait_since {
                ts
            } else {
                entry.time_wait_since = Some(now);
                self.reap_deadlines
                    .push(Reverse((now + self.config.time_wait_linger, handle)));
                now
            };
            let expired =
                check_timeouts && now.saturating_duration_since(tw_since) >= self.config.time_wait_linger;
            return (expired, false);
        }

        // Rule 4: Application-initiated abort sends RST immediately.
        if ctl.aborted {
            abort_socket_control(socket, &mut ctl);
            self.pending_abort_reap.push(handle);
            return (false, true);
        }

        // Rule 5: Half-open SynReceived handshake timeout.
        if check_timeouts
            && state == TcpState::SynReceived
            && now.saturating_duration_since(entry.created_at) >= self.config.syn_handshake_timeout
        {
            abort_socket_control(socket, &mut ctl);
            self.pending_abort_reap.push(handle);
            return (false, true);
        }

        // Signal EOF once peer's FIN is observed and state can no longer receive.
        if !ctl.recv_closed && !socket.may_recv() && may_recv_closed(state) {
            ctl.recv_closed = true;
            wake_recv = true;
        }
        if wake_recv {
            ctl.wake_recv();
        }

        // Flush remaining application TX buffer into smoltcp socket.
        let mut wake_send = match flush_socket_tx(socket, &mut ctl) {
            Ok(true) => {
                need_egress_poll = true;
                true
            }
            Ok(false) => false,
            Err(()) => {
                self.pending_abort_reap.push(handle);
                return (false, true);
            }
        };

        // Rule 8: Complete half-close once send_buf is flushed and 3-way handshake completed
        // (calling socket.close() in SynReceived confuses smoltcp's sent_syn/sent_fin accounting).
        if ctl.send_state == HalfState::Closing
            && ctl.send_buf.is_empty()
            && !matches!(socket.state(), TcpState::Listen | TcpState::SynReceived)
        {
            socket.close();
            ctl.send_state = HalfState::Closed;
            if entry.closing_since.is_none() {
                entry.closing_since = Some(now);
                self.reap_deadlines
                    .push(Reverse((now + self.config.close_linger_timeout, handle)));
            }
            wake_send = true;
            need_egress_poll = true;
        }

        if wake_send {
            ctl.wake_send();
        }

        // Rule 6: Bound how long dropped/closing sockets linger waiting for peer FIN/ACK.
        let fresh_state = socket.state();
        if ctl.dropped || is_closing_state(fresh_state) {
            let closing_since = if let Some(ts) = entry.closing_since {
                ts
            } else {
                entry.closing_since = Some(now);
                self.reap_deadlines
                    .push(Reverse((now + self.config.close_linger_timeout, handle)));
                now
            };
            if check_timeouts
                && now.saturating_duration_since(closing_since) >= self.config.close_linger_timeout
            {
                abort_socket_control(socket, &mut ctl);
                self.pending_abort_reap.push(handle);
                need_egress_poll = true;
            }
        }

        (false, need_egress_poll)
    }

    fn sweep_pending_aborts(&mut self) {
        let mut pending = std::mem::take(&mut self.pending_abort_reap);
        pending.sort_unstable();
        pending.dedup();
        let mut to_remove = Vec::new();
        let mut still_pending = Vec::new();

        for handle in pending {
            let Some(entry) = self.sockets.get(&handle) else {
                continue;
            };
            let sock = self.socket_set.get::<TcpSocket>(handle);
            let state = sock.state();
            if (state == TcpState::Closed
                && (sock.remote_endpoint().is_none() || entry.abort_polls >= MAX_ABORT_POLLS))
                || (state == TcpState::Listen && entry.had_tuple)
            {
                to_remove.push(handle);
            } else if state == TcpState::Closed {
                still_pending.push(handle);
            }
        }

        for handle in to_remove {
            self.remove_socket(handle);
        }
        self.pending_abort_reap = still_pending;
    }

    fn run_poll_cycle(
        &mut self,
        mut work: Vec<SocketHandle>,
        now: Instant,
        check_timeouts_all: bool,
    ) -> Vec<SocketHandle> {
        self.last_poll_at = now;

        let mut pre_remove = Vec::new();
        for &handle in &work {
            if self.sync_handle_pre_poll(handle, now) {
                pre_remove.push(handle);
            }
        }
        for handle in pre_remove {
            self.remove_socket(handle);
        }

        let egress_before = self.device.egress.len();
        let _ = self
            .iface
            .poll(SmolInstant::from(now), &mut self.device, &mut self.socket_set);

        if check_timeouts_all {
            work.extend(self.sockets.keys().copied());
            work.sort_unstable();
            work.dedup();
        }

        let mut need_egress_poll = false;
        let mut to_remove = Vec::new();
        for &handle in &work {
            let (remove, egress) = self.sync_handle_post_poll(handle, now, check_timeouts_all);
            if remove {
                to_remove.push(handle);
            }
            need_egress_poll |= egress;
        }
        for handle in to_remove {
            self.remove_socket(handle);
        }

        if need_egress_poll && self.device.egress.len() < self.device.max_pending_egress {
            let follow_now = Instant::now();
            self.last_poll_at = follow_now;
            let _ = self.iface.poll(
                SmolInstant::from(follow_now),
                &mut self.device,
                &mut self.socket_set,
            );
        }

        if !self.pending_abort_reap.is_empty() {
            self.sweep_pending_aborts();
        }
        self.update_egress_congestion();
        if self.device.egress.len() != egress_before {
            self.zero_delay_streak = 0;
        }

        work.clear();
        work
    }

    fn poll_dirty_only(&mut self) {
        let mut work = std::mem::take(&mut self.dirty_scratch);
        work.clear();
        self.dirty.drain_into(&mut work);
        work.sort_unstable();
        work.dedup();
        if work.is_empty() {
            self.dirty_scratch = work;
            return;
        }
        self.dirty_scratch = self.run_poll_cycle(work, Instant::now(), false);
    }

    fn poll_ingress_and_dirty(&mut self, now: Instant) {
        let mut work = std::mem::take(&mut self.touched_scratch);
        self.dirty.drain_into(&mut work);
        work.sort_unstable();
        work.dedup();
        self.touched_scratch = self.run_poll_cycle(work, now, false);
    }

    fn poll_timer_sweep(&mut self) {
        let mut work = std::mem::take(&mut self.touched_scratch);
        work.clear();
        self.dirty.drain_into(&mut work);
        work.sort_unstable();
        work.dedup();
        self.touched_scratch = self.run_poll_cycle(work, Instant::now(), true);
    }

    fn poll_after_egress_drain(&mut self, force_poll: bool) {
        let mut work = std::mem::take(&mut self.dirty_scratch);
        work.clear();
        self.dirty.drain_into(&mut work);
        work.extend(self.pending_abort_reap.iter().copied());
        work.sort_unstable();
        work.dedup();
        if work.is_empty() && !force_poll {
            self.dirty_scratch = work;
            return;
        }
        self.dirty_scratch = self.run_poll_cycle(work, Instant::now(), false);
    }

    fn update_egress_congestion(&mut self) {
        let limit = self.device.max_pending_egress;
        let resume = (limit / 2).max(1);
        let len = self.device.egress.len();
        if len >= limit {
            self.egress_congested = true;
        } else if len <= resume {
            self.egress_congested = false;
        }
    }

    fn flush_egress_try(&mut self) -> bool {
        while let Some(pkt) = self.device.egress.pop_front() {
            match self.tcp_out_tx.try_send(pkt) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(pkt)) => {
                    self.device.egress.push_front(pkt);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
            }
        }
        self.update_egress_congestion();
        true
    }

    fn socket_reap_deadline(&self, handle: SocketHandle) -> Option<Instant> {
        let entry = self.sockets.get(&handle)?;
        let state = self.socket_set.get::<TcpSocket>(handle).state();
        match state {
            TcpState::Listen | TcpState::SynReceived => {
                Some(entry.created_at + self.config.syn_handshake_timeout)
            }
            TcpState::TimeWait => entry
                .time_wait_since
                .map(|ts| ts + self.config.time_wait_linger),
            TcpState::Closed => None,
            _ => entry
                .closing_since
                .map(|ts| ts + self.config.close_linger_timeout),
        }
    }

    fn rebuild_reap_deadlines(&mut self) {
        self.reap_deadlines.clear();
        for &handle in self.sockets.keys() {
            if let Some(dl) = self.socket_reap_deadline(handle) {
                self.reap_deadlines.push(Reverse((dl, handle)));
            }
        }
    }

    fn next_reap_deadline(&mut self) -> Option<Instant> {
        while let Some(&Reverse((ts, handle))) = self.reap_deadlines.peek() {
            if self.socket_reap_deadline(handle) == Some(ts) {
                let threshold = self.sockets.len().saturating_mul(4).max(64);
                if self.reap_deadlines.len() > threshold {
                    self.rebuild_reap_deadlines();
                }
                return Some(ts);
            }
            self.reap_deadlines.pop();
        }
        None
    }

    fn next_wakeup_delay(&mut self) -> Option<Duration> {
        if self.egress_congested || (self.sockets.is_empty() && self.device.egress.is_empty()) {
            self.zero_delay_streak = 0;
            return None;
        }

        let now_std = self.last_poll_at;
        let now_smol = SmolInstant::from(now_std);
        let smoltcp_delay = self
            .iface
            .poll_delay(now_smol, &self.socket_set)
            .map(Duration::from);
        let reap_delay = self
            .next_reap_deadline()
            .map(|dl| dl.saturating_duration_since(now_std));

        let combined = match (smoltcp_delay, reap_delay) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        match combined {
            Some(d) if d.is_zero() => {
                self.zero_delay_streak = self.zero_delay_streak.saturating_add(1);
                let shift = (self.zero_delay_streak - 1).min(6);
                let ms = (1u64 << shift).min(MAX_ZERO_DELAY_BACKOFF_MS);
                Some(Duration::from_millis(ms))
            }
            other => {
                self.zero_delay_streak = 0;
                other
            }
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        loop {
            let was_congested = self.egress_congested;
            if !self.flush_egress_try() {
                return Ok(());
            }
            if was_congested && !self.egress_congested {
                self.poll_after_egress_drain(true);
                if !self.flush_egress_try() {
                    return Ok(());
                }
            }

            let delay = self.next_wakeup_delay();
            let sleep_fut = async {
                match delay {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(sleep_fut);

            let has_egress = !self.device.egress.is_empty();
            let ingress_ready = !self.egress_congested;

            tokio::select! {
                permit = self.tcp_out_tx.clone().reserve_owned(), if has_egress => {
                    match permit {
                        Ok(permit) => {
                            if let Some(pkt) = self.device.egress.pop_front() {
                                permit.send(pkt);
                            }
                            self.update_egress_congestion();
                        }
                        Err(_) => return Ok(()),
                    }
                    let congested_before_flush = self.egress_congested;
                    if !self.flush_egress_try() {
                        return Ok(());
                    }
                    if !self.egress_congested
                        && (congested_before_flush || !self.pending_abort_reap.is_empty())
                    {
                        self.poll_after_egress_drain(congested_before_flush);
                    }
                }
                maybe_pkt = self.tcp_in_rx.recv(), if ingress_ready => {
                    let Some(pkt) = maybe_pkt else { break };
                    let now = Instant::now();
                    self.handle_tcp_packet(pkt, now);
                    for _ in 1..INGRESS_DRAIN_BATCH {
                        match self.tcp_in_rx.try_recv() {
                            Ok(extra) => self.handle_tcp_packet(extra, now),
                            Err(_) => break,
                        }
                    }
                    self.zero_delay_streak = 0;
                    self.poll_ingress_and_dirty(now);
                }
                _ = self.dirty.notify.notified() => {
                    self.poll_dirty_only();
                }
                _ = &mut sleep_fut => {
                    self.poll_timer_sweep();
                }
            }
        }

        self.poll_dirty_only();
        let _ = self.flush_egress_try();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{
        IpProtocol, Ipv4Packet, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> NetStackConfig {
        NetStackConfig {
            mtu: 1500,
            shards: 1,
            tcp_rx_buf: 16 * 1024,
            tcp_tx_buf: 16 * 1024,
            max_tcp_sockets: 64,
            tcp_keepalive: Duration::from_secs(30),
            tcp_timeout: Duration::from_secs(120),
            syn_handshake_timeout: Duration::from_millis(80),
            close_linger_timeout: Duration::from_millis(80),
            time_wait_linger: Duration::from_millis(80),
        }
    }

    fn build_tcp_segment(
        src: SocketAddr,
        dst: SocketAddr,
        seq: u32,
        ack: Option<u32>,
        control: TcpControl,
        payload: &[u8],
    ) -> Vec<u8> {
        let caps = ChecksumCapabilities::default();
        let tcp_repr = TcpRepr {
            src_port: src.port(),
            dst_port: dst.port(),
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: ack.map(|v| TcpSeqNumber(v as i32)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let l4_len = tcp_repr.buffer_len();
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
                let ip_repr = Ipv4Repr {
                    src_addr: src_v4,
                    dst_addr: dst_v4,
                    next_header: IpProtocol::Tcp,
                    payload_len: l4_len,
                    hop_limit: 64,
                };
                let mut pkt = vec![0u8; ip_repr.buffer_len() + l4_len];
                let (ip_buf, l4_buf) = pkt.split_at_mut(ip_repr.buffer_len());
                ip_repr.emit(&mut Ipv4Packet::new_unchecked(ip_buf), &caps);
                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(l4_buf),
                    &IpAddress::Ipv4(src_v4),
                    &IpAddress::Ipv4(dst_v4),
                    &caps,
                );
                pkt
            }
            (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
                let ip_repr = Ipv6Repr {
                    src_addr: src_v6,
                    dst_addr: dst_v6,
                    next_header: IpProtocol::Tcp,
                    payload_len: l4_len,
                    hop_limit: 64,
                };
                let mut pkt = vec![0u8; ip_repr.buffer_len() + l4_len];
                let (ip_buf, l4_buf) = pkt.split_at_mut(ip_repr.buffer_len());
                ip_repr.emit(&mut Ipv6Packet::new_unchecked(ip_buf));
                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(l4_buf),
                    &IpAddress::Ipv6(src_v6),
                    &IpAddress::Ipv6(dst_v6),
                    &caps,
                );
                pkt
            }
            _ => panic!("mismatched address families"),
        }
    }

    fn parse_tcp_flags(pkt: &[u8]) -> (bool, bool, bool, bool, u32, Option<u32>, Vec<u8>) {
        let caps = ChecksumCapabilities::default();
        let (src, dst, l4) = match IpVersion::of_packet(pkt).unwrap() {
            IpVersion::Ipv4 => {
                let ip = Ipv4Packet::new_checked(pkt).unwrap();
                (
                    IpAddress::Ipv4(ip.src_addr()),
                    IpAddress::Ipv4(ip.dst_addr()),
                    ip.payload(),
                )
            }
            IpVersion::Ipv6 => {
                let ip = Ipv6Packet::new_checked(pkt).unwrap();
                (
                    IpAddress::Ipv6(ip.src_addr()),
                    IpAddress::Ipv6(ip.dst_addr()),
                    ip.payload(),
                )
            }
        };
        let tcp = TcpPacket::new_checked(l4).unwrap();
        let repr = TcpRepr::parse(&tcp, &src, &dst, &caps).unwrap();
        (
            repr.control == TcpControl::Syn,
            repr.ack_number.is_some(),
            repr.control == TcpControl::Rst,
            repr.control == TcpControl::Fin,
            repr.seq_number.0 as u32,
            repr.ack_number.map(|n| n.0 as u32),
            repr.payload.to_vec(),
        )
    }

    async fn recv_egress(rx: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for stack egress packet")
            .expect("stack egress channel closed")
    }

    async fn wait_socket_count(count: &AtomicUsize, expected: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if count.load(Ordering::Acquire) == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for active_socket_count == {}, current == {}",
                expected,
                count.load(Ordering::Acquire)
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn establish_handshake(
        tcp_in_tx: &mpsc::Sender<Vec<u8>>,
        tcp_out_rx: &mut mpsc::Receiver<Vec<u8>>,
        listener: &mut TcpListener,
        src: SocketAddr,
        dst: SocketAddr,
        client_seq: u32,
    ) -> (StackTcpStream, u32) {
        let syn = build_tcp_segment(src, dst, client_seq, None, TcpControl::Syn, &[]);
        tcp_in_tx.send(syn).await.unwrap();

        let (stream, got_src, got_dst) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_src, src);
        assert_eq!(got_dst, dst);

        let syn_ack = recv_egress(tcp_out_rx).await;
        let flags = parse_tcp_flags(&syn_ack);
        let (is_syn, is_ack, is_rst, _, server_seq, ack_num, _) = flags;
        assert!(is_syn && is_ack && !is_rst, "unexpected syn_ack: {:?}", flags);
        assert_eq!(ack_num, Some(client_seq.wrapping_add(1)));

        let ack = build_tcp_segment(
            src,
            dst,
            client_seq.wrapping_add(1),
            Some(server_seq.wrapping_add(1)),
            TcpControl::None,
            &[],
        );
        tcp_in_tx.send(ack).await.unwrap();
        // Wait until the stack task polls the 3rd-handshake ACK into Established
        // before callers immediately trigger shutdown()/abort().
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while !stream.is_established() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for handshake ACK to reach Established"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        (stream, server_seq.wrapping_add(1))
    }

    #[tokio::test]
    async fn duplicate_syn_on_same_tuple_does_not_create_duplicate_stream_or_socket() {
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(test_config(), tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        let src: SocketAddr = "198.19.254.1:57650".parse().unwrap();
        let dst: SocketAddr = "47.236.86.78:443".parse().unwrap();
        let syn = build_tcp_segment(src, dst, 1000, None, TcpControl::Syn, &[]);

        tcp_in_tx.send(syn.clone()).await.unwrap();
        let (stream, got_src, got_dst) = listener.accept().await.unwrap();
        assert_eq!(got_src, src);
        assert_eq!(got_dst, dst);
        let _syn_ack = recv_egress(&mut tcp_out_rx).await;

        // Retransmitted SYN for the same 4-tuple must be deduplicated.
        for _ in 0..5 {
            tcp_in_tx.send(syn.clone()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(active.load(Ordering::Acquire), 1);
        assert!(listener.stream_rx.try_recv().is_err());

        drop(stream);
        wait_socket_count(&active, 0).await;
        stack_task.abort();
    }

    #[tokio::test]
    async fn abort_and_ungraceful_drop_emit_rst_and_reap_socket_immediately() {
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(test_config(), tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        // Case 1: explicit stream.abort() on established stream emits RST and reaps immediately.
        let src1: SocketAddr = "198.19.254.1:50001".parse().unwrap();
        let dst1: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let (stream1, _sseq1) =
            establish_handshake(&tcp_in_tx, &mut tcp_out_rx, &mut listener, src1, dst1, 1000).await;
        assert_eq!(active.load(Ordering::Acquire), 1);

        stream1.abort();
        let rst1 = recv_egress(&mut tcp_out_rx).await;
        let (_, _, is_rst1, _, _, _, _) = parse_tcp_flags(&rst1);
        assert!(is_rst1, "expected RST on explicit abort");
        wait_socket_count(&active, 0).await;

        // Case 2: ungraceful drop without shutdown emits RST and reaps immediately.
        let src2: SocketAddr = "198.19.254.1:50002".parse().unwrap();
        let (stream2, _sseq2) =
            establish_handshake(&tcp_in_tx, &mut tcp_out_rx, &mut listener, src2, dst1, 2000).await;
        assert_eq!(active.load(Ordering::Acquire), 1);

        drop(stream2);
        let rst2 = recv_egress(&mut tcp_out_rx).await;
        let (_, _, is_rst2, _, _, _, _) = parse_tcp_flags(&rst2);
        assert!(is_rst2, "expected RST on ungraceful drop");
        wait_socket_count(&active, 0).await;

        stack_task.abort();
    }

    #[tokio::test]
    async fn rst_in_syn_received_reaps_zombie_listen_socket_and_wakes_reader() {
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(test_config(), tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        let src: SocketAddr = "198.19.254.1:51001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let syn = build_tcp_segment(src, dst, 5000, None, TcpControl::Syn, &[]);
        tcp_in_tx.send(syn).await.unwrap();

        let (mut stream, _, _) = listener.accept().await.unwrap();
        let _syn_ack = recv_egress(&mut tcp_out_rx).await;
        assert_eq!(active.load(Ordering::Acquire), 1);

        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            stream.read(&mut buf).await
        });

        // Client resets while server socket is still in SynReceived.
        let rst = build_tcp_segment(src, dst, 5001, None, TcpControl::Rst, &[]);
        tcp_in_tx.send(rst).await.unwrap();

        let read_res = tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(read_res, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
                || matches!(read_res, Ok(0)),
            "unexpected read result after RST in SynReceived: {:?}",
            read_res
        );
        wait_socket_count(&active, 0).await;

        stack_task.abort();
    }

    #[tokio::test]
    async fn half_open_syn_received_reaps_after_handshake_timeout() {
        let mut cfg = test_config();
        cfg.syn_handshake_timeout = Duration::from_millis(60);
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(cfg, tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        let src: SocketAddr = "198.19.254.1:52001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let syn = build_tcp_segment(src, dst, 7000, None, TcpControl::Syn, &[]);
        tcp_in_tx.send(syn).await.unwrap();

        let (_stream, _, _) = listener.accept().await.unwrap();
        let _syn_ack = recv_egress(&mut tcp_out_rx).await;
        assert_eq!(active.load(Ordering::Acquire), 1);

        // No ACK arrives; half-open socket must abort with RST and reap after timeout.
        let rst = recv_egress(&mut tcp_out_rx).await;
        let (_, _, is_rst, _, _, _, _) = parse_tcp_flags(&rst);
        assert!(is_rst, "expected RST after SynReceived handshake timeout");
        wait_socket_count(&active, 0).await;

        stack_task.abort();
    }

    #[tokio::test]
    async fn lingering_fin_wait_reaps_after_close_linger_timeout() {
        let mut cfg = test_config();
        cfg.close_linger_timeout = Duration::from_millis(60);
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(cfg, tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        let src: SocketAddr = "198.19.254.1:53001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let (mut stream, _sseq) =
            establish_handshake(&tcp_in_tx, &mut tcp_out_rx, &mut listener, src, dst, 9000).await;

        stream.shutdown().await.unwrap();
        let fin = recv_egress(&mut tcp_out_rx).await;
        let (_, _, _, is_fin, _, _, _) = parse_tcp_flags(&fin);
        assert!(is_fin, "expected FIN on graceful shutdown");

        // Peer never acknowledges or sends its FIN; socket must linger-reap rather than stay for 7200s.
        wait_socket_count(&active, 0).await;

        stack_task.abort();
    }

    #[tokio::test]
    async fn time_wait_reaps_without_rst_and_allows_immediate_syn_reuse() {
        let mut cfg = test_config();
        cfg.time_wait_linger = Duration::from_millis(60);
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(cfg, tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        let src: SocketAddr = "198.19.254.1:54001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let (mut stream, sseq) =
            establish_handshake(&tcp_in_tx, &mut tcp_out_rx, &mut listener, src, dst, 11000).await;

        stream.shutdown().await.unwrap();
        let fin_pkt = recv_egress(&mut tcp_out_rx).await;
        let flags = parse_tcp_flags(&fin_pkt);
        let (_, _, _, is_fin, fin_seq, _, _) = flags;
        assert!(is_fin, "expected FIN on shutdown, got {:?}", flags);
        assert_eq!(fin_seq, sseq);

        // Client sends FIN+ACK acknowledging our FIN -> smoltcp enters TIME-WAIT.
        let peer_fin_ack = build_tcp_segment(
            src,
            dst,
            11001,
            Some(sseq.wrapping_add(1)),
            TcpControl::Fin,
            &[],
        );
        tcp_in_tx.send(peer_fin_ack).await.unwrap();
        let ack_of_peer_fin = recv_egress(&mut tcp_out_rx).await;
        let (_, is_ack, is_rst, _, _, ack_num, _) = parse_tcp_flags(&ack_of_peer_fin);
        assert!(is_ack && !is_rst);
        assert_eq!(ack_num, Some(11002));

        // Immediate SYN reuse on the exact same 4-tuple must succeed cleanly before TIME-WAIT expires.
        let (stream2, _sseq2) = establish_handshake(
            &tcp_in_tx,
            &mut tcp_out_rx,
            &mut listener,
            src,
            dst,
            21000,
        )
        .await;
        assert_eq!(active.load(Ordering::Acquire), 1);

        // Close stream2 through TimeWait and confirm it reaps after time_wait_linger without RST.
        stream2.abort();
        let rst = recv_egress(&mut tcp_out_rx).await;
        let (_, _, is_rst, _, _, _, _) = parse_tcp_flags(&rst);
        assert!(is_rst);
        wait_socket_count(&active, 0).await;

        // Establish a third connection and verify normal TimeWait reap emits no RST.
        let (mut stream3, sseq3) = establish_handshake(
            &tcp_in_tx,
            &mut tcp_out_rx,
            &mut listener,
            src,
            dst,
            31000,
        )
        .await;
        stream3.shutdown().await.unwrap();
        let _ = recv_egress(&mut tcp_out_rx).await;
        let peer_fin3 = build_tcp_segment(
            src,
            dst,
            31001,
            Some(sseq3.wrapping_add(1)),
            TcpControl::Fin,
            &[],
        );
        tcp_in_tx.send(peer_fin3).await.unwrap();
        let _ = recv_egress(&mut tcp_out_rx).await;

        wait_socket_count(&active, 0).await;
        assert!(tcp_out_rx.try_recv().is_err(), "TimeWait reap emitted unexpected packet");

        stack_task.abort();
    }

    #[tokio::test]
    async fn graceful_shutdown_flushes_and_completes_without_waiting_for_peer_fin() {
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(test_config(), tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        let src: SocketAddr = "198.19.254.1:55001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let (mut stream, sseq) =
            establish_handshake(&tcp_in_tx, &mut tcp_out_rx, &mut listener, src, dst, 41000).await;

        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut received = Vec::new();
        let mut saw_fin = false;
        while !saw_fin || received.len() < b"HTTP/1.1 200 OK\r\n\r\n".len() {
            let pkt = recv_egress(&mut tcp_out_rx).await;
            let (_, _, is_rst, is_fin, _, _, data) = parse_tcp_flags(&pkt);
            assert!(!is_rst);
            received.extend_from_slice(&data);
            if is_fin {
                saw_fin = true;
            }
        }
        assert_eq!(&received, b"HTTP/1.1 200 OK\r\n\r\n");

        // ACK server's FIN + data cleanly (client FIN triggers CloseWait/TimeWait).
        let ack_all = build_tcp_segment(
            src,
            dst,
            41001,
            Some(sseq.wrapping_add(received.len() as u32 + 1)),
            TcpControl::Fin,
            &[],
        );
        tcp_in_tx.send(ack_all).await.unwrap();
        let _final_ack = recv_egress(&mut tcp_out_rx).await;
        wait_socket_count(&active, 0).await;

        stack_task.abort();
    }

    #[test]
    fn udp_ipv4_and_ipv6_parse_and_build_roundtrip_and_reject_invalid() {
        let src_v4: SocketAddr = "198.19.254.1:51000".parse().unwrap();
        let dst_v4: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let v4_pkt = build_udp_packet(b"hello-v4", src_v4, dst_v4).unwrap();
        assert!(is_udp_packet(&v4_pkt));
        assert!(!is_tcp_packet(&v4_pkt));
        assert_eq!(
            parse_udp_packet(&v4_pkt).unwrap(),
            (b"hello-v4".to_vec(), src_v4, dst_v4)
        );

        let src_v6: SocketAddr = "[fd72:666f:7200::1]:52000".parse().unwrap();
        let dst_v6: SocketAddr = "[2001:db8:50::1]:9001".parse().unwrap();
        let v6_pkt = build_udp_packet(b"hello-v6", src_v6, dst_v6).unwrap();
        assert!(is_udp_packet(&v6_pkt));
        assert!(!is_tcp_packet(&v6_pkt));
        assert_eq!(
            parse_udp_packet(&v6_pkt).unwrap(),
            (b"hello-v6".to_vec(), src_v6, dst_v6)
        );

        // Family mismatch and empty payloads return None cleanly.
        assert!(build_udp_packet(b"", src_v4, dst_v4).is_none());
        assert!(build_udp_packet(b"bad", src_v4, dst_v6).is_none());

        // Reject IPv4 fragments.
        let mut frag_pkt = v4_pkt.clone();
        frag_pkt[6] = 0x20; // MF bit
        frag_pkt[10] = 0;
        frag_pkt[11] = 0;
        Ipv4Packet::new_unchecked(&mut frag_pkt[..20]).fill_checksum();
        assert!(parse_udp_packet(&frag_pkt).is_none());

        // Reject broadcast / multicast destinations.
        let bcast = build_udp_packet(b"bcast", src_v4, "255.255.255.255:53".parse().unwrap()).unwrap();
        assert!(parse_udp_packet(&bcast).is_none());

        let mcast = build_udp_packet(b"mcast", src_v6, "[ff02::1]:5353".parse().unwrap()).unwrap();
        assert!(parse_udp_packet(&mcast).is_none());

        // Sanity check UdpRepr checksum validity on emitted packet.
        let parsed_ip = Ipv6Packet::new_checked(&v6_pkt).unwrap();
        let parsed_udp = UdpPacket::new_checked(parsed_ip.payload()).unwrap();
        assert!(UdpRepr::parse(
            &parsed_udp,
            &IpAddress::Ipv6(parsed_ip.src_addr()),
            &IpAddress::Ipv6(parsed_ip.dst_addr()),
            &ChecksumCapabilities::default()
        )
        .is_ok());
    }

    #[tokio::test]
    async fn sharded_tcp_stack_routes_same_tuple_consistently_and_distributes_flows() {
        let mut cfg = test_config();
        cfg.shards = 4;
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(256);
        let (stacks, router, mut listener) = create_sharded_tcp_stack(cfg, tcp_out_tx).unwrap();
        assert_eq!(router.shard_count(), 4);

        let shard_counts: Vec<Arc<AtomicUsize>> =
            stacks.iter().map(|s| s.active_socket_count_handle()).collect();
        let mut tasks = Vec::new();
        for s in stacks {
            tasks.push(tokio::spawn(s.run()));
        }

        // Verify consistent 4-tuple shard affinity and distribution across multiple flows.
        let mut used_shards = std::collections::HashSet::new();
        for i in 0..32u16 {
            let src: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 254, 1)), 40000 + i);
            let dst: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80 + (i % 7));
            let syn = build_tcp_segment(src, dst, 1000, None, TcpControl::Syn, &[]);
            let ack = build_tcp_segment(src, dst, 1001, Some(1), TcpControl::None, b"hi");
            let s1 = router.shard_for_packet(&syn).unwrap();
            let s2 = router.shard_for_packet(&ack).unwrap();
            assert_eq!(s1, s2, "same 4-tuple must hash to identical shard");
            used_shards.insert(s1);
        }
        assert!(
            used_shards.len() >= 2,
            "32 flows should spread across at least 2 of 4 shards, used={:?}",
            used_shards
        );

        // Full lifecycle on a sharded flow.
        let src: SocketAddr = "198.19.254.1:56001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let syn = build_tcp_segment(src, dst, 100, None, TcpControl::Syn, &[]);
        router.send(syn).await.unwrap();

        let (mut stream, got_src, got_dst) =
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(got_src, src);
        assert_eq!(got_dst, dst);

        let syn_ack = recv_egress(&mut tcp_out_rx).await;
        let (is_syn, is_ack, is_rst, _, server_seq, ack_num, _) = parse_tcp_flags(&syn_ack);
        assert!(is_syn && is_ack && !is_rst);
        assert_eq!(ack_num, Some(101));

        let ack = build_tcp_segment(
            src,
            dst,
            101,
            Some(server_seq.wrapping_add(1)),
            TcpControl::None,
            b"ping",
        );
        router.send(ack).await.unwrap();

        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping");

        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut got_fin = false;
        let mut out_bytes = Vec::new();
        while !got_fin || out_bytes.len() < 4 {
            let pkt = recv_egress(&mut tcp_out_rx).await;
            let (_, _, _, is_fin, _, _, data) = parse_tcp_flags(&pkt);
            out_bytes.extend_from_slice(&data);
            if is_fin {
                got_fin = true;
            }
        }
        assert_eq!(&out_bytes, b"pong");

        let peer_fin = build_tcp_segment(
            src,
            dst,
            105,
            Some(server_seq.wrapping_add(1 + 4 + 1)),
            TcpControl::Fin,
            &[],
        );
        router.send(peer_fin).await.unwrap();
        let _ = recv_egress(&mut tcp_out_rx).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let total: usize = shard_counts.iter().map(|c| c.load(Ordering::Acquire)).sum();
            if total == 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "sharded stack leaked sockets: remaining={}",
                total
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        for t in tasks {
            t.abort();
        }
    }

    #[tokio::test]
    async fn rx_backpressure_release_and_immediate_tx_dispatch_do_not_stall() {
        let mut cfg = test_config();
        cfg.tcp_rx_buf = 2048;
        cfg.tcp_tx_buf = 2048;
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (stack, mut listener) = create_tcp_stack(cfg, tcp_in_rx, tcp_out_tx).unwrap();
        let active = stack.active_socket_count_handle();
        let stack_task = tokio::spawn(stack.run());

        let src: SocketAddr = "198.19.254.1:57001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let (mut stream, mut sseq) =
            establish_handshake(&tcp_in_tx, &mut tcp_out_rx, &mut listener, src, dst, 1000).await;

        // First chunk (1400 bytes) moves into ctl.recv_buf (2048 capacity).
        let chunk1 = vec![b'A'; 1400];
        tcp_in_tx
            .send(build_tcp_segment(src, dst, 1001, Some(sseq), TcpControl::None, &chunk1))
            .await
            .unwrap();
        let _ack1 = recv_egress(&mut tcp_out_rx).await;

        // Second chunk (1400 bytes) overflows ctl.recv_buf (only 648 free) -> leaves 752 bytes
        // in smoltcp rx_buffer with ctl.rx_backpressured = true.
        let chunk2 = vec![b'B'; 1400];
        tcp_in_tx
            .send(build_tcp_segment(
                src,
                dst,
                1001 + 1400,
                Some(sseq),
                TcpControl::None,
                &chunk2,
            ))
            .await
            .unwrap();

        let mut received = vec![0u8; 2800];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut received))
            .await
            .expect("read_exact stalled under rx_backpressured")
            .unwrap();
        assert_eq!(&received[..1400], &chunk1[..]);
        assert_eq!(&received[1400..], &chunk2[..]);

        // Verify TX flush works promptly via pre-poll without requiring shutdown().
        let tx_payload = vec![b'Z'; 1024];
        stream.write_all(&tx_payload).await.unwrap();
        let mut echoed = Vec::new();
        while echoed.len() < tx_payload.len() {
            let pkt = recv_egress(&mut tcp_out_rx).await;
            let (_, _, is_rst, _, seq, _, data) = parse_tcp_flags(&pkt);
            assert!(!is_rst);
            if !data.is_empty() {
                sseq = seq.wrapping_add(data.len() as u32);
                echoed.extend_from_slice(&data);
            }
        }
        assert_eq!(echoed, tx_payload);

        stream.abort();
        let _ = recv_egress(&mut tcp_out_rx).await;
        wait_socket_count(&active, 0).await;
        let _ = sseq;
        stack_task.abort();
    }

    #[tokio::test]
    async fn concurrent_streams_graceful_and_abort_reap_cleanly() {
        let mut cfg = test_config();
        cfg.shards = 4;
        cfg.syn_handshake_timeout = Duration::from_millis(80);
        cfg.close_linger_timeout = Duration::from_millis(80);
        cfg.time_wait_linger = Duration::from_millis(60);

        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(512);
        let (stacks, router, mut listener) = create_sharded_tcp_stack(cfg, tcp_out_tx).unwrap();
        let shard_counts: Vec<Arc<AtomicUsize>> =
            stacks.iter().map(|s| s.active_socket_count_handle()).collect();
        let mut stack_tasks = Vec::new();
        for s in stacks {
            stack_tasks.push(tokio::spawn(s.run()));
        }

        // Drain egress packets in the background while tracking SYN-ACKs per client port.
        let syn_ack_seqs = Arc::new(Mutex::new(HashMap::<u16, u32>::new()));
        let syn_ack_notify = Arc::new(Notify::new());
        let syn_ack_seqs_bg = Arc::clone(&syn_ack_seqs);
        let syn_ack_notify_bg = Arc::clone(&syn_ack_notify);
        let egress_drainer = tokio::spawn(async move {
            while let Some(pkt) = tcp_out_rx.recv().await {
                if let Ok(IpVersion::Ipv4) = IpVersion::of_packet(&pkt) {
                    if let Ok(ip) = Ipv4Packet::new_checked(&pkt) {
                        if let Ok(tcp) = TcpPacket::new_checked(ip.payload()) {
                            if tcp.syn() && tcp.ack() {
                                let seq = tcp.seq_number().0 as u32;
                                syn_ack_seqs_bg
                                    .lock()
                                    .unwrap()
                                    .insert(tcp.dst_port(), seq);
                                syn_ack_notify_bg.notify_waiters();
                            }
                        }
                    }
                }
            }
        });

        const FLOW_COUNT: usize = 24;
        let mut streams = Vec::with_capacity(FLOW_COUNT);
        for i in 0..FLOW_COUNT {
            let sport = 58000 + i as u16;
            let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 254, 1)), sport);
            let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
            let syn = build_tcp_segment(src, dst, 1000, None, TcpControl::Syn, &[]);
            router.send(syn).await.unwrap();

            let (stream, got_src, _) =
                tokio::time::timeout(Duration::from_secs(2), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(got_src, src);

            let server_seq = loop {
                if let Some(seq) = syn_ack_seqs.lock().unwrap().get(&sport).copied() {
                    break seq;
                }
                tokio::time::timeout(Duration::from_secs(2), syn_ack_notify.notified())
                    .await
                    .unwrap();
            };

            let ack = build_tcp_segment(
                src,
                dst,
                1001,
                Some(server_seq.wrapping_add(1)),
                TcpControl::None,
                &[],
            );
            router.send(ack).await.unwrap();
            while !stream.is_established() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            streams.push((i, sport, server_seq.wrapping_add(1), stream));
        }

        // Half abort immediately, half graceful-close via FIN handshake.
        for (i, sport, sseq, mut stream) in streams {
            if i % 2 == 0 {
                stream.abort();
            } else {
                stream.shutdown().await.unwrap();
                let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 254, 1)), sport);
                let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
                let fin = build_tcp_segment(
                    src,
                    dst,
                    1001,
                    Some(sseq.wrapping_add(1)),
                    TcpControl::Fin,
                    &[],
                );
                router.send(fin).await.unwrap();
            }
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let total: usize = shard_counts.iter().map(|c| c.load(Ordering::Acquire)).sum();
            if total == 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for all {} flows to reap cleanly, remaining={}",
                FLOW_COUNT,
                total
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        egress_drainer.abort();
        for t in stack_tasks {
            t.abort();
        }
    }

    #[test]
    fn shard_queue_budgets_scale_inversely_with_shard_count() {
        let mut cfg = test_config();

        for (shards, expected_in, expected_egress) in [
            (0usize, TOTAL_TCP_IN_QUEUE_BUDGET, TOTAL_PENDING_EGRESS_BUDGET),
            (1, TOTAL_TCP_IN_QUEUE_BUDGET, TOTAL_PENDING_EGRESS_BUDGET),
            (2, TOTAL_TCP_IN_QUEUE_BUDGET / 2, TOTAL_PENDING_EGRESS_BUDGET / 2),
            (
                3,
                TOTAL_TCP_IN_QUEUE_BUDGET.div_ceil(3),
                TOTAL_PENDING_EGRESS_BUDGET.div_ceil(3),
            ),
            (4, TOTAL_TCP_IN_QUEUE_BUDGET / 4, TOTAL_PENDING_EGRESS_BUDGET / 4),
            (16, MIN_SHARD_IN_QUEUE, MIN_SHARD_PENDING_EGRESS),
        ] {
            cfg.shards = shards;
            let count = cfg.shard_count();
            assert_eq!(count, shards.max(1));
            assert_eq!(cfg.shard_in_channel_size(), expected_in);
            assert_eq!(cfg.shard_max_pending_egress(), expected_egress);
            assert_eq!(cfg.tcp_out_channel_size(), TOTAL_TCP_OUT_CHANNEL_BUDGET);

            if shards <= 4 {
                // Within the default 1..=4 shard range, total queued budget stays bounded
                // near the fixed global budget (modulo ceil rounding).
                let total_in = cfg.shard_in_channel_size() * count;
                let total_egress = cfg.shard_max_pending_egress() * count;
                assert!(total_in >= TOTAL_TCP_IN_QUEUE_BUDGET);
                assert!(total_in < TOTAL_TCP_IN_QUEUE_BUDGET + count);
                assert!(total_egress >= TOTAL_PENDING_EGRESS_BUDGET);
                assert!(total_egress < TOTAL_PENDING_EGRESS_BUDGET + count);
            }
        }

        // Verify created shards actually wire the derived per-shard egress cap.
        cfg.shards = 4;
        let (tcp_out_tx, _tcp_out_rx) = mpsc::channel(cfg.tcp_out_channel_size());
        let (stacks, router, _listener) = create_sharded_tcp_stack(cfg.clone(), tcp_out_tx).unwrap();
        assert_eq!(router.shard_count(), 4);
        assert_eq!(stacks.len(), 4);
        for stack in &stacks {
            assert_eq!(stack.device.max_pending_egress, cfg.shard_max_pending_egress());
        }
    }
}
