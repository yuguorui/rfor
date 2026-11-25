//! Route-aware ICMP/ICMPv6 Echo forwarding and error synthesis for macOS `utun`.
//!
//! `DIRECT` Echo Requests are relayed over shared non-blocking `SOCK_DGRAM`
//! ICMP/ICMPv6 sockets pinned to the physical egress interface so real replies
//! flow back through `utun`. Flows hitting a proxy outbound receive an ICMP
//! Protocol Unreachable / Parameter Problem error immediately without leaking
//! direct packets, and flows hitting `DROP` receive Administratively Prohibited.

use anyhow::{Context, Result};
use nix::libc;
use socket2::SockAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::get_settings;
use crate::rules::{prepare_socket_bypass_mangle_for_addr, IcmpRouteAction};

use super::utun_macos;

const ICMP_BATCH: usize = 64;
const ICMP_FLOW_TTL: Duration = Duration::from_secs(30);
const ICMP_MAX_FLOWS: usize = 512;

const IPPROTO_ICMP: libc::c_int = 1;
const IPPROTO_ICMPV6: libc::c_int = 58;

const ICMP_V4_ECHO_REPLY: u8 = 0;
const ICMP_V4_DEST_UNREACH: u8 = 3;
const ICMP_V4_CODE_PROTO_UNREACH: u8 = 2;
const ICMP_V4_CODE_ADMIN_PROHIBITED: u8 = 13;
const ICMP_V4_ECHO_REQUEST: u8 = 8;

const ICMP_V6_DEST_UNREACH: u8 = 1;
const ICMP_V6_CODE_ADMIN_PROHIBITED: u8 = 1;
const ICMP_V6_PARAM_PROB: u8 = 4;
const ICMP_V6_CODE_NEXT_HDR: u8 = 1;
const ICMP_V6_ECHO_REQUEST: u8 = 128;
const ICMP_V6_ECHO_REPLY: u8 = 129;

const MAX_V4_QUOTED_BYTES: usize = 548; // 20 (IPv4) + 8 (ICMP) + 548 = 576 bytes (RFC 1812)
const MAX_V6_QUOTED_BYTES: usize = 1232; // 40 (IPv6) + 8 (ICMPv6) + 1232 = 1280 bytes (RFC 4443)

static IPV4_ID_COUNTER: AtomicU16 = AtomicU16::new(1);

fn next_ipv4_id() -> u16 {
    IPV4_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Return `true` if `pkt` is an IPv4 ICMP or IPv6 ICMPv6 packet ready for the ICMP worker.
pub(crate) fn is_icmp_packet(pkt: &[u8]) -> bool {
    (pkt.len() >= 20 && (pkt[0] >> 4) == 4 && pkt[9] == 1)
        || (pkt.len() >= 40 && (pkt[0] >> 4) == 6 && pkt[6] == 58)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IcmpEchoRequest {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) id: u16,
    pub(crate) seq: u16,
    pub(crate) payload: Vec<u8>,
    pub(crate) raw_packet: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IcmpErrorKind {
    ProxyUnsupported,
    AdminProhibited,
}

fn is_valid_unicast_v4(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified() && !addr.is_multicast() && !addr.is_broadcast()
}

fn is_valid_unicast_v6(addr: Ipv6Addr) -> bool {
    !addr.is_unspecified() && !addr.is_multicast()
}

/// Parse an inbound IPv4/IPv6 packet from `utun` and extract an ICMP Echo Request.
/// Rejects fragments, malformed lengths, multicast/broadcast addresses, and non-Echo ICMP.
pub(crate) fn parse_echo_request(pkt: &[u8]) -> Option<IcmpEchoRequest> {
    let version = pkt.first()? >> 4;
    match version {
        4 => {
            if pkt.len() < 20 || pkt[9] != 1 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total_len < ihl + 8 || total_len > pkt.len() {
                return None;
            }
            // Drop fragmented IPv4 packets (MF flag or non-zero fragment offset).
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if (frag & 0x3fff) != 0 {
                return None;
            }
            let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            if !is_valid_unicast_v4(src) || !is_valid_unicast_v4(dst) {
                return None;
            }
            let icmp = &pkt[ihl..total_len];
            if icmp[0] != ICMP_V4_ECHO_REQUEST || icmp[1] != 0 {
                return None;
            }
            Some(IcmpEchoRequest {
                src: IpAddr::V4(src),
                dst: IpAddr::V4(dst),
                id: u16::from_be_bytes([icmp[4], icmp[5]]),
                seq: u16::from_be_bytes([icmp[6], icmp[7]]),
                payload: icmp[8..].to_vec(),
                raw_packet: pkt[..total_len].to_vec(),
            })
        }
        6 => {
            if pkt.len() < 40 || pkt[6] != 58 {
                return None;
            }
            let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            if payload_len < 8 || 40 + payload_len > pkt.len() {
                return None;
            }
            let src_bytes: [u8; 16] = pkt[8..24].try_into().ok()?;
            let dst_bytes: [u8; 16] = pkt[24..40].try_into().ok()?;
            let src = Ipv6Addr::from(src_bytes);
            let dst = Ipv6Addr::from(dst_bytes);
            if !is_valid_unicast_v6(src) || !is_valid_unicast_v6(dst) {
                return None;
            }
            let icmp6 = &pkt[40..40 + payload_len];
            if icmp6[0] != ICMP_V6_ECHO_REQUEST || icmp6[1] != 0 {
                return None;
            }
            Some(IcmpEchoRequest {
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                id: u16::from_be_bytes([icmp6[4], icmp6[5]]),
                seq: u16::from_be_bytes([icmp6[6], icmp6[7]]),
                payload: icmp6[8..].to_vec(),
                raw_packet: pkt[..40 + payload_len].to_vec(),
            })
        }
        _ => None,
    }
}

fn sum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    sum
}

fn fold_ones_complement(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    fold_ones_complement(sum_words(data))
}

pub(crate) fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp6: &[u8]) -> u16 {
    let len_bytes = (icmp6.len() as u32).to_be_bytes();
    let sum = sum_words(&src.octets())
        + sum_words(&dst.octets())
        + sum_words(&len_bytes)
        + IPPROTO_ICMPV6 as u32
        + sum_words(icmp6);
    fold_ones_complement(sum)
}

fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let id = next_ipv4_id();
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        (id >> 8) as u8,
        id as u8,
        0x00,
        0x00,
        ttl,
        proto,
        0x00,
        0x00,
    ]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let hdr_csum = internet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&hdr_csum.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn build_ipv6_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    hop_limit: u8,
    next_hdr: u8,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut pkt = Vec::with_capacity(40 + payload.len());
    pkt.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (payload_len >> 8) as u8,
        payload_len as u8,
        next_hdr,
        hop_limit,
    ]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    pkt.extend_from_slice(payload);
    pkt
}

fn build_icmp_echo(
    icmp_type: u8,
    id: u16,
    seq: u16,
    payload: &[u8],
    compute_v4_checksum: bool,
) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.extend_from_slice(&[icmp_type, 0, 0, 0]);
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    if compute_v4_checksum {
        let csum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&csum.to_be_bytes());
    }
    icmp
}

pub(crate) fn build_outbound_icmpv4_echo(proxy_id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    build_icmp_echo(ICMP_V4_ECHO_REQUEST, proxy_id, seq, payload, true)
}

pub(crate) fn build_outbound_icmpv6_echo(proxy_id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    // macOS computes and inserts the ICMPv6 checksum on SOCK_DGRAM IPPROTO_ICMPV6 sends.
    build_icmp_echo(ICMP_V6_ECHO_REQUEST, proxy_id, seq, payload, false)
}

pub(crate) fn build_inbound_ipv4_echo_reply(
    from: Ipv4Addr,
    to: Ipv4Addr,
    ttl: u8,
    orig_id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp = build_icmp_echo(ICMP_V4_ECHO_REPLY, orig_id, seq, payload, true);
    build_ipv4_packet(from, to, ttl.max(1), 1, &icmp)
}

pub(crate) fn build_inbound_ipv6_echo_reply(
    from: Ipv6Addr,
    to: Ipv6Addr,
    orig_id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut icmp6 = build_icmp_echo(ICMP_V6_ECHO_REPLY, orig_id, seq, payload, false);
    let csum = icmpv6_checksum(from, to, &icmp6);
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());
    build_ipv6_packet(from, to, 64, 58, &icmp6)
}

/// Synthesize an RFC-compliant ICMP error packet quoting the original Echo Request.
pub(crate) fn build_icmp_error(req: &IcmpEchoRequest, kind: IcmpErrorKind) -> Vec<u8> {
    match req.src {
        IpAddr::V4(orig_src) => {
            let code = match kind {
                IcmpErrorKind::ProxyUnsupported => ICMP_V4_CODE_PROTO_UNREACH,
                IcmpErrorKind::AdminProhibited => ICMP_V4_CODE_ADMIN_PROHIBITED,
            };
            let quoted = &req.raw_packet[..req.raw_packet.len().min(MAX_V4_QUOTED_BYTES)];
            let mut icmp = Vec::with_capacity(8 + quoted.len());
            icmp.extend_from_slice(&[ICMP_V4_DEST_UNREACH, code, 0, 0, 0, 0, 0, 0]);
            icmp.extend_from_slice(quoted);
            let csum = internet_checksum(&icmp);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());
            build_ipv4_packet(utun_macos::UTUN_V4_PEER_ADDR, orig_src, 64, 1, &icmp)
        }
        IpAddr::V6(orig_src) => {
            let (icmp_type, code, rest) = match kind {
                // Pointer 6 identifies the Next Header field inside the quoted IPv6 header.
                IcmpErrorKind::ProxyUnsupported => {
                    (ICMP_V6_PARAM_PROB, ICMP_V6_CODE_NEXT_HDR, 6u32.to_be_bytes())
                }
                IcmpErrorKind::AdminProhibited => {
                    (ICMP_V6_DEST_UNREACH, ICMP_V6_CODE_ADMIN_PROHIBITED, [0u8; 4])
                }
            };
            let quoted = &req.raw_packet[..req.raw_packet.len().min(MAX_V6_QUOTED_BYTES)];
            let mut icmp6 = Vec::with_capacity(8 + quoted.len());
            icmp6.extend_from_slice(&[icmp_type, code, 0, 0]);
            icmp6.extend_from_slice(&rest);
            icmp6.extend_from_slice(quoted);
            let src = utun_macos::UTUN_V6_PEER_ADDR;
            let csum = icmpv6_checksum(src, orig_src, &icmp6);
            icmp6[2..4].copy_from_slice(&csum.to_be_bytes());
            build_ipv6_packet(src, orig_src, 64, 58, &icmp6)
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct ForwardKey {
    orig_src: IpAddr,
    dst: IpAddr,
    orig_id: u16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct ReverseKey {
    dst: IpAddr,
    proxy_id: u16,
}

#[derive(Debug, Clone, Copy)]
struct IcmpFlowEntry {
    orig_src: IpAddr,
    orig_id: u16,
    last_active: Instant,
}

pub(crate) struct IcmpNatTable {
    forward: HashMap<ForwardKey, u16>,
    reverse: HashMap<ReverseKey, IcmpFlowEntry>,
    next_proxy_id: u16,
    flow_ttl: Duration,
    max_flows: usize,
}

impl IcmpNatTable {
    pub(crate) fn new() -> Self {
        Self::with_limits(ICMP_FLOW_TTL, ICMP_MAX_FLOWS)
    }

    pub(crate) fn with_limits(flow_ttl: Duration, max_flows: usize) -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            next_proxy_id: 1,
            flow_ttl,
            max_flows,
        }
    }

    fn is_flow_expired(ttl: Duration, last_active: Instant, now: Instant) -> bool {
        now.saturating_duration_since(last_active) >= ttl
    }

    fn evict_expired(&mut self, now: Instant) {
        let ttl = self.flow_ttl;
        self.reverse.retain(|rev_key, entry| {
            let keep = !Self::is_flow_expired(ttl, entry.last_active, now);
            if !keep {
                self.forward.remove(&ForwardKey {
                    orig_src: entry.orig_src,
                    dst: rev_key.dst,
                    orig_id: entry.orig_id,
                });
            }
            keep
        });
    }

    fn evict_oldest(&mut self) {
        let Some((oldest_key, oldest_entry)) = self
            .reverse
            .iter()
            .min_by_key(|(_, entry)| entry.last_active)
            .map(|(k, e)| (*k, *e))
        else {
            return;
        };
        self.reverse.remove(&oldest_key);
        self.forward.remove(&ForwardKey {
            orig_src: oldest_entry.orig_src,
            dst: oldest_key.dst,
            orig_id: oldest_entry.orig_id,
        });
    }

    fn allocate_proxy_id(&mut self, dst: IpAddr) -> u16 {
        for _ in 0..=u16::MAX {
            let candidate = self.next_proxy_id;
            self.next_proxy_id = self.next_proxy_id.wrapping_add(1);
            if !self
                .reverse
                .contains_key(&ReverseKey { dst, proxy_id: candidate })
            {
                return candidate;
            }
        }
        let fallback = self.next_proxy_id;
        self.next_proxy_id = self.next_proxy_id.wrapping_add(1);
        fallback
    }

    /// Look up or allocate a `(dst, proxy_id)` mapping for an outbound Echo Request.
    /// Returns `(proxy_id, is_new_flow)`.
    pub(crate) fn get_or_insert(
        &mut self,
        orig_src: IpAddr,
        dst: IpAddr,
        orig_id: u16,
        now: Instant,
    ) -> (u16, bool) {
        let ttl = self.flow_ttl;
        let fwd_key = ForwardKey {
            orig_src,
            dst,
            orig_id,
        };
        if let Some(&proxy_id) = self.forward.get(&fwd_key) {
            let rev_key = ReverseKey { dst, proxy_id };
            if let Some(entry) = self.reverse.get_mut(&rev_key) {
                if !Self::is_flow_expired(ttl, entry.last_active, now) {
                    entry.last_active = now;
                    return (proxy_id, false);
                }
            }
            self.forward.remove(&fwd_key);
            self.reverse.remove(&rev_key);
        }

        self.evict_expired(now);
        while self.max_flows > 0 && self.reverse.len() >= self.max_flows {
            self.evict_oldest();
        }

        let proxy_id = self.allocate_proxy_id(dst);
        let rev_key = ReverseKey { dst, proxy_id };
        self.forward.insert(fwd_key, proxy_id);
        self.reverse.insert(
            rev_key,
            IcmpFlowEntry {
                orig_src,
                orig_id,
                last_active: now,
            },
        );
        (proxy_id, true)
    }

    /// Resolve a received Echo Reply `(from, proxy_id)` back to `(orig_src, orig_id)`.
    pub(crate) fn lookup_reply(
        &mut self,
        from: IpAddr,
        proxy_id: u16,
        now: Instant,
    ) -> Option<(IpAddr, u16)> {
        let rev_key = ReverseKey {
            dst: from,
            proxy_id,
        };
        let entry = *self.reverse.get(&rev_key)?;
        if Self::is_flow_expired(self.flow_ttl, entry.last_active, now) {
            self.reverse.remove(&rev_key);
            self.forward.remove(&ForwardKey {
                orig_src: entry.orig_src,
                dst: from,
                orig_id: entry.orig_id,
            });
            return None;
        }
        if let Some(slot) = self.reverse.get_mut(&rev_key) {
            slot.last_active = now;
        }
        Some((entry.orig_src, entry.orig_id))
    }
}

async fn open_icmp_socket(is_ipv4: bool) -> Result<AsyncFd<OwnedFd>> {
    let (domain, proto, label_ip) = if is_ipv4 {
        (
            libc::AF_INET,
            IPPROTO_ICMP,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        )
    } else {
        (
            libc::AF_INET6,
            IPPROTO_ICMPV6,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        )
    };
    let raw_fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, proto) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create ICMP socket");
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    utun_macos::set_nonblocking_cloexec(owned_fd.as_raw_fd())
        .context("failed to configure ICMP socket flags")?;
    prepare_socket_bypass_mangle_for_addr(owned_fd.as_raw_fd(), Some(label_ip))
        .await
        .context("failed to bind ICMP socket to egress interface")?;
    // SAFETY: `owned_fd` remains open and uniquely owned by the returned `AsyncFd`.
    unsafe { AsyncFd::register(owned_fd) }.context("failed to register ICMP socket with tokio")
}

fn sendto_icmp(sock: &AsyncFd<OwnedFd>, dst: IpAddr, payload: &[u8]) {
    let sa = SockAddr::from(SocketAddr::new(dst, 0));
    loop {
        let ret = unsafe {
            libc::sendto(
                sock.get_ref().as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                sa.as_ptr().cast(),
                sa.len(),
            )
        };
        if ret >= 0 {
            return;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        debug!("icmp sendto {} failed: {}", dst, err);
        return;
    }
}

fn recvfrom_icmp(fd: i32, buf: &mut [u8]) -> std::io::Result<(usize, IpAddr)> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ret = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr>(),
            &mut len,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ip = match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe {
                &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
            };
            IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe {
                &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
            };
            IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected sockaddr family from ICMP socket",
            ))
        }
    };
    Ok((ret as usize, ip))
}

async fn wait_readable(
    sock: Option<&AsyncFd<OwnedFd>>,
) -> std::io::Result<tokio::io::unix::AsyncFdReadyGuard<'_, OwnedFd>> {
    match sock {
        Some(sock) => sock.readable().await,
        None => std::future::pending().await,
    }
}

fn decode_and_forward_reply(
    pkt: &[u8],
    from_ip: IpAddr,
    is_ipv4: bool,
    nat: &mut IcmpNatTable,
    reply_tx: &mpsc::Sender<Vec<u8>>,
) {
    let now = Instant::now();
    if is_ipv4 {
        // macOS SOCK_DGRAM IPPROTO_ICMP returns the IPv4 header + ICMP payload.
        if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
            return;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if ihl < 20 || pkt.len() < ihl + 8 {
            return;
        }
        let ttl = pkt[8];
        let icmp = &pkt[ihl..];
        if icmp[0] != ICMP_V4_ECHO_REPLY || icmp[1] != 0 {
            return;
        }
        let proxy_id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
        if let (IpAddr::V4(from_v4), Some((IpAddr::V4(orig_src), orig_id))) =
            (from_ip, nat.lookup_reply(from_ip, proxy_id, now))
        {
            let reply =
                build_inbound_ipv4_echo_reply(from_v4, orig_src, ttl, orig_id, seq, &icmp[8..]);
            let _ = reply_tx.try_send(reply);
        }
    } else {
        // macOS SOCK_DGRAM IPPROTO_ICMPV6 strips the IPv6 header and echoes back Type 128 requests.
        if pkt.len() < 8 || pkt[0] != ICMP_V6_ECHO_REPLY || pkt[1] != 0 {
            return;
        }
        let proxy_id = u16::from_be_bytes([pkt[4], pkt[5]]);
        let seq = u16::from_be_bytes([pkt[6], pkt[7]]);
        if let (IpAddr::V6(from_v6), Some((IpAddr::V6(orig_src), orig_id))) =
            (from_ip, nat.lookup_reply(from_ip, proxy_id, now))
        {
            let reply =
                build_inbound_ipv6_echo_reply(from_v6, orig_src, orig_id, seq, &pkt[8..]);
            let _ = reply_tx.try_send(reply);
        }
    }
}

fn drain_icmp_replies(
    mut guard: tokio::io::unix::AsyncFdReadyGuard<'_, OwnedFd>,
    is_ipv4: bool,
    nat: &mut IcmpNatTable,
    reply_tx: &mpsc::Sender<Vec<u8>>,
    buf: &mut [u8],
) {
    for _ in 0..ICMP_BATCH {
        match guard.try_io(|inner| recvfrom_icmp(inner.as_raw_fd(), buf)) {
            Ok(Ok((n, from_ip))) => {
                decode_and_forward_reply(&buf[..n], from_ip, is_ipv4, nat, reply_tx);
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) => {
                debug!("icmp recvfrom failed: {}", e);
                break;
            }
            Err(_would_block) => break,
        }
    }
}

pub(crate) async fn icmp_worker(
    mut req_rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let v4_sock = match open_icmp_socket(true).await {
        Ok(sock) => Some(sock),
        Err(err) => {
            warn!("failed to open outbound IPv4 ICMP socket: {:#}", err);
            None
        }
    };
    let v6_sock = match open_icmp_socket(false).await {
        Ok(sock) => Some(sock),
        Err(err) => {
            warn!("failed to open outbound IPv6 ICMP socket: {:#}", err);
            None
        }
    };

    let mut nat = IcmpNatTable::new();
    let mut recv_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            maybe_pkt = req_rx.recv() => {
                let Some(pkt) = maybe_pkt else { break };
                let Some(req) = parse_echo_request(&pkt) else {
                    continue;
                };
                let action = {
                    let settings = get_settings().read().await;
                    settings.routetable.resolve_icmp_action(req.dst)
                };
                match action {
                    Ok(IcmpRouteAction::Direct { outbound }) => {
                        let (proxy_id, is_new) =
                            nat.get_or_insert(req.src, req.dst, req.id, Instant::now());
                        if is_new {
                            info!("icmp relay: {} -> {} -> Outbound({})", req.src, req.dst, outbound);
                        } else {
                            debug!("icmp relay: {} -> {} -> Outbound({})", req.src, req.dst, outbound);
                        }
                        match req.dst {
                            IpAddr::V4(_) => {
                                if let Some(ref sock) = v4_sock {
                                    let out = build_outbound_icmpv4_echo(proxy_id, req.seq, &req.payload);
                                    sendto_icmp(sock, req.dst, &out);
                                }
                            }
                            IpAddr::V6(_) => {
                                if let Some(ref sock) = v6_sock {
                                    let out = build_outbound_icmpv6_echo(proxy_id, req.seq, &req.payload);
                                    sendto_icmp(sock, req.dst, &out);
                                }
                            }
                        }
                    }
                    Ok(IcmpRouteAction::Proxy { outbound }) => {
                        info!(
                            "icmp: {} -> {} -> Outbound({}) (unsupported by proxy, replying ICMP error)",
                            req.src, req.dst, outbound
                        );
                        let _ = reply_tx.try_send(build_icmp_error(&req, IcmpErrorKind::ProxyUnsupported));
                    }
                    Ok(IcmpRouteAction::Drop { outbound }) => {
                        info!(
                            "icmp: {} -> {} -> Outbound({}) (replying ICMP administratively prohibited)",
                            req.src, req.dst, outbound
                        );
                        let _ = reply_tx.try_send(build_icmp_error(&req, IcmpErrorKind::AdminProhibited));
                    }
                    Err(err) => {
                        debug!("icmp route resolution failed for {}: {}", req.dst, err);
                    }
                }
            }
            res = wait_readable(v4_sock.as_ref()) => {
                drain_icmp_replies(res?, true, &mut nat, &reply_tx, &mut recv_buf);
            }
            res = wait_readable(v6_sock.as_ref()) => {
                drain_icmp_replies(res?, false, &mut nat, &reply_tx, &mut recv_buf);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_ipv4_icmp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ihl_words: u8,
        frag_field: u16,
        proto: u8,
        icmp_payload: &[u8],
    ) -> Vec<u8> {
        let ihl_bytes = (ihl_words as usize) * 4;
        let total_len = (ihl_bytes + icmp_payload.len()) as u16;
        let mut pkt = vec![0u8; total_len as usize];
        pkt[0] = (4 << 4) | (ihl_words & 0x0f);
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[6..8].copy_from_slice(&frag_field.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        let csum = internet_checksum(&pkt[..ihl_bytes]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt[ihl_bytes..].copy_from_slice(icmp_payload);
        pkt
    }

    fn build_test_ipv6_icmp(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_hdr: u8,
        icmp_payload: &[u8],
    ) -> Vec<u8> {
        let mut icmp = icmp_payload.to_vec();
        if icmp.len() >= 4 {
            icmp[2] = 0;
            icmp[3] = 0;
            let csum = icmpv6_checksum(src, dst, &icmp);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());
        }
        build_ipv6_packet(src, dst, 64, next_hdr, &icmp)
    }

    #[test]
    fn parse_echo_request_accepts_ipv4_with_options_and_ipv6() {
        let v4_src = Ipv4Addr::new(198, 19, 254, 1);
        let v4_dst = Ipv4Addr::new(1, 1, 1, 1);
        let icmp_echo = build_outbound_icmpv4_echo(0x1234, 7, b"ping4");
        let mut v4_pkt = build_test_ipv4_icmp(v4_src, v4_dst, 6, 0x4000, 1, &icmp_echo);
        v4_pkt.extend_from_slice(&[0xaa, 0xbb]); // trailing link padding beyond total_len
        assert!(is_icmp_packet(&v4_pkt));

        let parsed = parse_echo_request(&v4_pkt).expect("valid IPv4 echo request");
        assert_eq!(parsed.src, IpAddr::V4(v4_src));
        assert_eq!(parsed.dst, IpAddr::V4(v4_dst));
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.seq, 7);
        assert_eq!(parsed.payload, b"ping4");
        assert_eq!(parsed.raw_packet.len(), 24 + icmp_echo.len());

        let v6_src = Ipv6Addr::new(0xfd72, 0x666f, 0x7200, 0, 0, 0, 0, 1);
        let v6_dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let icmp6_echo = build_icmp_echo(ICMP_V6_ECHO_REQUEST, 0x5678, 9, b"ping6", false);
        let v6_pkt = build_test_ipv6_icmp(v6_src, v6_dst, 58, &icmp6_echo);
        assert!(is_icmp_packet(&v6_pkt));

        let parsed6 = parse_echo_request(&v6_pkt).expect("valid IPv6 echo request");
        assert_eq!(parsed6.src, IpAddr::V6(v6_src));
        assert_eq!(parsed6.dst, IpAddr::V6(v6_dst));
        assert_eq!(parsed6.id, 0x5678);
        assert_eq!(parsed6.seq, 9);
        assert_eq!(parsed6.payload, b"ping6");
    }

    #[test]
    fn parse_echo_request_rejects_fragments_multicast_truncated_and_non_echo() {
        let v4_src = Ipv4Addr::new(198, 19, 254, 1);
        let v4_dst = Ipv4Addr::new(1, 1, 1, 1);
        let echo = build_outbound_icmpv4_echo(0x1111, 1, b"abc");

        // Fragmented IPv4 (offset = 1 or MF = 1)
        assert!(parse_echo_request(&build_test_ipv4_icmp(v4_src, v4_dst, 5, 0x2000, 1, &echo)).is_none());
        assert!(parse_echo_request(&build_test_ipv4_icmp(v4_src, v4_dst, 5, 0x0001, 1, &echo)).is_none());

        // Multicast / broadcast / unspecified destinations
        assert!(parse_echo_request(&build_test_ipv4_icmp(
            v4_src,
            Ipv4Addr::new(224, 0, 0, 1),
            5,
            0,
            1,
            &echo
        ))
        .is_none());
        assert!(parse_echo_request(&build_test_ipv4_icmp(
            v4_src,
            Ipv4Addr::BROADCAST,
            5,
            0,
            1,
            &echo
        ))
        .is_none());
        assert!(parse_echo_request(&build_test_ipv4_icmp(
            Ipv4Addr::UNSPECIFIED,
            v4_dst,
            5,
            0,
            1,
            &echo
        ))
        .is_none());

        // Non-echo ICMPv4 (Type 3 error)
        let mut err_icmp = echo.clone();
        err_icmp[0] = ICMP_V4_DEST_UNREACH;
        assert!(parse_echo_request(&build_test_ipv4_icmp(v4_src, v4_dst, 5, 0, 1, &err_icmp)).is_none());

        // Truncated IPv4
        let valid_v4 = build_test_ipv4_icmp(v4_src, v4_dst, 5, 0, 1, &echo);
        assert!(parse_echo_request(&valid_v4[..27]).is_none());
        assert!(parse_echo_request(&valid_v4[..19]).is_none());

        // Non-echo ICMPv6 and multicast IPv6
        let v6_src = Ipv6Addr::new(0xfd72, 0x666f, 0x7200, 0, 0, 0, 0, 1);
        let echo6 = build_icmp_echo(ICMP_V6_ECHO_REQUEST, 0x1, 1, b"x", false);
        assert!(parse_echo_request(&build_test_ipv6_icmp(
            v6_src,
            "ff02::1".parse().unwrap(),
            58,
            &echo6
        ))
        .is_none());
        let reply6 = build_icmp_echo(ICMP_V6_ECHO_REPLY, 0x1, 1, b"x", false);
        assert!(parse_echo_request(&build_test_ipv6_icmp(
            v6_src,
            "2606:4700:4700::1111".parse().unwrap(),
            58,
            &reply6
        ))
        .is_none());
    }

    #[test]
    fn build_icmp_errors_verify_rfc_headers_checksums_and_quote_caps() {
        let v4_src = Ipv4Addr::new(198, 19, 254, 1);
        let v4_dst = Ipv4Addr::new(203, 0, 113, 10);
        let big_payload = vec![0x5a; 800];
        let v4_raw = build_test_ipv4_icmp(
            v4_src,
            v4_dst,
            5,
            0,
            1,
            &build_outbound_icmpv4_echo(0x1234, 2, &big_payload),
        );
        let req4 = parse_echo_request(&v4_raw).unwrap();

        let err_proxy = build_icmp_error(&req4, IcmpErrorKind::ProxyUnsupported);
        assert_eq!(err_proxy.len(), 20 + 8 + MAX_V4_QUOTED_BYTES);
        assert_eq!(internet_checksum(&err_proxy[..20]), 0);
        assert_eq!(internet_checksum(&err_proxy[20..]), 0);
        assert_eq!(&err_proxy[12..16], &utun_macos::UTUN_V4_PEER_ADDR.octets());
        assert_eq!(&err_proxy[16..20], &v4_src.octets());
        assert_eq!(err_proxy[20], ICMP_V4_DEST_UNREACH);
        assert_eq!(err_proxy[21], ICMP_V4_CODE_PROTO_UNREACH);

        let err_drop = build_icmp_error(&req4, IcmpErrorKind::AdminProhibited);
        assert_eq!(err_drop[20], ICMP_V4_DEST_UNREACH);
        assert_eq!(err_drop[21], ICMP_V4_CODE_ADMIN_PROHIBITED);
        assert_eq!(internet_checksum(&err_drop[20..]), 0);

        let v6_src = Ipv6Addr::new(0xfd72, 0x666f, 0x7200, 0, 0, 0, 0, 1);
        let v6_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let v6_raw = build_test_ipv6_icmp(
            v6_src,
            v6_dst,
            58,
            &build_icmp_echo(ICMP_V6_ECHO_REQUEST, 0x2222, 3, &vec![0x77; 1500], false),
        );
        let req6 = parse_echo_request(&v6_raw).unwrap();

        let err6_proxy = build_icmp_error(&req6, IcmpErrorKind::ProxyUnsupported);
        assert_eq!(err6_proxy.len(), 40 + 8 + MAX_V6_QUOTED_BYTES);
        assert_eq!(err6_proxy[6], 58);
        assert_eq!(&err6_proxy[8..24], &utun_macos::UTUN_V6_PEER_ADDR.octets());
        assert_eq!(&err6_proxy[24..40], &v6_src.octets());
        assert_eq!(err6_proxy[40], ICMP_V6_PARAM_PROB);
        assert_eq!(err6_proxy[41], ICMP_V6_CODE_NEXT_HDR);
        assert_eq!(u32::from_be_bytes(err6_proxy[44..48].try_into().unwrap()), 6);
        assert_eq!(
            icmpv6_checksum(utun_macos::UTUN_V6_PEER_ADDR, v6_src, &err6_proxy[40..]),
            0
        );

        let err6_drop = build_icmp_error(&req6, IcmpErrorKind::AdminProhibited);
        assert_eq!(err6_drop[40], ICMP_V6_DEST_UNREACH);
        assert_eq!(err6_drop[41], ICMP_V6_CODE_ADMIN_PROHIBITED);
        assert_eq!(
            icmpv6_checksum(utun_macos::UTUN_V6_PEER_ADDR, v6_src, &err6_drop[40..]),
            0
        );
    }

    #[test]
    fn build_inbound_echo_replies_restore_id_ttl_and_checksums() {
        let from4 = Ipv4Addr::new(1, 1, 1, 1);
        let to4 = Ipv4Addr::new(198, 19, 254, 1);
        let reply4 = build_inbound_ipv4_echo_reply(from4, to4, 57, 0x4321, 12, b"pong4");
        assert_eq!(internet_checksum(&reply4[..20]), 0);
        assert_eq!(internet_checksum(&reply4[20..]), 0);
        assert_eq!(reply4[8], 57);
        assert_eq!(reply4[9], 1);
        assert_eq!(reply4[20], ICMP_V4_ECHO_REPLY);
        assert_eq!(reply4[21], 0);
        assert_eq!(u16::from_be_bytes([reply4[24], reply4[25]]), 0x4321);
        assert_eq!(u16::from_be_bytes([reply4[26], reply4[27]]), 12);
        assert_eq!(&reply4[28..], b"pong4");

        let from6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let to6: Ipv6Addr = "fd72:666f:7200::1".parse().unwrap();
        let reply6 = build_inbound_ipv6_echo_reply(from6, to6, 0x8765, 3, b"pong6");
        assert_eq!(reply6[6], 58);
        assert_eq!(reply6[7], 64);
        assert_eq!(reply6[40], ICMP_V6_ECHO_REPLY);
        assert_eq!(reply6[41], 0);
        assert_eq!(u16::from_be_bytes([reply6[44], reply6[45]]), 0x8765);
        assert_eq!(u16::from_be_bytes([reply6[46], reply6[47]]), 3);
        assert_eq!(&reply6[48..], b"pong6");
        assert_eq!(icmpv6_checksum(from6, to6, &reply6[40..]), 0);
    }

    #[test]
    fn nat_table_isolates_clients_expires_ttl_and_bounds_capacity() {
        let t0 = Instant::now();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        let src_a: IpAddr = "198.19.254.1".parse().unwrap();
        let src_b: IpAddr = "10.0.0.2".parse().unwrap();

        let mut nat = IcmpNatTable::with_limits(Duration::from_secs(30), 2);
        let (pid_a1, new_a1) = nat.get_or_insert(src_a, dst, 0x100, t0);
        assert!(new_a1);
        let (pid_a2, new_a2) = nat.get_or_insert(src_a, dst, 0x100, t0 + Duration::from_secs(1));
        assert!(!new_a2);
        assert_eq!(pid_a1, pid_a2);

        // Two clients using identical orig_id toward the same destination get distinct proxy IDs.
        let (pid_b, new_b) = nat.get_or_insert(src_b, dst, 0x100, t0 + Duration::from_secs(2));
        assert!(new_b);
        assert_ne!(pid_b, pid_a1);

        assert_eq!(
            nat.lookup_reply(dst, pid_a1, t0 + Duration::from_secs(3)),
            Some((src_a, 0x100))
        );
        assert_eq!(
            nat.lookup_reply(dst, pid_b, t0 + Duration::from_secs(4)),
            Some((src_b, 0x100))
        );

        // Third flow exceeds max_flows=2 and evicts oldest (src_a/pid_a1 last active at +3s vs src_b at +4s).
        let src_c: IpAddr = "10.0.0.3".parse().unwrap();
        let (pid_c, new_c) = nat.get_or_insert(src_c, dst, 0x200, t0 + Duration::from_secs(5));
        assert!(new_c);
        assert_eq!(nat.lookup_reply(dst, pid_a1, t0 + Duration::from_secs(5)), None);
        assert_eq!(
            nat.lookup_reply(dst, pid_b, t0 + Duration::from_secs(5)),
            Some((src_b, 0x100))
        );
        assert_eq!(
            nat.lookup_reply(dst, pid_c, t0 + Duration::from_secs(5)),
            Some((src_c, 0x200))
        );

        // TTL expiry removes stale mappings.
        assert_eq!(
            nat.lookup_reply(dst, pid_c, t0 + Duration::from_secs(36)),
            None
        );
    }
}
