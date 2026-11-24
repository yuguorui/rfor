//! Shared TPROXY TCP sniffing, UDP session dispatch, QUIC/DNS aggregation,
//! and address/rate-limit helpers used across Unix and macOS data planes.

use anyhow::Result;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::get_settings;
use crate::rules::{InboundProtocol, ProxyDgram, RouteContext, SocketType, TargetAddr};
use crate::sniffer::{QuicParseResult, QuicSniAggregator, SniffedHost, SniffedProtocol};
use crate::stats::UDP_STATS;
use crate::utils::{is_valid_domain, ToV6SockAddr};

/// Channel buffer size for forwarding packets to existing UDP sessions.
pub(super) const UDP_SESSION_CHANNEL_SIZE: usize = 32;

/// DNS exchanges are request/response flows; use a shorter idle timeout than generic UDP.
pub(super) const DNS_UDP_TIMEOUT_SECS: u64 = 10;

pub(super) const QUIC_SNI_MAX_BUFFERED_PACKETS: usize = 16;
pub(super) const QUIC_SNI_AGGREGATION_TIMEOUT_MS: u64 = 300;

/// Unmap an IPv4-mapped IPv6 socket address (`::ffff:a.b.c.d`) back to native IPv4.
pub(super) fn unmap_ipv4_mapped(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if let Some(v4) = v6.ip().to_ipv4_mapped() {
            return SocketAddr::V4(SocketAddrV4::new(v4, v6.port()));
        }
    }
    addr
}

/// Normalize an IPv4 or IPv6 address into `rfor`'s canonical IPv6 form.
pub(super) fn canonical_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

/// A connected UDP reply socket receives `ECONNREFUSED` when the client closes
/// its local UDP port and answers a trailing reply with ICMP Port Unreachable.
/// Treat that as a normal session close rather than an error.
pub(super) fn is_udp_peer_closed(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::ConnectionRefused
}

/// Choose the UDP idle timeout, applying the shorter DNS timeout only when the
/// payload itself was identified as DNS.
pub(super) fn udp_session_timeout(
    sniffed_proto: Option<SniffedProtocol>,
    default_timeout_secs: u64,
) -> Duration {
    if sniffed_proto == Some(SniffedProtocol::Dns) {
        Duration::from_secs(DNS_UDP_TIMEOUT_SECS)
    } else {
        Duration::from_secs(default_timeout_secs)
    }
}

pub(super) struct SniffedTcpRoute {
    pub(super) context: RouteContext,
    pub(super) initial_data: Vec<u8>,
}

/// Sniff HTTP/TLS/DNS-over-TCP on an inbound transparent stream and build its `RouteContext`.
pub(super) async fn sniff_tcp_route<S: AsyncRead + Unpin>(
    inbound: &mut S,
    peer_addr: SocketAddr,
    orig_dst: SocketAddr,
) -> std::io::Result<Option<SniffedTcpRoute>> {
    let Some(sniffed) = crate::sniffer::sniff_tcp(inbound).await? else {
        return Ok(None);
    };
    let mut domain = sniffed.host.filter(|s| is_valid_domain(s.host.as_str()));

    if domain.is_none() && orig_dst.port() == 53 {
        domain = crate::sniffer::dns_parse::parse_host_tcp(&sniffed.data)
            .filter(|s| is_valid_domain(s.as_str()))
            .map(|host| SniffedHost {
                host,
                protocol: Some(SniffedProtocol::Dns),
            });
    }

    let sniffed_proto = domain.as_ref().and_then(|d| d.protocol);
    let target_addr = match domain {
        Some(domain) => TargetAddr::Domain(domain.host, orig_dst.port(), Some(orig_dst)),
        None => TargetAddr::Ip(orig_dst),
    };

    Ok(Some(SniffedTcpRoute {
        context: RouteContext {
            src_addr: peer_addr,
            dst_addr: target_addr,
            inbound_proto: Some(InboundProtocol::TPROXY),
            socket_type: SocketType::STREAM,
            sniffed_proto,
        },
        initial_data: sniffed.data,
    }))
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct UdpSessionKey {
    source: SocketAddr,
    target: SocketAddr,
}

impl UdpSessionKey {
    fn new(source: SocketAddr, target: SocketAddr) -> Self {
        Self {
            source: source.to_ipv6_sockaddr(),
            target: target.to_ipv6_sockaddr(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct UdpSessionId(u64);

static NEXT_UDP_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn next_udp_session_id() -> UdpSessionId {
    UdpSessionId(NEXT_UDP_SESSION_ID.fetch_add(1, Ordering::Relaxed))
}

struct UdpSessionEntry {
    id: UdpSessionId,
    packet_tx: mpsc::Sender<bytes::Bytes>,
}

struct UdpSessionTable {
    sessions: DashMap<UdpSessionKey, UdpSessionEntry>,
    track_stats: bool,
}

impl UdpSessionTable {
    fn new(track_stats: bool) -> Self {
        Self {
            sessions: DashMap::new(),
            track_stats,
        }
    }

    fn dispatch(
        &'static self,
        source_sockaddr: SocketAddr,
        target_sockaddr: SocketAddr,
        prefilled_data: bytes::Bytes,
        max_sessions: usize,
    ) -> Option<NewUdpSession> {
        let pkt_len = prefilled_data.len();
        let session_key = UdpSessionKey::new(source_sockaddr, target_sockaddr);

        // Existing sessions must remain usable after the global new-session limit
        // has been reached. Check the map before checking `len()`, and avoid
        // calling `len()` while holding a shard entry lock.
        if let Some(session) = self.sessions.get(&session_key) {
            let session_id = session.id;
            match handle_forward_result(
                session.packet_tx.try_send(prefilled_data.clone()),
                session_id,
                source_sockaddr,
                target_sockaddr,
                pkt_len,
            ) {
                None => return None,
                Some(stale_id) => {
                    drop(session);
                    self.sessions
                        .remove_if(&session_key, |_, entry| entry.id == stale_id);
                    debug!(
                        "udp relay: removed stale session {:?} <-> {:?}",
                        source_sockaddr, target_sockaddr
                    );
                }
            }
        }

        if max_sessions > 0 && self.sessions.len() >= max_sessions {
            warn!(
                "udp relay: max sessions limit ({}) reached, dropping new session {:?} <-> {:?}",
                max_sessions, source_sockaddr, target_sockaddr
            );
            return None;
        }

        match self.sessions.entry(session_key) {
            Entry::Occupied(entry) => {
                let session_id = entry.get().id;
                if let Some(stale_id) = handle_forward_result(
                    entry.get().packet_tx.try_send(prefilled_data),
                    session_id,
                    source_sockaddr,
                    target_sockaddr,
                    pkt_len,
                ) {
                    drop(entry);
                    self.sessions
                        .remove_if(&session_key, |_, entry| entry.id == stale_id);
                    debug!(
                        "udp relay: removed stale session {:?} <-> {:?}",
                        source_sockaddr, target_sockaddr
                    );
                }
                None
            }
            Entry::Vacant(entry) => {
                let (tx, rx) = mpsc::channel(UDP_SESSION_CHANNEL_SIZE);
                if let Err(e) = tx.try_send(prefilled_data) {
                    error!("Failed to send init packet to new UDP session: {}", e);
                    return None;
                }

                let id = next_udp_session_id();
                entry.insert(UdpSessionEntry { id, packet_tx: tx });
                let lease = UdpSessionLease::new(self, session_key, id);
                Some(NewUdpSession {
                    packet_rx: rx,
                    lease,
                    active_sessions: self.sessions.len(),
                })
            }
        }
    }
}

/// Removes the session and updates stats when the relay task exits, including
/// early error/panic exits. Only removes the matching generation.
#[must_use = "the lease must be held for the lifetime of the relay task"]
pub(super) struct UdpSessionLease {
    table: &'static UdpSessionTable,
    key: UdpSessionKey,
    id: UdpSessionId,
}

impl UdpSessionLease {
    fn new(table: &'static UdpSessionTable, key: UdpSessionKey, id: UdpSessionId) -> Self {
        if table.track_stats {
            UDP_STATS.session_start();
        }
        Self { table, key, id }
    }
}

impl Drop for UdpSessionLease {
    fn drop(&mut self) {
        self.table
            .sessions
            .remove_if(&self.key, |_, entry| entry.id == self.id);
        if self.table.track_stats {
            UDP_STATS.session_end(0);
        }
    }
}

static UDP_SESSIONS: Lazy<UdpSessionTable> = Lazy::new(|| UdpSessionTable::new(true));

#[cfg(target_os = "macos")]
static BYPASS_UDP_SESSIONS: Lazy<UdpSessionTable> = Lazy::new(|| UdpSessionTable::new(false));

pub(super) struct NewUdpSession {
    pub(super) packet_rx: mpsc::Receiver<bytes::Bytes>,
    pub(super) lease: UdpSessionLease,
    pub(super) active_sessions: usize,
}

fn handle_forward_result(
    res: std::result::Result<(), mpsc::error::TrySendError<bytes::Bytes>>,
    id: UdpSessionId,
    source_sockaddr: SocketAddr,
    target_sockaddr: SocketAddr,
    pkt_len: usize,
) -> Option<UdpSessionId> {
    match res {
        Ok(()) => {
            debug!(
                "udp relay: forwarded packet to existing session {:?} <-> {:?}, {} bytes",
                source_sockaddr, target_sockaddr, pkt_len
            );
            None
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!(
                "udp relay: channel full for session {:?} <-> {:?}, packet dropped",
                source_sockaddr, target_sockaddr
            );
            None
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Some(id),
    }
}

/// Route an incoming UDP packet into an active session channel or create a new
/// session when `max_sessions` allows.
pub(super) fn dispatch_udp_session(
    source_sockaddr: SocketAddr,
    target_sockaddr: SocketAddr,
    prefilled_data: bytes::Bytes,
    max_sessions: usize,
) -> Option<NewUdpSession> {
    UDP_SESSIONS.dispatch(source_sockaddr, target_sockaddr, prefilled_data, max_sessions)
}

/// Route a non-intercepted macOS UDP packet into a dedicated bypass session table
/// excluded from `udp_max_sessions` limits and `UDP_STATS` accounting.
#[cfg(target_os = "macos")]
pub(super) fn dispatch_bypass_udp_session(
    source_sockaddr: SocketAddr,
    target_sockaddr: SocketAddr,
    prefilled_data: bytes::Bytes,
) -> Option<NewUdpSession> {
    BYPASS_UDP_SESSIONS.dispatch(source_sockaddr, target_sockaddr, prefilled_data, 0)
}

async fn sniff_host_with_quic_aggregation(
    packet_rx: &mut mpsc::Receiver<bytes::Bytes>,
) -> (Option<SniffedHost>, Vec<bytes::Bytes>) {
    let mut buffered_packets = Vec::new();

    let Some(init_packet) = packet_rx.recv().await else {
        return (None, buffered_packets);
    };

    buffered_packets.push(init_packet.clone());

    if let Some(host) = crate::sniffer::dns_parse::parse_host(&init_packet) {
        debug!("DNS query domain parsed from first packet: {}", host);
        return (
            Some(SniffedHost {
                host,
                protocol: Some(SniffedProtocol::Dns),
            }),
            buffered_packets,
        );
    }

    let mut aggregator = QuicSniAggregator::new();
    match aggregator.process_packet(&init_packet) {
        QuicParseResult::Success(host) => {
            debug!("QUIC SNI parsed from first packet: {}", host.host);
            return (Some(host), buffered_packets);
        }
        QuicParseResult::NeedMoreData(dest_cid) => {
            debug!(
                "QUIC SNI needs more packets, dest_cid: {:x?}, waiting for additional packets",
                dest_cid
            );
        }
        QuicParseResult::Failed(e) => {
            debug!("QUIC parsing failed: {}, trying other protocols", e);
            if let Some(host) = crate::sniffer::parse_host(&init_packet) {
                return (
                    Some(SniffedHost {
                        host,
                        protocol: None,
                    }),
                    buffered_packets,
                );
            }
            return (None, buffered_packets);
        }
    }

    let timeout = tokio::time::sleep(Duration::from_millis(QUIC_SNI_AGGREGATION_TIMEOUT_MS));
    tokio::pin!(timeout);

    loop {
        if buffered_packets.len() >= QUIC_SNI_MAX_BUFFERED_PACKETS {
            debug!(
                "QUIC SNI aggregation: reached max buffered packets ({}), giving up",
                QUIC_SNI_MAX_BUFFERED_PACKETS
            );
            break;
        }

        tokio::select! {
            Some(packet) = packet_rx.recv() => {
                buffered_packets.push(packet.clone());

                match aggregator.process_packet(&packet) {
                    QuicParseResult::Success(host) => {
                        debug!(
                            "QUIC SNI parsed after {} packets: {}",
                            buffered_packets.len(),
                            host.host
                        );
                        return (Some(host), buffered_packets);
                    }
                    QuicParseResult::NeedMoreData(_) => {
                        debug!(
                            "QUIC SNI still needs more packets after {} packets",
                            buffered_packets.len()
                        );
                    }
                    QuicParseResult::Failed(e) => {
                        debug!(
                            "QUIC parsing failed after {} packets: {}",
                            buffered_packets.len(),
                            e
                        );
                        break;
                    }
                }
            }
            _ = &mut timeout => {
                debug!(
                    "QUIC SNI aggregation timeout after {}ms with {} packets",
                    QUIC_SNI_AGGREGATION_TIMEOUT_MS,
                    buffered_packets.len()
                );
                break;
            }
        }
    }

    (None, buffered_packets)
}

pub(super) enum UdpRouteOutcome {
    Empty,
    Dropped {
        nxdomain_reply: Option<Vec<u8>>,
    },
    Ready {
        target_socket: Box<dyn ProxyDgram>,
        dst_addr: TargetAddr,
        sniffed_proto: Option<SniffedProtocol>,
        buffered_packets: Vec<bytes::Bytes>,
    },
}

/// Sniff UDP payloads (DNS / QUIC / fallback) and resolve the outbound `ProxyDgram`.
pub(super) async fn prepare_udp_route(
    packet_rx: &mut mpsc::Receiver<bytes::Bytes>,
    source_sockaddr: SocketAddr,
    target_sockaddr: SocketAddr,
    wire_target: SocketAddr,
    dns_drop_nxdomain: bool,
) -> Result<UdpRouteOutcome> {
    let (host, buffered_packets) = sniff_host_with_quic_aggregation(packet_rx).await;
    if buffered_packets.is_empty() {
        return Ok(UdpRouteOutcome::Empty);
    }

    let sniffed_proto = host.as_ref().and_then(|h| h.protocol);
    let dst_addr = match host {
        None => TargetAddr::Ip(wire_target),
        Some(host) => TargetAddr::Domain(host.host, target_sockaddr.port(), Some(target_sockaddr)),
    };

    let target_socket = match get_settings()
        .read()
        .await
        .routetable
        .get_dgram_sock(&RouteContext {
            src_addr: source_sockaddr,
            dst_addr: dst_addr.clone(),
            inbound_proto: Some(InboundProtocol::TPROXY),
            socket_type: SocketType::DGRAM,
            sniffed_proto,
        })
        .await
    {
        Ok(sock) => sock,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            let nxdomain_reply = if dns_drop_nxdomain {
                crate::sniffer::dns_parse::build_nxdomain_response(&buffered_packets[0])
            } else {
                None
            };
            return Ok(UdpRouteOutcome::Dropped { nxdomain_reply });
        }
        Err(err) => return Err(err.into()),
    };

    Ok(UdpRouteOutcome::Ready {
        target_socket,
        dst_addr,
        sniffed_proto,
        buffered_packets,
    })
}

/// Extract an IP address from a `ProxyDgram` response target, warning when
/// full-cone NAT encounters an unresolved domain response.
pub(super) fn extract_udp_response_ip(addr: &TargetAddr) -> Option<SocketAddr> {
    match addr {
        TargetAddr::Ip(ip) => Some(*ip),
        TargetAddr::Domain(_, _, Some(ip)) => Some(*ip),
        TargetAddr::Domain(domain, port, None) => {
            warn!(
                "udp relay (fullcone): received response from domain {}:{} without resolved IP",
                domain, port
            );
            None
        }
    }
}

/// Token-bucket rate limiter (refilled per second) for new full-cone peer state.
pub(super) struct FullconeRateLimiter {
    tokens: u32,
    last_refill: Instant,
    max_tokens: u32,
}

impl FullconeRateLimiter {
    pub(super) fn new(rate: u32) -> Self {
        Self {
            tokens: rate,
            last_refill: Instant::now(),
            max_tokens: rate,
        }
    }

    pub(super) fn try_acquire(&mut self) -> bool {
        if self.max_tokens == 0 {
            return true;
        }
        let now = Instant::now();
        if now.duration_since(self.last_refill).as_secs() >= 1 {
            self.tokens = self.max_tokens;
            self.last_refill = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV6};

    static UDP_SESSION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn addresses_use_canonical_ipv6_form() {
        let mapped_loopback = Ipv4Addr::LOCALHOST.to_ipv6_mapped();

        assert_eq!(
            canonical_ipv6(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            mapped_loopback
        );
        assert_eq!(
            canonical_ipv6(IpAddr::V6(mapped_loopback)),
            mapped_loopback
        );
        assert_eq!(
            canonical_ipv6(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Ipv6Addr::LOCALHOST
        );
    }

    #[test]
    fn unmap_ipv4_mapped_unmaps_socket_address() {
        let v4 = Ipv4Addr::new(192, 0, 2, 7);
        let mapped = SocketAddr::V6(SocketAddrV6::new(v4.to_ipv6_mapped(), 19000, 0, 0));
        assert_eq!(
            unmap_ipv4_mapped(mapped),
            SocketAddr::V4(SocketAddrV4::new(v4, 19000))
        );

        let native = SocketAddr::V6(SocketAddrV6::new("2001:db8::7".parse().unwrap(), 443, 0, 0));
        assert_eq!(unmap_ipv4_mapped(native), native);
    }

    #[test]
    fn udp_session_lease_removes_only_its_generation() {
        let _guard = UDP_SESSION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = UdpSessionKey::new(
            "127.0.0.1:65100".parse().unwrap(),
            "127.0.0.1:65101".parse().unwrap(),
        );
        let (first_tx, _first_rx) = mpsc::channel(1);
        let first_id = next_udp_session_id();
        UDP_SESSIONS.sessions.insert(
            key,
            UdpSessionEntry {
                id: first_id,
                packet_tx: first_tx,
            },
        );
        let lease = UdpSessionLease::new(&*UDP_SESSIONS, key, first_id);

        let (second_tx, _second_rx) = mpsc::channel(1);
        let second_id = next_udp_session_id();
        UDP_SESSIONS.sessions.insert(
            key,
            UdpSessionEntry {
                id: second_id,
                packet_tx: second_tx,
            },
        );

        drop(lease);
        let preserved = UDP_SESSIONS
            .sessions
            .get(&key)
            .map(|entry| entry.id == second_id)
            .unwrap_or(false);
        UDP_SESSIONS.sessions.remove(&key);
        assert!(preserved, "old lease removed the replacement session");
    }

    #[test]
    fn udp_peer_closed_matches_only_connection_refused() {
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(is_udp_peer_closed(&refused));

        let timed_out = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert!(!is_udp_peer_closed(&timed_out));

        let other = std::io::Error::other("other error");
        assert!(!is_udp_peer_closed(&other));
    }

    #[test]
    fn dispatch_udp_session_routes_existing_and_enforces_limit() {
        let _guard = UDP_SESSION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let src1: SocketAddr = "127.0.0.1:65200".parse().unwrap();
        let dst1: SocketAddr = "127.0.0.1:65201".parse().unwrap();
        let src2: SocketAddr = "127.0.0.1:65202".parse().unwrap();
        let dst2: SocketAddr = "127.0.0.1:65203".parse().unwrap();

        let mut s1 = dispatch_udp_session(src1, dst1, bytes::Bytes::from_static(b"one"), 1)
            .expect("first session should be created");
        assert_eq!(
            s1.packet_rx.try_recv().unwrap(),
            bytes::Bytes::from_static(b"one")
        );

        // Existing session still receives packets even while max_sessions == 1 is reached.
        assert!(dispatch_udp_session(src1, dst1, bytes::Bytes::from_static(b"two"), 1).is_none());
        assert_eq!(
            s1.packet_rx.try_recv().unwrap(),
            bytes::Bytes::from_static(b"two")
        );

        // New session is rejected when active session count >= max_sessions.
        assert!(dispatch_udp_session(src2, dst2, bytes::Bytes::from_static(b"blocked"), 1).is_none());

        drop(s1.lease);
        drop(s1.packet_rx);

        // Replacement session is allowed once the prior lease drops.
        let s2 = dispatch_udp_session(src2, dst2, bytes::Bytes::from_static(b"ok"), 1)
            .expect("second session should be created after first lease drops");
        drop(s2.lease);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bypass_udp_sessions_are_isolated_from_intercepted_limit() {
        let _guard = UDP_SESSION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let b_src: SocketAddr = "127.0.0.1:65300".parse().unwrap();
        let b_dst: SocketAddr = "127.0.0.1:65301".parse().unwrap();
        let i_src: SocketAddr = "127.0.0.1:65302".parse().unwrap();
        let i_dst: SocketAddr = "127.0.0.1:65303".parse().unwrap();

        let b_session = dispatch_bypass_udp_session(b_src, b_dst, bytes::Bytes::from_static(b"b"))
            .expect("bypass session should be created");
        assert!(BYPASS_UDP_SESSIONS
            .sessions
            .contains_key(&UdpSessionKey::new(b_src, b_dst)));

        // Intercepted session pool with max_sessions == 1 must still succeed.
        let i_session = dispatch_udp_session(i_src, i_dst, bytes::Bytes::from_static(b"i"), 1)
            .expect("bypass session must not consume intercepted quota");
        drop(i_session.lease);

        drop(b_session.lease);
        assert!(!BYPASS_UDP_SESSIONS
            .sessions
            .contains_key(&UdpSessionKey::new(b_src, b_dst)));
    }

    #[test]
    fn fullcone_rate_limiter_enforces_rate_and_allows_zero_unlimited() {
        let mut limited = FullconeRateLimiter::new(2);
        assert!(limited.try_acquire());
        assert!(limited.try_acquire());
        assert!(!limited.try_acquire());

        let mut unlimited = FullconeRateLimiter::new(0);
        for _ in 0..10 {
            assert!(unlimited.try_acquire());
        }
    }
}
