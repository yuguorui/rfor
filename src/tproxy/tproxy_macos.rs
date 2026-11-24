//! macOS transparent interception data plane backed by `utun` + `netstack-smoltcp`.

use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener, TcpStream as StackTcpStream, UdpSocket as StackUdpSocket};
use socket2::SockRef;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::get_settings;
use crate::rules::{prepare_socket_bypass_mangle_for_addr, TargetAddr, TIMEOUT};
use crate::stats::UDP_STATS;
use crate::utils::transfer_stream_with_initial_data;

use super::common;
use super::utun_macos;

const UDP_REPLY_CHANNEL_SIZE: usize = 1024;

#[derive(Debug, Clone)]
struct PortFilter {
    ranges: Vec<RangeInclusive<u16>>,
}

impl PortFilter {
    fn parse(ports: &str) -> Self {
        let mut ranges = Vec::new();
        for token in ports.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let sep = if token.contains(':') { ':' } else { '-' };
            if let Some((start, end)) = token.split_once(sep) {
                if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                    if s <= e {
                        ranges.push(s..=e);
                    } else {
                        ranges.push(e..=s);
                    }
                }
            } else if let Ok(port) = token.parse::<u16>() {
                ranges.push(port..=port);
            }
        }
        Self { ranges }
    }

    fn matches(&self, port: u16) -> bool {
        self.ranges.is_empty() || self.ranges.iter().any(|r| r.contains(&port))
    }
}

type UdpReplyMsg = (Vec<u8>, SocketAddr, SocketAddr);

// Retained for parity with tproxy_unix's exported module surface.
#[allow(dead_code)]
pub async fn handle_intercept_sock(_sock: &tokio::net::TcpSocket) -> tokio::io::Result<()> {
    Ok(())
}

#[allow(dead_code)]
pub fn tproxy_bind_src(_sock: SockRef, _src_sock: SocketAddr) -> tokio::io::Result<()> {
    Ok(())
}

pub(crate) use utun_macos::configure_manual_egress;

pub async fn clean_environment() -> Result<()> {
    utun_macos::cleanup().await
}

pub async fn tproxy_worker() -> Result<()> {
    let (
        local_traffic,
        ports,
        utun_name_pref,
        egress_interface,
        proxy_chain,
        bypass_cidrs,
        udp_enable,
        disable_ipv6,
    ) = {
        let settings = get_settings().read().await;
        match &settings.intercept_mode {
            crate::settings::InterceptMode::MANUAL => return Ok(()),
            crate::settings::InterceptMode::UTUN {
                local_traffic,
                ports,
                utun_name,
                egress_interface,
                proxy_chain,
            } => (
                *local_traffic,
                ports.clone(),
                utun_name.clone(),
                egress_interface.clone(),
                proxy_chain.clone(),
                settings.bypass_cidrs.clone(),
                settings.udp_enable,
                settings.disable_ipv6,
            ),
            _ => {
                return Err(anyhow!(
                    "macOS transparent interception requires auto/tproxy/utun mode"
                ))
            }
        }
    };

    let (utun_fd, utun_ifname) = utun_macos::setup(
        local_traffic,
        &ports,
        utun_name_pref.as_deref(),
        egress_interface.as_deref(),
        &proxy_chain,
        disable_ipv6,
        udp_enable,
        &bypass_cidrs,
    )
    .await?;

    info!(
        "utun listen: {} (local_traffic={}, ports='{}', udp_enable={})",
        utun_ifname, local_traffic, ports, udp_enable
    );

    let result = async {
        let port_filter = Arc::new(PortFilter::parse(&ports));
        let utun_async = Arc::new(
            // SAFETY: utun_fd is an OwnedFd that remains open and uniquely owned
            // by the AsyncFd until AsyncFd is dropped.
            unsafe { AsyncFd::register(utun_fd) }
                .map_err(|e| anyhow!("failed to register utun descriptor with tokio: {}", e))?,
        );

        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .stack_buffer_size(4096)
            .tcp_buffer_size(4096)
            .udp_buffer_size(4096)
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(utun_macos::UTUN_MTU as usize)
            .build()
            .context("failed to build netstack-smoltcp stack")?;

        let (mut stack_sink, mut stack_stream) = stack.split();
        let tcp_listener = tcp_listener.ok_or_else(|| anyhow!("netstack TCP listener missing"))?;
        let udp_socket = udp_socket.ok_or_else(|| anyhow!("netstack UDP socket missing"))?;

        let mut tasks = tokio::task::JoinSet::new();

        if let Some(runner) = runner {
            tasks.spawn(async move {
                runner
                    .await
                    .map_err(|e| anyhow!("netstack runner failed: {}", e))
            });
        }

        let utun_reader = Arc::clone(&utun_async);
        tasks.spawn(async move {
            utun_read_loop(utun_reader, &mut stack_sink).await
        });

        let utun_writer = Arc::clone(&utun_async);
        tasks.spawn(async move {
            utun_write_loop(utun_writer, &mut stack_stream).await
        });

        let tcp_ports = Arc::clone(&port_filter);
        tasks.spawn(async move { tcp_accept_loop(tcp_listener, tcp_ports).await });

        let udp_ports = Arc::clone(&port_filter);
        tasks.spawn(async move { udp_loop(udp_socket, udp_ports, udp_enable).await });

        let outcome = tokio::select! {
            res = async {
                loop {
                    match tasks.join_next().await {
                        Some(Ok(Ok(()))) => continue,
                        Some(Ok(Err(err))) => break Err(err),
                        Some(Err(err)) => {
                            if err.is_cancelled() {
                                continue;
                            }
                            break Err(anyhow!("utun worker task panicked: {}", err));
                        }
                        None => break Ok(()),
                    }
                }
            } => res,
            err = crate::utils::receive_signal() => err,
        };

        tasks.shutdown().await;
        // Clean up routes while utun_async keeps the utun interface alive.
        let clean_res = clean_environment().await;
        drop(utun_async);
        clean_res?;
        outcome
    }
    .await;

    clean_environment().await?;
    result
}

async fn utun_read_loop<S>(utun: Arc<AsyncFd<OwnedFd>>, stack_sink: &mut S) -> Result<()>
where
    S: futures::Sink<Vec<u8>, Error = std::io::Error> + Unpin,
{
    const MAX_BATCH: usize = 64;
    let af_inet = nix::libc::AF_INET as u32;
    let af_inet6 = nix::libc::AF_INET6 as u32;
    let mut buf = vec![0u8; 65536];

    loop {
        let mut guard = utun.readable().await?;
        let mut drained = 0usize;
        let mut fed = false;
        while drained < MAX_BATCH {
            match guard.try_io(|inner| {
                let ret = unsafe {
                    nix::libc::read(
                        inner.as_raw_fd(),
                        buf.as_mut_ptr() as *mut nix::libc::c_void,
                        buf.len(),
                    )
                };
                if ret < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    drained += 1;
                    if n <= 4 {
                        continue;
                    }
                    let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    if af != af_inet && af != af_inet6 {
                        continue;
                    }
                    if let Err(err) = stack_sink.feed(buf[4..n].to_vec()).await {
                        return Err(anyhow!("failed to inject utun packet into stack: {}", err));
                    }
                    fed = true;
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) if e.raw_os_error() == Some(nix::libc::ENOBUFS) => {
                    warn!("utun read ENOBUFS, dropping packet");
                    break;
                }
                Ok(Err(e)) => return Err(anyhow!("utun read error: {}", e)),
                Err(_would_block) => break,
            }
        }
        if fed {
            if let Err(err) = stack_sink.flush().await {
                return Err(anyhow!("failed to flush utun packets into stack: {}", err));
            }
        }
        if drained == MAX_BATCH {
            tokio::task::yield_now().await;
        }
    }
}

async fn write_utun_packet(utun: &AsyncFd<OwnedFd>, af_hdr: &[u8; 4], pkt: &[u8]) -> Result<()> {
    loop {
        let mut guard = utun.writable().await?;
        match guard.try_io(|inner| {
            let iov = [
                nix::libc::iovec {
                    iov_base: af_hdr.as_ptr() as *mut nix::libc::c_void,
                    iov_len: af_hdr.len(),
                },
                nix::libc::iovec {
                    iov_base: pkt.as_ptr() as *mut nix::libc::c_void,
                    iov_len: pkt.len(),
                },
            ];
            let ret = unsafe { nix::libc::writev(inner.as_raw_fd(), iov.as_ptr(), 2) };
            if ret < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }) {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) if e.raw_os_error() == Some(nix::libc::ENOBUFS) => {
                tokio::task::yield_now().await;
                return Ok(());
            }
            Ok(Err(e)) => return Err(anyhow!("utun writev error: {}", e)),
            Err(_would_block) => continue,
        }
    }
}

async fn utun_write_loop<S>(utun: Arc<AsyncFd<OwnedFd>>, stack_stream: &mut S) -> Result<()>
where
    S: futures::Stream<Item = std::io::Result<Vec<u8>>> + Unpin,
{
    let af_inet = (nix::libc::AF_INET as u32).to_be_bytes();
    let af_inet6 = (nix::libc::AF_INET6 as u32).to_be_bytes();

    while let Some(item) = stack_stream.next().await {
        let pkt = match item {
            Ok(pkt) => pkt,
            Err(err) => return Err(anyhow!("stack egress stream failed: {}", err)),
        };
        let Some(&first) = pkt.first() else {
            continue;
        };
        let af_hdr = match first >> 4 {
            4 => af_inet,
            6 => af_inet6,
            _ => continue,
        };
        write_utun_packet(&utun, &af_hdr, &pkt).await?;
    }

    Ok(())
}

async fn tcp_accept_loop(mut listener: TcpListener, port_filter: Arc<PortFilter>) -> Result<()> {
    while let Some((mut stream, client_addr, orig_dst)) = listener.next().await {
        let port_filter = Arc::clone(&port_filter);
        tokio::spawn(async move {
            let res = if port_filter.matches(orig_dst.port()) {
                handle_tcp(&mut stream, client_addr, orig_dst).await
            } else {
                bypass_tcp(&mut stream, orig_dst).await
            };
            if let Err(err) = res {
                error!(
                    "TCP connection failed: {} -> {}, error: {:#}",
                    client_addr, orig_dst, err
                );
            }
        });
    }
    Ok(())
}

async fn bypass_tcp(inbound: &mut StackTcpStream, orig_dst: SocketAddr) -> Result<()> {
    let sock = if orig_dst.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    prepare_socket_bypass_mangle_for_addr(sock.as_raw_fd(), Some(orig_dst.ip())).await?;
    let mut outbound =
        tokio::time::timeout(Duration::from_millis(TIMEOUT), sock.connect(orig_dst)).await??;
    let _ = tokio::io::copy_bidirectional(inbound, &mut outbound).await;
    Ok(())
}

async fn handle_tcp(
    inbound: &mut StackTcpStream,
    peer_addr: SocketAddr,
    orig_dst: SocketAddr,
) -> Result<()> {
    let Some(sniffed) = common::sniff_tcp_route(inbound, peer_addr, orig_dst).await? else {
        return Ok(());
    };
    let rt_context = sniffed.context.to_owned();
    transfer_stream_with_initial_data(inbound, sniffed.context, sniffed.initial_data)
        .await
        .context(format!("Failed request `{}`", rt_context))?;

    Ok(())
}

async fn udp_loop(
    udp_socket: StackUdpSocket,
    port_filter: Arc<PortFilter>,
    udp_enable: bool,
) -> Result<()> {
    let (mut udp_rx, mut udp_tx) = udp_socket.split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReplyMsg>(UDP_REPLY_CHANNEL_SIZE);

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = reply_rx.recv().await {
            if let Err(err) = udp_tx.send(msg).await {
                return Err(anyhow!("utun UDP writer failed: {}", err));
            }
        }
        Ok(())
    });

    let max_sessions = get_settings().read().await.udp_max_sessions;

    let read_result: Result<()> = async {
        while let Some((payload, source_sockaddr, target_sockaddr)) = udp_rx.next().await {
            let source_sockaddr = common::unmap_ipv4_mapped(source_sockaddr);
            let target_sockaddr = common::unmap_ipv4_mapped(target_sockaddr);
            let intercept = udp_enable && port_filter.matches(target_sockaddr.port());
            let session = if intercept {
                common::dispatch_udp_session(
                    source_sockaddr,
                    target_sockaddr,
                    bytes::Bytes::from(payload),
                    max_sessions,
                )
            } else {
                common::dispatch_bypass_udp_session(
                    source_sockaddr,
                    target_sockaddr,
                    bytes::Bytes::from(payload),
                )
            };
            let Some(session) = session else {
                continue;
            };

            let reply_tx = reply_tx.clone();
            if intercept {
                info!(
                    "udp relay: create tunnel {:?} <-> {:?} (active sessions: {})",
                    source_sockaddr, target_sockaddr, session.active_sessions
                );
            } else {
                debug!(
                    "udp bypass: create tunnel {:?} <-> {:?} (active bypass sessions: {})",
                    source_sockaddr, target_sockaddr, session.active_sessions
                );
            }

            tokio::spawn(async move {
                let result = if intercept {
                    relay_udp_packet(session.packet_rx, reply_tx, source_sockaddr, target_sockaddr)
                        .await
                } else {
                    relay_udp_bypass(session.packet_rx, reply_tx, source_sockaddr, target_sockaddr)
                        .await
                };
                drop(session.lease);

                if let Err(e) = result {
                    if intercept {
                        error!("Failed to relay udp packet: {}", e);
                    } else {
                        debug!("Bypass udp relay failed: {}", e);
                    }
                }
            });
        }
        Ok(())
    }
    .await;

    drop(reply_tx);
    let writer_res = writer_task
        .await
        .map_err(|e| anyhow!("utun UDP writer task panicked: {}", e))?;
    read_result?;
    writer_res
}

async fn bind_bypass_udp_socket(target_addr: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = if target_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    prepare_socket_bypass_mangle_for_addr(sock.as_raw_fd(), Some(target_addr.ip())).await?;
    Ok(sock)
}

async fn relay_udp_bypass(
    mut packet_rx: mpsc::Receiver<bytes::Bytes>,
    reply_tx: mpsc::Sender<UdpReplyMsg>,
    source_sockaddr: SocketAddr,
    target_sockaddr: SocketAddr,
) -> Result<()> {
    let udp_timeout = get_settings().read().await.udp_timeout;
    let out_sock = bind_bypass_udp_socket(target_sockaddr).await?;
    out_sock.connect(target_sockaddr).await?;

    let timeout_dur = Duration::from_secs(udp_timeout);
    let sleep = tokio::time::sleep(timeout_dur);
    tokio::pin!(sleep);
    let mut buf = vec![0u8; 0x10000];

    loop {
        tokio::select! {
            maybe_pkt = packet_rx.recv() => {
                let Some(pkt) = maybe_pkt else { break };
                sleep.as_mut().set(tokio::time::sleep(timeout_dur));
                if let Err(err) = out_sock.send(&pkt).await {
                    debug!("bypass udp send failed for {}: {}", target_sockaddr, err);
                    break;
                }
            }
            recv_res = out_sock.recv(&mut buf) => {
                match recv_res {
                    Ok(size) if size > 0 => {
                        sleep.as_mut().set(tokio::time::sleep(timeout_dur));
                        if reply_tx
                            .send((buf[..size].to_vec(), target_sockaddr, source_sockaddr))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(err) if common::is_udp_peer_closed(&err) => break,
                    Err(err) => {
                        debug!("bypass udp recv failed for {}: {}", target_sockaddr, err);
                        break;
                    }
                }
            }
            _ = &mut sleep => break,
        }
    }

    Ok(())
}

fn allow_fullcone_peer(
    peers: &mut HashMap<SocketAddr, Instant>,
    rate_limiter: &mut common::FullconeRateLimiter,
    peer: SocketAddr,
    max_peers: usize,
    peer_timeout: Duration,
) -> bool {
    let now = Instant::now();
    if let Some(last) = peers.get_mut(&peer) {
        *last = now;
        return true;
    }

    peers.retain(|_, ts| now.duration_since(*ts) < peer_timeout);
    if !rate_limiter.try_acquire() {
        return false;
    }

    if max_peers > 0 && peers.len() >= max_peers {
        if let Some(oldest) = peers
            .iter()
            .min_by_key(|(_, ts)| *ts)
            .map(|(addr, _)| *addr)
        {
            peers.remove(&oldest);
        }
    }

    peers.insert(peer, now);
    true
}

async fn relay_udp_packet(
    mut packet_rx: mpsc::Receiver<bytes::Bytes>,
    reply_tx: mpsc::Sender<UdpReplyMsg>,
    source_sockaddr: SocketAddr,
    target_sockaddr: SocketAddr,
) -> Result<()> {
    let settings = get_settings().read().await;
    let udp_fullcone = settings.udp_fullcone;
    let udp_timeout = settings.udp_timeout;
    let fullcone_max_sockets = settings.udp_fullcone_max_sockets;
    let fullcone_socket_timeout = settings.udp_fullcone_socket_timeout;
    let fullcone_rate_limit = settings.udp_fullcone_rate_limit;
    let dns_drop_nxdomain = matches!(
        settings.drop_reply.dns,
        crate::settings::DnsDropReply::Nxdomain
    );
    drop(settings);

    let (target_socket, dst_addr, sniffed_proto, buffered_packets) =
        match common::prepare_udp_route(
            &mut packet_rx,
            source_sockaddr,
            target_sockaddr,
            target_sockaddr,
            dns_drop_nxdomain,
        )
        .await?
        {
            common::UdpRouteOutcome::Empty => return Ok(()),
            common::UdpRouteOutcome::Dropped { nxdomain_reply } => {
                if let Some(resp) = nxdomain_reply {
                    let _ = reply_tx
                        .send((resp, target_sockaddr, source_sockaddr))
                        .await;
                }
                return Ok(());
            }
            common::UdpRouteOutcome::Ready {
                target_socket,
                dst_addr,
                sniffed_proto,
                buffered_packets,
            } => (target_socket, dst_addr, sniffed_proto, buffered_packets),
        };

    for packet in &buffered_packets {
        target_socket
            .send_to(packet, TargetAddr::Ip(target_sockaddr))
            .await?;
        UDP_STATS.add_bytes(packet.len() as u64);
    }

    let timeout = common::udp_session_timeout(sniffed_proto, udp_timeout);
    let peer_idle_timeout = Duration::from_secs(fullcone_socket_timeout);
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);

    let mut fullcone_peers = HashMap::<SocketAddr, Instant>::new();
    let mut rate_limiter = common::FullconeRateLimiter::new(fullcone_rate_limit);
    let mut dst_buffer = vec![0u8; 0x10000];

    loop {
        tokio::select! {
            Some(packet) = packet_rx.recv() => {
                sleep.as_mut().set(tokio::time::sleep(timeout));
                match target_socket.send_to(&packet, TargetAddr::Ip(target_sockaddr)).await {
                    Ok(_) => {
                        UDP_STATS.add_bytes(packet.len() as u64);
                        debug!(
                            "udp relay: {:?} -> {} with bytes {}",
                            source_sockaddr, &dst_addr, packet.len()
                        );
                    }
                    Err(e) => {
                        error!("Failed to send udp packet to target: {}", e);
                        break;
                    }
                }
            }
            val = target_socket.recv_from(&mut dst_buffer) => {
                match val {
                    Ok((size, addr)) => {
                        sleep.as_mut().set(tokio::time::sleep(timeout));
                        if size == 0 {
                            continue;
                        }

                        let Some(resp_ip) =
                            common::extract_udp_response_ip(&addr).map(common::unmap_ipv4_mapped)
                        else {
                            continue;
                        };

                        let is_expected_target = common::canonical_ipv6(resp_ip.ip())
                            == common::canonical_ipv6(target_sockaddr.ip())
                            && resp_ip.port() == target_sockaddr.port();

                        let reply_src = if is_expected_target {
                            target_sockaddr
                        } else if udp_fullcone {
                            if resp_ip.is_ipv4() != source_sockaddr.is_ipv4() {
                                continue;
                            }
                            if !allow_fullcone_peer(
                                &mut fullcone_peers,
                                &mut rate_limiter,
                                resp_ip,
                                fullcone_max_sockets,
                                peer_idle_timeout,
                            ) {
                                continue;
                            }
                            resp_ip
                        } else {
                            continue;
                        };

                        UDP_STATS.add_bytes(size as u64);
                        if reply_tx
                            .send((dst_buffer[..size].to_vec(), reply_src, source_sockaddr))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) if common::is_udp_peer_closed(&e) => break,
                    Err(e) => {
                        error!("Failed to receive udp packet from target: {}", e);
                        break;
                    }
                }
            }
            _ = &mut sleep => break,
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn port_filter_parses_empty_singles_and_ranges() {
        let all = PortFilter::parse("");
        assert!(all.matches(22));
        assert!(all.matches(443));

        let filtered = PortFilter::parse("53, 80, 443, 8080:8082");
        assert!(filtered.matches(53));
        assert!(filtered.matches(80));
        assert!(filtered.matches(443));
        assert!(filtered.matches(8080));
        assert!(filtered.matches(8081));
        assert!(filtered.matches(8082));
        assert!(!filtered.matches(22));
        assert!(!filtered.matches(8079));
        assert!(!filtered.matches(8083));
    }

    #[tokio::test]
    async fn netstack_tcp_and_udp_preserve_client_and_destination_endpoints() {
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(1500)
            .build()
            .unwrap();

        let runner_handle = tokio::spawn(runner.unwrap());
        let (mut stack_sink, mut stack_stream) = stack.split();
        let mut tcp_listener = tcp_listener.unwrap();
        let (mut udp_rx, mut udp_tx) = udp_socket.unwrap().split();

        // Inject a raw UDP/IPv4 packet from client 198.19.254.1:51000 to 8.8.8.8:53
        let client_udp: SocketAddr = "198.19.254.1:51000".parse().unwrap();
        let target_udp: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let payload = b"dns-probe";
        let udp_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(198, 19, 254, 1),
            51000,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            payload,
        );
        stack_sink.send(udp_pkt).await.unwrap();

        let (recv_payload, got_client, got_target) =
            tokio::time::timeout(Duration::from_secs(2), udp_rx.next())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(recv_payload, payload);
        assert_eq!(got_client, client_udp);
        assert_eq!(got_target, target_udp);

        // Reply via WriteHalf using (payload, target, client)
        udp_tx
            .send((b"dns-reply".to_vec(), got_target, got_client))
            .await
            .unwrap();
        let raw_reply = tokio::time::timeout(Duration::from_secs(2), stack_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(raw_reply[0] >> 4, 4);
        assert_eq!(&raw_reply[12..16], &[8, 8, 8, 8]);
        assert_eq!(&raw_reply[16..20], &[198, 19, 254, 1]);

        // Test TCP via smoltcp Interface -> Stack -> TcpListener
        let client_tcp: SocketAddr = "198.19.254.1:52000".parse().unwrap();
        let target_tcp: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let syn_pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(198, 19, 254, 1),
            52000,
            Ipv4Addr::new(1, 1, 1, 1),
            80,
            1000,
        );
        stack_sink.send(syn_pkt).await.unwrap();

        let (mut accepted_stream, accepted_client, accepted_dst) =
            tokio::time::timeout(Duration::from_secs(2), tcp_listener.next())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(accepted_client, client_tcp);
        assert_eq!(accepted_dst, target_tcp);

        // Stack emits SYN-ACK back toward client
        let syn_ack = tokio::time::timeout(Duration::from_secs(2), stack_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(syn_ack[0] >> 4, 4);
        assert_eq!(&syn_ack[12..16], &[1, 1, 1, 1]);
        assert_eq!(&syn_ack[16..20], &[198, 19, 254, 1]);
        let server_seq = u32::from_be_bytes([syn_ack[24], syn_ack[25], syn_ack[26], syn_ack[27]]);

        // Send ACK + HTTP payload to complete handshake and test stream read/write
        let ack_data = build_ipv4_tcp_ack_psh(
            Ipv4Addr::new(198, 19, 254, 1),
            52000,
            Ipv4Addr::new(1, 1, 1, 1),
            80,
            1001,
            server_seq + 1,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        stack_sink.send(ack_data).await.unwrap();

        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), accepted_stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("Host: example.com"));

        accepted_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let data_pkt = loop {
            let pkt = tokio::time::timeout(Duration::from_secs(2), stack_stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let ihl = ((pkt[0] & 0x0f) * 4) as usize;
            let doff = ((pkt[ihl + 12] >> 4) * 4) as usize;
            if pkt.len() > ihl + doff {
                break pkt[ihl + doff..].to_vec();
            }
        };
        assert_eq!(&data_pkt, b"HTTP/1.1 200 OK\r\n\r\n");

        drop(accepted_stream);
        runner_handle.abort();
    }

    fn ipv4_checksum(hdr: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in hdr.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in src.octets().chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        for chunk in dst.octets().chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += proto as u32;
        sum += payload.len() as u32;
        for chunk in payload.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
        let total_len = (20 + l4.len()) as u16;
        let mut pkt = Vec::with_capacity(total_len as usize);
        pkt.extend_from_slice(&[
            0x45,
            0x00,
            (total_len >> 8) as u8,
            total_len as u8,
            0x00,
            0x01,
            0x40,
            0x00,
            64,
            proto,
            0x00,
            0x00,
        ]);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        let csum = ipv4_checksum(&pkt[..20]);
        pkt[10] = (csum >> 8) as u8;
        pkt[11] = csum as u8;
        pkt.extend_from_slice(l4);
        pkt
    }

    fn build_ipv4_udp_packet(
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let mut udp = Vec::with_capacity(udp_len as usize);
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(payload);
        let csum = transport_checksum(src, dst, 17, &udp);
        udp[6..8].copy_from_slice(&csum.to_be_bytes());
        build_ipv4_packet(src, dst, 17, &udp)
    }

    fn build_ipv4_tcp_segment(
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::with_capacity(20 + payload.len());
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.push(0x50);
        tcp.push(flags);
        tcp.extend_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(payload);
        let csum = transport_checksum(src, dst, 6, &tcp);
        tcp[16..18].copy_from_slice(&csum.to_be_bytes());
        build_ipv4_packet(src, dst, 6, &tcp)
    }

    fn build_ipv4_tcp_syn(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, seq: u32) -> Vec<u8> {
        build_ipv4_tcp_segment(src, sport, dst, dport, seq, 0, 0x02, &[])
    }

    fn build_ipv4_tcp_ack_psh(
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        build_ipv4_tcp_segment(src, sport, dst, dport, seq, ack, 0x18, payload)
    }
}
