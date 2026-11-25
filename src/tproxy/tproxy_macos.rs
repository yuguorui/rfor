//! macOS transparent interception data plane backed by `utun` + `smoltcp`.

use anyhow::{anyhow, Context, Result};
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
use super::netstack_macos::{self, NetStackConfig, StackTcpStream, TcpListener, UdpPacketMsg};
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

        const UDP_CHANNEL_SIZE: usize = 4096;
        const ICMP_CHANNEL_SIZE: usize = 256;
        let stack_config = NetStackConfig {
            mtu: utun_macos::UTUN_MTU as usize,
            ..Default::default()
        };
        let (tcp_out_tx, tcp_out_rx) =
            mpsc::channel::<Vec<u8>>(stack_config.tcp_out_channel_size());
        let (udp_in_tx, udp_in_rx) = mpsc::channel::<UdpPacketMsg>(UDP_CHANNEL_SIZE);
        let (udp_out_tx, udp_out_rx) = mpsc::channel::<Vec<u8>>(UDP_CHANNEL_SIZE);
        let (icmp_req_tx, icmp_req_rx) = mpsc::channel::<Vec<u8>>(ICMP_CHANNEL_SIZE);
        let (icmp_reply_tx, icmp_reply_rx) = mpsc::channel::<Vec<u8>>(ICMP_CHANNEL_SIZE);

        let (tcp_stacks, tcp_router, tcp_listener) =
            netstack_macos::create_sharded_tcp_stack(stack_config.clone(), tcp_out_tx)?;

        info!(
            "utun TCP stack initialized: shards={}, shard_in_cap={}, shard_egress_cap={}, tcp_out_cap={}, max_sockets={}",
            tcp_router.shard_count(),
            stack_config.shard_in_channel_size(),
            stack_config.shard_max_pending_egress(),
            stack_config.tcp_out_channel_size(),
            stack_config.max_tcp_sockets,
        );

        let (egress_tx, egress_rx) =
            tokio::sync::watch::channel(utun_macos::current_egress_ifindices());

        let mut tasks = tokio::task::JoinSet::new();
        for tcp_stack in tcp_stacks {
            tasks.spawn(async move { tcp_stack.run().await });
        }
        tasks.spawn(async move {
            super::icmp_macos::icmp_worker(icmp_req_rx, icmp_reply_tx, local_traffic, egress_rx)
                .await
        });
        if local_traffic {
            let mon_utun = utun_ifname.clone();
            let mon_egress = egress_interface.clone();
            let mon_bypass = bypass_cidrs.clone();
            tasks.spawn(async move {
                utun_macos::route_monitor_loop(
                    mon_utun,
                    mon_egress,
                    disable_ipv6,
                    mon_bypass,
                    egress_tx,
                )
                .await
            });
        }

        let utun_reader = Arc::clone(&utun_async);
        tasks.spawn(async move {
            utun_read_loop(utun_reader, tcp_router, udp_in_tx, icmp_req_tx).await
        });

        let utun_writer = Arc::clone(&utun_async);
        tasks.spawn(async move {
            utun_write_loop(utun_writer, tcp_out_rx, udp_out_rx, icmp_reply_rx).await
        });

        let tcp_ports = Arc::clone(&port_filter);
        let max_concurrent_tcp = stack_config.max_tcp_sockets;
        tasks.spawn(async move {
            tcp_accept_loop(tcp_listener, tcp_ports, max_concurrent_tcp).await
        });

        let udp_ports = Arc::clone(&port_filter);
        tasks.spawn(async move { udp_loop(udp_in_rx, udp_out_tx, udp_ports, udp_enable).await });

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

struct RateLimitedLog {
    interval: Duration,
    last_log: Option<Instant>,
    suppressed: u64,
}

impl RateLimitedLog {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_log: None,
            suppressed: 0,
        }
    }

    fn warn(&mut self, msg: &str) {
        let now = Instant::now();
        let should_log = match self.last_log {
            None => true,
            Some(prev) => now.saturating_duration_since(prev) >= self.interval,
        };
        if should_log {
            if self.suppressed > 0 {
                warn!("{} ({} suppressed)", msg, self.suppressed);
                self.suppressed = 0;
            } else {
                warn!("{}", msg);
            }
            self.last_log = Some(now);
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
    }
}

struct EnobufsBackoff {
    backoff: Duration,
    log: RateLimitedLog,
}

impl EnobufsBackoff {
    fn new() -> Self {
        Self {
            backoff: Duration::from_millis(2),
            log: RateLimitedLog::new(Duration::from_secs(5)),
        }
    }

    fn reset(&mut self) {
        self.backoff = Duration::from_millis(2);
    }

    async fn on_event(&mut self, label: &str) {
        self.log.warn(label);
        tokio::time::sleep(self.backoff).await;
        self.backoff = (self.backoff * 2).min(Duration::from_millis(50));
    }
}

async fn utun_read_loop(
    utun: Arc<AsyncFd<OwnedFd>>,
    tcp_router: netstack_macos::TcpIngressRouter,
    udp_in_tx: mpsc::Sender<UdpPacketMsg>,
    icmp_req_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    const MAX_BATCH: usize = 64;
    let af_inet = nix::libc::AF_INET as u32;
    let af_inet6 = nix::libc::AF_INET6 as u32;
    let mut buf = vec![0u8; 65536];
    let mut enobufs = EnobufsBackoff::new();
    let mut full_log = RateLimitedLog::new(Duration::from_secs(5));

    loop {
        let mut guard = utun.readable().await?;
        let mut drained = 0usize;
        let mut hit_enobufs = false;
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
                Ok(Ok(0)) => {
                    hit_enobufs = true;
                    break;
                }
                Ok(Ok(n)) => {
                    drained += 1;
                    enobufs.reset();
                    if n <= 4 {
                        continue;
                    }
                    let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    if af != af_inet && af != af_inet6 {
                        continue;
                    }
                    let pkt = &buf[4..n];
                    if super::icmp_macos::is_icmp_packet(pkt) {
                        let _ = icmp_req_tx.try_send(pkt.to_vec());
                        continue;
                    }
                    if netstack_macos::is_udp_packet(pkt) {
                        if let Some(msg) = netstack_macos::parse_udp_packet(pkt) {
                            let _ = udp_in_tx.try_send(msg);
                        }
                        continue;
                    }
                    if netstack_macos::is_tcp_packet(pkt) {
                        match tcp_router.try_dispatch(pkt) {
                            netstack_macos::DispatchOutcome::Sent
                            | netstack_macos::DispatchOutcome::Ignored => {}
                            netstack_macos::DispatchOutcome::Full => {
                                full_log.warn("utun TCP shard queue full, dropping packet");
                            }
                            netstack_macos::DispatchOutcome::Closed => {
                                return Err(anyhow!("TCP stack ingress channel closed"));
                            }
                        }
                    }
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) if e.raw_os_error() == Some(nix::libc::ENOBUFS) => {
                    hit_enobufs = true;
                    break;
                }
                Ok(Err(e)) => return Err(anyhow!("utun read error: {}", e)),
                Err(_would_block) => break,
            }
        }
        drop(guard);
        if hit_enobufs {
            enobufs.on_event("utun read ENOBUFS, backing off").await;
        } else if drained == MAX_BATCH {
            tokio::task::yield_now().await;
        }
    }
}

async fn write_utun_packet(
    utun: &AsyncFd<OwnedFd>,
    af_hdr: &[u8; 4],
    pkt: &[u8],
) -> Result<bool> {
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
            Ok(Ok(_)) => return Ok(true),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) if e.raw_os_error() == Some(nix::libc::ENOBUFS) => return Ok(false),
            Ok(Err(e)) => return Err(anyhow!("utun writev error: {}", e)),
            Err(_would_block) => continue,
        }
    }
}

async fn write_ip_packet(
    utun: &AsyncFd<OwnedFd>,
    af_inet: &[u8; 4],
    af_inet6: &[u8; 4],
    pkt: &[u8],
) -> Result<bool> {
    let Some(&first) = pkt.first() else {
        return Ok(true);
    };
    let af_hdr = match first >> 4 {
        4 => af_inet,
        6 => af_inet6,
        _ => return Ok(true),
    };
    write_utun_packet(utun, af_hdr, pkt).await
}

async fn utun_write_loop(
    utun: Arc<AsyncFd<OwnedFd>>,
    mut tcp_out_rx: mpsc::Receiver<Vec<u8>>,
    mut udp_out_rx: mpsc::Receiver<Vec<u8>>,
    mut icmp_reply_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let af_inet = (nix::libc::AF_INET as u32).to_be_bytes();
    let af_inet6 = (nix::libc::AF_INET6 as u32).to_be_bytes();
    let mut icmp_open = true;
    let mut enobufs = EnobufsBackoff::new();

    loop {
        let wrote = tokio::select! {
            maybe_tcp = tcp_out_rx.recv() => {
                let Some(pkt) = maybe_tcp else { break };
                write_ip_packet(&utun, &af_inet, &af_inet6, &pkt).await?
            }
            maybe_udp = udp_out_rx.recv() => {
                let Some(pkt) = maybe_udp else { break };
                write_ip_packet(&utun, &af_inet, &af_inet6, &pkt).await?
            }
            maybe_icmp = icmp_reply_rx.recv(), if icmp_open => {
                match maybe_icmp {
                    Some(pkt) => write_ip_packet(&utun, &af_inet, &af_inet6, &pkt).await?,
                    None => {
                        icmp_open = false;
                        true
                    }
                }
            }
        };
        if wrote {
            enobufs.reset();
        } else {
            enobufs.on_event("utun write ENOBUFS, backing off").await;
        }
    }

    Ok(())
}

async fn tcp_accept_loop(
    mut listener: TcpListener,
    port_filter: Arc<PortFilter>,
    max_concurrent: usize,
) -> Result<()> {
    let limiter = Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1)));
    let mut overload_log = RateLimitedLog::new(Duration::from_secs(5));
    while let Some((mut stream, client_addr, orig_dst)) = listener.accept().await {
        let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
            stream.abort();
            overload_log.warn(&format!(
                "TCP concurrency limit ({}) reached, resetting {} -> {}",
                max_concurrent, client_addr, orig_dst
            ));
            continue;
        };
        let port_filter = Arc::clone(&port_filter);
        tokio::spawn(async move {
            let _permit = permit;
            let res = if port_filter.matches(orig_dst.port()) {
                handle_tcp(&mut stream, client_addr, orig_dst).await
            } else {
                bypass_tcp(&mut stream, orig_dst).await
            };
            if let Err(err) = res {
                stream.abort();
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
    mut udp_in_rx: mpsc::Receiver<UdpPacketMsg>,
    udp_out_tx: mpsc::Sender<Vec<u8>>,
    port_filter: Arc<PortFilter>,
    udp_enable: bool,
) -> Result<()> {
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReplyMsg>(UDP_REPLY_CHANNEL_SIZE);

    let writer_task = tokio::spawn(async move {
        while let Some((payload, src, dst)) = reply_rx.recv().await {
            if let Some(pkt) = netstack_macos::build_udp_packet(&payload, src, dst) {
                if udp_out_tx.send(pkt).await.is_err() {
                    return Err(anyhow!("utun UDP writer failed: egress channel closed"));
                }
            }
        }
        Ok(())
    });

    let max_sessions = get_settings().read().await.udp_max_sessions;

    let read_result: Result<()> = async {
        while let Some((payload, source_sockaddr, target_sockaddr)) = udp_in_rx.recv().await {
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
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel(64);
        let (tcp_out_tx, mut tcp_out_rx) = mpsc::channel(64);
        let (tcp_stack, mut tcp_listener) =
            netstack_macos::create_tcp_stack(NetStackConfig::default(), tcp_in_rx, tcp_out_tx)
                .unwrap();
        let stack_handle = tokio::spawn(tcp_stack.run());

        // Parse a raw UDP/IPv4 packet from client 198.19.254.1:51000 to 8.8.8.8:53
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
        let (recv_payload, got_client, got_target) =
            netstack_macos::parse_udp_packet(&udp_pkt).unwrap();
        assert_eq!(recv_payload, payload);
        assert_eq!(got_client, client_udp);
        assert_eq!(got_target, target_udp);

        // Encode reply packet using (payload, target, client)
        let raw_reply = netstack_macos::build_udp_packet(b"dns-reply", got_target, got_client)
            .unwrap();
        assert_eq!(raw_reply[0] >> 4, 4);
        assert_eq!(&raw_reply[12..16], &[8, 8, 8, 8]);
        assert_eq!(&raw_reply[16..20], &[198, 19, 254, 1]);

        // Test TCP via smoltcp Interface -> TcpStack -> TcpListener
        let client_tcp: SocketAddr = "198.19.254.1:52000".parse().unwrap();
        let target_tcp: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let syn_pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(198, 19, 254, 1),
            52000,
            Ipv4Addr::new(1, 1, 1, 1),
            80,
            1000,
        );
        tcp_in_tx.send(syn_pkt).await.unwrap();

        let (mut accepted_stream, accepted_client, accepted_dst) =
            tokio::time::timeout(Duration::from_secs(2), tcp_listener.accept())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(accepted_client, client_tcp);
        assert_eq!(accepted_dst, target_tcp);

        // Stack emits SYN-ACK back toward client
        let syn_ack = tokio::time::timeout(Duration::from_secs(2), tcp_out_rx.recv())
            .await
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
        tcp_in_tx.send(ack_data).await.unwrap();

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
            let pkt = tokio::time::timeout(Duration::from_secs(2), tcp_out_rx.recv())
                .await
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
        stack_handle.abort();
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

    fn ipv6_udp_checksum(
        src: std::net::Ipv6Addr,
        dst: std::net::Ipv6Addr,
        udp: &[u8],
    ) -> u16 {
        let mut sum: u32 = 0;
        for chunk in src.octets().chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        for chunk in dst.octets().chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        for chunk in (udp.len() as u32).to_be_bytes().chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += 17u32;
        for chunk in udp.chunks(2) {
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
        let csum = !(sum as u16);
        if csum == 0 {
            0xffff
        } else {
            csum
        }
    }

    fn build_ipv6_udp_packet(
        src: std::net::Ipv6Addr,
        sport: u16,
        dst: std::net::Ipv6Addr,
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
        let csum = ipv6_udp_checksum(src, dst, &udp);
        udp[6..8].copy_from_slice(&csum.to_be_bytes());

        let mut pkt = Vec::with_capacity(40 + udp.len());
        pkt.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (udp_len >> 8) as u8,
            udp_len as u8,
            17,
            64,
        ]);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(&udp);
        pkt
    }

    #[test]
    fn allow_fullcone_peer_tracks_rate_limits_evicts_oldest_and_expires_idle() {
        let p1: SocketAddr = "203.0.113.10:9001".parse().unwrap();
        let p2: SocketAddr = "203.0.113.10:9002".parse().unwrap();
        let p3: SocketAddr = "203.0.113.10:9003".parse().unwrap();

        let mut peers = HashMap::new();
        let mut rate = common::FullconeRateLimiter::new(2);
        assert!(allow_fullcone_peer(&mut peers, &mut rate, p1, 4, Duration::from_secs(30)));
        assert!(allow_fullcone_peer(&mut peers, &mut rate, p2, 4, Duration::from_secs(30)));
        // Refreshing an existing peer must not consume a new-peer rate token.
        assert!(allow_fullcone_peer(&mut peers, &mut rate, p1, 4, Duration::from_secs(30)));
        // A third distinct peer exceeds the 2/sec rate limit.
        assert!(!allow_fullcone_peer(&mut peers, &mut rate, p3, 4, Duration::from_secs(30)));
        assert_eq!(peers.len(), 2);

        // Max peers cap evicts the oldest active peer.
        let mut capped = HashMap::new();
        let mut unlimited = common::FullconeRateLimiter::new(0);
        assert!(allow_fullcone_peer(&mut capped, &mut unlimited, p1, 2, Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(allow_fullcone_peer(&mut capped, &mut unlimited, p2, 2, Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(allow_fullcone_peer(&mut capped, &mut unlimited, p3, 2, Duration::from_secs(30)));
        assert_eq!(capped.len(), 2);
        assert!(!capped.contains_key(&p1));
        assert!(capped.contains_key(&p2));
        assert!(capped.contains_key(&p3));

        // Idle expiry prunes stale entries when a new peer arrives.
        let mut expiring = HashMap::new();
        assert!(allow_fullcone_peer(&mut expiring, &mut unlimited, p1, 4, Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(20));
        assert!(allow_fullcone_peer(&mut expiring, &mut unlimited, p2, 4, Duration::from_millis(10)));
        assert!(!expiring.contains_key(&p1));
        assert!(expiring.contains_key(&p2));
    }

    #[tokio::test]
    async fn netstack_ipv6_udp_preserves_client_and_destination_endpoints() {
        let src_v6: std::net::Ipv6Addr = "fd72:666f:7200::1".parse().unwrap();
        let dst_v6: std::net::Ipv6Addr = "2001:db8:50::1".parse().unwrap();
        let client_v6 = SocketAddr::new(src_v6.into(), 51000);
        let target_v6 = SocketAddr::new(dst_v6.into(), 9001);

        let pkt = build_ipv6_udp_packet(src_v6, 51000, dst_v6, 9001, b"udp6-probe");
        let (recv_payload, got_client, got_target) = netstack_macos::parse_udp_packet(&pkt).unwrap();
        assert_eq!(recv_payload, b"udp6-probe");
        assert_eq!(got_client, client_v6);
        assert_eq!(got_target, target_v6);

        let raw_reply =
            netstack_macos::build_udp_packet(b"udp6-reply", got_target, got_client).unwrap();
        assert_eq!(raw_reply[0] >> 4, 6);
        assert_eq!(raw_reply[6], 17);
        assert_eq!(&raw_reply[8..24], &dst_v6.octets());
        assert_eq!(&raw_reply[24..40], &src_v6.octets());
        assert_eq!(u16::from_be_bytes([raw_reply[40], raw_reply[41]]), 9001);
        assert_eq!(u16::from_be_bytes([raw_reply[42], raw_reply[43]]), 51000);
        assert_eq!(&raw_reply[48..], b"udp6-reply");
    }
}
