use anyhow::{anyhow, Context, Result};
use socket2::{SockAddr, SockRef};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use tracing::{error, info, warn, debug};

use crate::{rules::prepare_socket_bypass_mangle, utils::ToV6SockAddr, get_settings};
use std::{collections::hash_map, mem::MaybeUninit, os::fd::BorrowedFd, sync::Arc, time::Instant};

use dashmap::DashMap;
use once_cell::sync::Lazy;

/// Key for UDP session mapping: (source_addr, target_addr)
type UdpSessionKey = (std::net::SocketAddr, std::net::SocketAddr);

/// UDP session entry containing a channel sender for forwarding packets
struct UdpSessionEntry {
    /// Channel sender for forwarding packets to the session handler
    packet_tx: mpsc::Sender<bytes::Bytes>,
}

/// Channel buffer size for forwarding packets to existing sessions
const UDP_SESSION_CHANNEL_SIZE: usize = 32;

/// Global map to track active UDP sessions with packet forwarding channels
static UDP_SESSIONS: Lazy<DashMap<UdpSessionKey, UdpSessionEntry>> = 
    Lazy::new(|| DashMap::new());

fn setup_iptransparent_opts(sock: &SockRef) -> std::io::Result<()> {
    use nix::sys::socket::sockopt::IpTransparent;
    use nix::sys::socket::{self};
    use std::os::unix::io::AsRawFd;

    // SockRef implements AsRawFd but not AsFd, so we need to wrap with BorrowedFd
    // SAFETY: The fd is valid for the lifetime of sock
    let fd = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    socket::setsockopt(&fd, IpTransparent, &true)?;
    Ok(())
}

fn setup_udpsock_opts(sock: &tokio::net::UdpSocket) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    setup_iptransparent_opts(&SockRef::from(sock))?;

    let optret = match sock.local_addr()?.ip() {
        std::net::IpAddr::V4(_) => unsafe {
            nix::libc::setsockopt(
                sock.as_raw_fd(),
                nix::libc::SOL_IP,
                nix::libc::IP_RECVORIGDSTADDR,
                &1 as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<i32>() as u32,
            )
        },
        std::net::IpAddr::V6(_) => unsafe {
            // set both ipv4 and ipv6 for compatibility
            let r = nix::libc::setsockopt(
                sock.as_raw_fd(),
                nix::libc::SOL_IP,
                nix::libc::IP_RECVORIGDSTADDR,
                &1 as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<i32>() as u32,
            );

            if r != 0 {
                r
            } else {
                nix::libc::setsockopt(
                    sock.as_raw_fd(),
                    nix::libc::SOL_IPV6,
                    nix::libc::IPV6_RECVORIGDSTADDR,
                    &1 as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<i32>() as u32,
                )
            }
        },
    };

    if optret < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to set IP_RECVORIGDSTADDR.",
        )
        .into());
    }
    Ok(())
}

/// Periodically logs the number of active UDP sessions
async fn udp_session_stats_logger() {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    
    loop {
        interval.tick().await;
        let session_count = UDP_SESSIONS.len();
        if session_count > 0 {
            info!("udp stats: active_sessions={}", session_count);
        }
    }
}

pub async fn tproxy_worker() -> Result<()> {
    if get_settings().read().await.tproxy_listen.is_none() {
        return Ok(());
    }

    if let Err(err) = environment_setup().await {
        clean_environment().await.unwrap_or(());
        return Err(err);
    }

    let listen_addr = get_settings().read().await.tproxy_listen.clone().unwrap();
    info!("tproxy listen: {}", listen_addr);

    tokio::select! {
        Err(err) = accept_socket_loop(&listen_addr) => {
            clean_environment().await?;
            return Err(err);
        },
        Err(err) = udp_socket_loop(&listen_addr) => {
            clean_environment().await?;
            return Err(err);
        },
        _ = udp_session_stats_logger() => {
            clean_environment().await?;
            return Ok(());
        },
        Err(err) = crate::utils::receive_signal() => {
            clean_environment().await?;
            return Err(err);
        },
    };
}

async fn accept_socket_loop(listen_addr: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .context("failed to bind tcp listener")?;
    setup_iptransparent_opts(&SockRef::from(&listener)).context("failed to set IP_TRANSPARENT")?;

    loop {
        match listener.accept().await {
            Ok((mut _socket, _)) => {
                tokio::spawn(async move {
                    match handle_tcp(&mut _socket).await {
                        Err(e) => {
                            error!("{:#}", e);
                        }
                        _ => {}
                    };
                });
            }
            Err(e) => warn!("couldn't get client: {:?}", e),
        }
    }
}

fn parse_sockaddr_storage(
    sockaddr_storage: &nix::libc::sockaddr_storage,
) -> std::io::Result<std::net::SocketAddr> {
    unsafe {
        socket2::SockAddr::new(
            *sockaddr_storage,
            std::mem::size_of_val(sockaddr_storage) as _,
        )
    }
    .as_socket()
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to parse sockaddr_storage.",
        )
    })
}

fn parse_cmsg_orig_dst_addr(msghdr: &nix::libc::msghdr) -> std::io::Result<std::net::SocketAddr> {
    let cmsgptr = unsafe { nix::libc::CMSG_FIRSTHDR(msghdr) };
    if cmsgptr.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no control message is valid.",
        ));
    }

    let mut target_sockaddr_option = None;
    loop {
        let cmsg_level = unsafe { *cmsgptr }.cmsg_level;
        let cmsg_type = unsafe { *cmsgptr }.cmsg_type;
        let cmsg_data = unsafe { nix::libc::CMSG_DATA(cmsgptr) } as *const nix::libc::c_uchar;

        if cmsg_level == nix::libc::SOL_IP && cmsg_type == nix::libc::IP_ORIGDSTADDR {
            let sockaddr_storage = cmsg_data as *const nix::libc::sockaddr_storage;
            target_sockaddr_option = Some(
                unsafe {
                    socket2::SockAddr::new(
                        *sockaddr_storage,
                        std::mem::size_of::<nix::libc::sockaddr_in>() as _,
                    )
                }
                .as_socket()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "failed to parse sockaddr_in.")
                })?,
            );
            break;
        }

        if cmsg_level == nix::libc::SOL_IPV6 && cmsg_type == nix::libc::IPV6_ORIGDSTADDR {
            let sockaddr_storage = cmsg_data as *const nix::libc::sockaddr_storage;
            target_sockaddr_option = Some(
                unsafe {
                    socket2::SockAddr::new(
                        *sockaddr_storage,
                        std::mem::size_of::<nix::libc::sockaddr_in6>() as _,
                    )
                }
                .as_socket()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "failed to parse sockaddr_in6.")
                })?,
            );
            break;
        }

        let cmsgptr = unsafe { nix::libc::CMSG_NXTHDR(msghdr, cmsgptr) };
        if cmsgptr.is_null() {
            break;
        }
    }

    target_sockaddr_option.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "no target sockaddr received.")
    })
}

/// recvmsg wrapper for tproxy, which returns the source and target sockaddr of the packet.
fn recvmsg_wrapper(
    fd: i32,
    buffer: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, std::net::SocketAddr)> {
    let mut iovec_buffer = nix::libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut nix::libc::c_void,
        iov_len: buffer.len(),
    };
    let mut control = [0 as u8; 0x200];
    let mut source_storage = MaybeUninit::<nix::libc::sockaddr_storage>::uninit();
    let mut msghdr = unsafe { std::mem::zeroed::<nix::libc::msghdr>() };
    msghdr.msg_name = source_storage.as_mut_ptr() as *mut nix::libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<nix::libc::sockaddr_storage>() as u32;
    msghdr.msg_iov = &mut iovec_buffer;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = control.as_mut_ptr() as *mut nix::libc::c_void;
    msghdr.msg_controllen = control.len() as _;
    msghdr.msg_flags = 0;

    let ret = unsafe { nix::libc::recvmsg(fd, &mut msghdr, 0) };

    if ret > 0 {
        let source_sockaddr =
            parse_sockaddr_storage(&unsafe { source_storage.assume_init() })?.to_ipv6_sockaddr();
        let target_sockaddr = parse_cmsg_orig_dst_addr(&msghdr)?.to_ipv6_sockaddr();

        return Ok((ret as usize, source_sockaddr, target_sockaddr));
    } else {
        return Err(std::io::Error::last_os_error());
    }
}

async fn udp_socket_loop(listen_addr: &str) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;
    use dashmap::mapref::entry::Entry;

    let settings = get_settings().read().await;
    if !settings.udp_enable {
        return Ok(());
    }
    let max_sessions = settings.udp_max_sessions;
    drop(settings);

    let udp_socket = tokio::net::UdpSocket::bind(listen_addr).await?;
    setup_udpsock_opts(&udp_socket)?;

    let r = Arc::new(udp_socket);

    loop {
        let r = r.clone();

        let mut buffer = [0 as u8; 0x10000];
        match r
            .clone()
            .async_io(Interest::READABLE, || {
                recvmsg_wrapper(r.as_raw_fd(), &mut buffer)
            })
            .await
        {
            Ok((size, source_sockaddr, target_sockaddr)) => {
                // Normalize addresses for consistent session key
                let session_key = (
                    source_sockaddr.to_ipv6_sockaddr(),
                    target_sockaddr.to_ipv6_sockaddr(),
                );

                let prefilled_data = bytes::Bytes::copy_from_slice(&buffer[..size]);

                // Check max sessions limit before attempting entry (avoid calling len() inside entry())
                if max_sessions > 0 && UDP_SESSIONS.len() >= max_sessions {
                    warn!(
                        "udp relay: max sessions limit ({}) reached, dropping new session {:?} <-> {:?}",
                        max_sessions, source_sockaddr, target_sockaddr
                    );
                    continue;
                }

                // Use DashMap entry API to atomically check and insert
                match UDP_SESSIONS.entry(session_key) {
                    Entry::Occupied(entry) => {
                        // Session already exists, forward packet through channel
                        let session = entry.get();
                        match session.packet_tx.try_send(prefilled_data) {
                            Ok(_) => {
                                debug!(
                                    "udp relay: forwarded packet to existing session {:?} <-> {:?}, {} bytes",
                                    source_sockaddr, target_sockaddr, size
                                );
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!(
                                    "udp relay: channel full for session {:?} <-> {:?}, packet dropped",
                                    source_sockaddr, target_sockaddr
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                // Session is closing, remove stale entry and let next packet create new session
                                drop(entry);
                                UDP_SESSIONS.remove(&session_key);
                                debug!(
                                    "udp relay: removed stale session {:?} <-> {:?}",
                                    source_sockaddr, target_sockaddr
                                );
                            }
                        }
                        continue;
                    }
                    Entry::Vacant(entry) => {
                        // Create new session with channel
                        let (tx, rx) = mpsc::channel(UDP_SESSION_CHANNEL_SIZE);

                        // Use try_send since channel should be empty (freshly created)
                        if let Err(e) = tx.try_send(prefilled_data) {
                            error!("Failed to send init packet to new session: {}", e);
                            continue;
                        }

                        entry.insert(UdpSessionEntry {
                            packet_tx: tx,
                        });

                        info!(
                            "udp relay: create tunnel {:?} <-> {:?} (active sessions: {})",
                            source_sockaddr, target_sockaddr, UDP_SESSIONS.len()
                        );

                        tokio::spawn(async move {
                            let result = relay_udp_packet(
                                rx,
                                source_sockaddr,
                                target_sockaddr,
                            ).await;

                            // Always remove the session when done (DashMap remove is lock-free)
                            UDP_SESSIONS.remove(&(
                                source_sockaddr.to_ipv6_sockaddr(),
                                target_sockaddr.to_ipv6_sockaddr(),
                            ));

                            if let Err(e) = result {
                                error!("Failed to relay udp packet: {}", e);
                            }
                        });
                    }
                }
            }
            Err(e) => {
                return Err(e.into());
            }
        };
    }
}

async fn udp_socket_bind_to_any_with_flag(
    bind_sockaddr: std::net::SocketAddr,
    disable_ipv6: bool,
) -> Result<tokio::net::UdpSocket> {
    use nix::libc;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use tokio::net::UdpSocket;

    let bind_sockaddr = if disable_ipv6 {
        bind_sockaddr
    } else {
        bind_sockaddr.to_ipv6_sockaddr()
    };

    let fd;
    unsafe {
        fd = libc::socket(if disable_ipv6 {libc::AF_INET} else {libc::AF_INET6},
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return Err(anyhow!(
                "failed to create socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &1 as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        );
        if ret < 0 {
            return Err(anyhow!(
                "failed to set IP_TRANSPARENT: {}",
                std::io::Error::last_os_error()
            ));
        }

        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1 as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        );
        if ret < 0 {
            return Err(anyhow!(
                "failed to set SO_REUSEADDR: {}",
                std::io::Error::last_os_error()
            ));
        }

        let addr = socket2::SockAddr::from(bind_sockaddr);
        let addr_stor = addr.as_storage();
        let ret = libc::bind(
            fd,
            &addr_stor as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_storage>() as u32,
        );
        if ret < 0 {
            return Err(anyhow!(
                "failed to bind to target address {}: {}",
                bind_sockaddr,
                std::io::Error::last_os_error()
            ));
        }
    }
    let source_socket =
        unsafe { UdpSocket::from_std(std::net::UdpSocket::from(OwnedFd::from_raw_fd(fd))) }?;
    prepare_socket_bypass_mangle(source_socket.as_raw_fd()).await?;
    return Ok(source_socket);
}

async fn relay_udp_packet(
    mut packet_rx: mpsc::Receiver<bytes::Bytes>,
    source_sockaddr: std::net::SocketAddr,
    target_sockaddr: std::net::SocketAddr,
) -> Result<()> {
    let settings = get_settings().read().await;
    let udp_fullcone = settings.udp_fullcone;
    let udp_timeout = settings.udp_timeout;
    let fullcone_max_sockets = settings.udp_fullcone_max_sockets;
    let fullcone_socket_timeout = settings.udp_fullcone_socket_timeout;
    let fullcone_rate_limit = settings.udp_fullcone_rate_limit;
    let disable_ipv6 = settings.disable_ipv6;
    drop(settings);

    // Wait for the first packet to determine the destination address (for domain sniffing)
    let init_packet = match packet_rx.recv().await {
        Some(packet) => packet,
        None => {
            return Ok(());
        }
    };

    let host = crate::sniffer::parse_host(&init_packet);
    let dst_addr = match host {
        None => crate::rules::TargetAddr::Ip(target_sockaddr),
        Some(host) => {
            crate::rules::TargetAddr::Domain(host, target_sockaddr.port(), Some(target_sockaddr))
        }
    };

    let target_socket = get_settings()
        .read()
        .await
        .routetable
        .get_dgram_sock(&crate::rules::RouteContext {
            src_addr: source_sockaddr,
            dst_addr: dst_addr.clone(),
            inbound_proto: Some(crate::rules::InboundProtocol::TPROXY),
            socket_type: crate::rules::SocketType::DGRAM,
        })
        .await?;

    // Prepare the intermediate socket which is connected to the source, which should bind to the target address,
    // and pretend to be the target.
    let source_socket = udp_socket_bind_to_any_with_flag(target_sockaddr, disable_ipv6).await?;
    source_socket.connect(source_sockaddr).await?;

    // Send the first packet
    target_socket
        .send_to(&init_packet, crate::rules::TargetAddr::Ip(target_sockaddr))
        .await?;

    // FullconeSocketEntry: tracks socket with its last activity time for LRU eviction
    struct FullconeSocketEntry {
        socket: UdpSocket,
        last_active: Instant,
    }

    // Rate limiter for new fullcone socket creation
    struct RateLimiter {
        tokens: u32,
        last_refill: Instant,
        max_tokens: u32,
    }

    impl RateLimiter {
        fn new(rate: u32) -> Self {
            Self {
                tokens: rate,
                last_refill: Instant::now(),
                max_tokens: rate,
            }
        }

        fn try_acquire(&mut self) -> bool {
            if self.max_tokens == 0 {
                return true; // Rate limiting disabled
            }

            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill);

            // Refill tokens based on elapsed time (1 token per 1/rate seconds)
            if elapsed.as_secs() >= 1 {
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

    let mut socket_sets = hash_map::HashMap::<std::net::SocketAddr, FullconeSocketEntry>::new();
    let mut rate_limiter = RateLimiter::new(fullcone_rate_limit);

    let timeout = std::time::Duration::from_secs(udp_timeout);
    let socket_idle_timeout = std::time::Duration::from_secs(fullcone_socket_timeout);
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);

    // Cleanup interval for stale fullcone sockets (every 10 seconds)
    let cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    tokio::pin!(cleanup_interval);

    const BUFFER_SIZE: usize = 0x10000;
    let mut dst_buffer = [0 as u8; BUFFER_SIZE];
    let mut src_buffer = [0 as u8; BUFFER_SIZE];
    loop {
        tokio::select! {
            // Handle packets forwarded from other tasks via channel
            Some(packet) = packet_rx.recv() => {
                sleep.as_mut().set(tokio::time::sleep(timeout));
                match target_socket.send_to(&packet, crate::rules::TargetAddr::Ip(target_sockaddr)).await {
                    Ok(_) => {
                        debug!("udp relay (forwarded): {:?} -> {} with bytes {}",
                               source_sockaddr, &dst_addr, packet.len());
                    }
                    Err(e) => {
                        error!("Failed to send forwarded udp packet to target: {}", e);
                    }
                }
            },
            data = source_socket.recv(&mut src_buffer) => {
                match data {
                    Ok(size) => {
                        sleep.as_mut().set(tokio::time::sleep(timeout));
                        match target_socket.send_to(&src_buffer[..size], crate::rules::TargetAddr::Ip(target_sockaddr)).await {
                            Ok(_) => {
                                debug!("udp relay: {:?} -> {} with bytes {}", source_sockaddr, &dst_addr, size);
                            }
                            Err(e) => {
                                error!("Failed to send udp packet to target: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to receive udp packet from source: {}", e);
                        break;
                    }
                }
            },
            val = target_socket.recv_from(&mut dst_buffer) => {
                match val {
                    Ok((size, addr)) => {
                        sleep.as_mut().set(tokio::time::sleep(timeout));

                        // Extract the actual IP address from the response
                        let response_addr = match &addr {
                            crate::rules::TargetAddr::Ip(ip) => Some(*ip),
                            crate::rules::TargetAddr::Domain(_, _, Some(ip)) => Some(*ip),
                            crate::rules::TargetAddr::Domain(domain, port, None) => {
                                // Domain without resolved IP - this typically comes from SOCKS5 proxy
                                // responses. Full-cone NAT requires IP addresses for proper mapping,
                                // so we cannot reliably handle this case.
                                // 
                                // Note: We intentionally avoid DNS resolution here because:
                                // 1. DNS results are unstable (load balancing, CDN, etc.)
                                // 2. The resolved IP may differ from the actual source
                                // 3. It would add latency and potential failure points
                                //
                                // If you need full-cone support through a proxy, ensure the proxy
                                // returns IP addresses instead of domain names.
                                warn!(
                                    "udp relay (fullcone): received response from domain {}:{} without resolved IP, \
                                     full-cone NAT requires IP addresses. ",
                                    domain, port
                                );
                                None
                            }
                        };

                        let r = match response_addr {
                            Some(resp_ip) => {
                                let is_expected_target = resp_ip.to_ipv6_sockaddr() == target_sockaddr.to_ipv6_sockaddr();

                                if is_expected_target {
                                    source_socket.send(&dst_buffer[..size]).await
                                } else if udp_fullcone {
                                    // Full-cone NAT: accept packets from non-original addresses

                                    match socket_sets.get_mut(&resp_ip) {
                                        Some(entry) => {
                                            // Update last active time
                                            entry.last_active = Instant::now();
                                            entry.socket.send(&dst_buffer[..size]).await
                                        }
                                        None => {
                                            // Rate limit check for new socket creation
                                            if !rate_limiter.try_acquire() {
                                                Ok(0)
                                            } else {
                                                    // Check if we've reached the maximum number of sockets
                                                    if fullcone_max_sockets > 0 && socket_sets.len() >= fullcone_max_sockets {
                                                        // Evict the least recently used socket
                                                        if let Some(oldest_addr) = socket_sets
                                                            .iter()
                                                            .min_by_key(|(_, entry)| entry.last_active)
                                                            .map(|(addr, _)| *addr)
                                                        {
                                                            socket_sets.remove(&oldest_addr);
                                                        }
                                                    }

                                                // Create new socket with graceful error handling
                                                match udp_socket_bind_to_any_with_flag(resp_ip, disable_ipv6).await {
                                                    Ok(sock) => {
                                                        match sock.connect(source_sockaddr).await {
                                                            Ok(_) => {
                                                                let ret = sock.send(&dst_buffer[..size]).await;
                                                                socket_sets.insert(resp_ip, FullconeSocketEntry {
                                                                    socket: sock,
                                                                    last_active: Instant::now(),
                                                                });
                                                                ret
                                                            }
                                                            Err(e) => {
                                                                warn!("Failed to connect fullcone socket to source {}: {}", source_sockaddr, e);
                                                                Ok(0)
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to create fullcone socket for {}: {}", resp_ip, e);
                                                        Ok(0) // Don't break the session, just skip this packet
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    Ok(0 as usize)
                                }
                            }
                            None => {
                                Ok(0 as usize)
                            }
                        };

                        match r {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Failed to send back udp packet to source: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to receive udp packet from target: {}", e);
                        break;
                    }
                }
            },
            _ = cleanup_interval.tick() => {
                // Cleanup stale fullcone sockets based on per-socket timeout
                let now = Instant::now();
                socket_sets.retain(|_addr, entry| {
                    now.duration_since(entry.last_active) < socket_idle_timeout
                });
            },
            _ = &mut sleep => {
                break;
            }
        }
    }

    Ok(())
}

pub fn tproxy_bind_src(sock: SockRef, src_sock: std::net::SocketAddr) -> tokio::io::Result<()> {
    setup_iptransparent_opts(&sock)?;
    match sock.bind(&SockAddr::from(src_sock)) {
        Ok(_) => {}
        Err(err) => match err.kind() {
            // In this branch, we are processing the local traffic.
            std::io::ErrorKind::AddrInUse => {}
            _ => return Err(err),
        },
    };
    Ok(())
}

async fn handle_tcp(inbound: &mut tokio::net::TcpStream) -> Result<()> {
    use crate::rules::{InboundProtocol, RouteContext, TargetAddr};
    use crate::utils::{is_valid_domain, transfer_tcp};

    let mut buffer = [0u8; 0x800];
    inbound.peek(&mut buffer).await?;

    let domain = crate::sniffer::parse_host(&buffer).filter(|s| is_valid_domain(s.as_str()));

    let target_addr = match domain {
        Some(domain) => TargetAddr::Domain(
            domain,
            inbound.local_addr()?.port(),
            Some(inbound.local_addr()?),
        ),
        None => TargetAddr::Ip(inbound.local_addr()?),
    };

    let rt_context = RouteContext {
        src_addr: inbound.peer_addr()?,
        dst_addr: target_addr,
        inbound_proto: Some(InboundProtocol::TPROXY),
        socket_type: crate::rules::SocketType::STREAM,
    };

    transfer_tcp(inbound, rt_context.to_owned())
        .await
        .context(format!("Failed request `{}`", rt_context))?;

    Ok(())
}

fn cleanup_iptables(proxy_chain: &str, mark_chain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ipts = [
        iptables::new(false).expect("command iptables not found"),
        iptables::new(true).expect("command ip6tables not found"),
    ];

    for ipt in ipts {
        // cleanup proxy chain
        let rules = ipt.list("mangle", "PREROUTING")?;

        for rule in rules {
            if rule.contains(&format!("-j {}", proxy_chain)) {
                ipt.delete_all(
                    "mangle",
                    "PREROUTING",
                    &rule.trim_start_matches("-A PREROUTING"),
                )?;
            }
        }
        ipt.flush_chain("mangle", proxy_chain).unwrap_or(());
        ipt.delete_chain("mangle", proxy_chain).unwrap_or(());

        // cleanup output mark chain
        let rules = ipt.list("mangle", "OUTPUT")?;

        for rule in rules {
            if rule.contains(&format!("-j {}", mark_chain)) {
                ipt.delete_all("mangle", "OUTPUT", &rule.trim_start_matches("-A OUTPUT"))?;
            }
        }
        ipt.flush_chain("mangle", mark_chain).unwrap_or(());
        ipt.delete_chain("mangle", mark_chain).unwrap_or(());
    }

    Ok(())
}

fn __setup_iptables(
    ipt: &iptables::IPTables,
    proxy_chain: &str,
    mark_chain: &str,
    tproxy_port: u16,
    xmark: u32,
    direct_mark: u32,
    ports: &str,
    local_traffic: bool,
    udp_enable: bool,
    reserved_ip: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {

    let table = "mangle";
    ipt.new_chain(table, proxy_chain)?;
    for ip in reserved_ip {
        ipt.append(table, proxy_chain, &format!("-d {} -j RETURN", ip))?;
    }

    // skip traffic access local addr
    ipt.append(
        table,
        proxy_chain,
        &format!("-m addrtype --dst-type LOCAL -j RETURN"),
    )?;

    // skip local traffic with direct_mark
    ipt.append(
        table,
        proxy_chain,
        &format!("-j RETURN -m mark --mark {}", direct_mark),
    )?;

    ipt.append(
        table,
        proxy_chain,
        &format!(
            "-p tcp --match multiport --dports {} -j TPROXY --tproxy-mark {} --on-port {}",
            ports,
            xmark,
            tproxy_port,
        ),
    )?;

    if udp_enable {
        ipt.append(
            table,
            proxy_chain,
            &format!(
                "-p udp --match multiport --dports {} -j TPROXY --tproxy-mark {} --on-port {}",
                ports,
                xmark,
                tproxy_port,
            ),
        )?;
    }

    ipt.append(
        table,
        proxy_chain,
        &format!(
            "-p tcp --match multiport --sports {} -j MARK --set-mark {}",
            ports,
            xmark,
        ),
    )?;

    ipt.append(table, "PREROUTING", &format!("-j {}", proxy_chain))?;

    if local_traffic {
        ipt.new_chain(table, mark_chain)?;
        for ip in reserved_ip {
            ipt.append(table, mark_chain, &format!("-d {} -j RETURN", ip))?;
        }

        // skip traffic access local addr
        ipt.append(
            table,
            mark_chain,
            &format!("-m addrtype --dst-type LOCAL -j RETURN"),
        )?;

        // ignore traffic from rfor
        ipt.append(
            table,
            mark_chain,
            &format!("-j RETURN -m mark --mark {}", direct_mark),
        )?;

        ipt.append(
            table,
            mark_chain,
            &format!(
                "-p tcp --match multiport --dports {} -j MARK --set-mark {}",
                ports,
                xmark,
            ),
        )?;

        if udp_enable {
            ipt.append(
                table,
                mark_chain,
                &format!(
                    "-p udp --match multiport --dports {} -j MARK --set-mark {}",
                    ports,
                    xmark,
                ),
            )?;
        }

        ipt.append(table, "OUTPUT", &format!("-j {}", mark_chain))?;
    }
    Ok(())
}

async fn set_iptables(
    proxy_chain: &str,
    mark_chain: &str,
    tproxy_port: u16,
    xmark: u32,
    direct_mark: u32,
    ports: &str,
    local_traffic: bool,
) -> Result<()> {
    __setup_iptables(
        &iptables::new(false).unwrap(),
        proxy_chain,
        mark_chain,
        tproxy_port,
        xmark,
        direct_mark,
        ports,
        local_traffic,
        get_settings().read().await.udp_enable,
        &[
            "0.0.0.0/8",
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "255.255.255.255/32",
        ],
    )
    .map_err(|e| {
        tokio::io::Error::new(
            tokio::io::ErrorKind::Other,
            format!("failed adding ipv4 iptable rules, {}.", e.to_string()),
        )
    })?;

    if !get_settings().read().await.disable_ipv6 {
        __setup_iptables(
            &iptables::new(true).unwrap(),
            proxy_chain,
            mark_chain,
            tproxy_port,
            xmark,
            direct_mark,
            ports,
            local_traffic,
            get_settings().read().await.udp_enable,
            &[
                "::1/128",
                "100::/64",
                "2002::/16",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8",
                "::ffff:0:0/96",
                "::ffff:0:0:0/96",
            ],
        )
        .map_err(|e| {
            tokio::io::Error::new(
                tokio::io::ErrorKind::Other,
                format!("failed adding ipv6 iptable rules, {}.", e.to_string()),
            )
        })?;
    }
    Ok(())
}

async fn __cleanup_ip_rule(
    handle: &rtnetlink::Handle,
    ip_version: rtnetlink::IpVersion,
    route_table_index: u8,
    _fwmark: u32,
) -> Result<()> {
    use futures::TryStreamExt;

    // ip rule del
    let mut rule_msg_stream = handle.rule().get(ip_version.to_owned()).execute();
    loop {
        if let Some(r) = rule_msg_stream.try_next().await? {
            if r.header.table == route_table_index {
                handle.rule().del(r).execute().await?;
            }
            continue;
        }
        break;
    }

    // ip route del
    let mut rule_msg_stream = handle.route().get(ip_version.to_owned()).execute();
    loop {
        if let Some(r) = rule_msg_stream.try_next().await? {
            if r.header.table == route_table_index {
                handle.route().del(r).execute().await?;
            }
            continue;
        }
        break;
    }
    Ok(())
}

async fn cleanup_ip_rule(route_table_index: u8, fwmark: u32) -> Result<()> {
    use rtnetlink::new_connection;

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    __cleanup_ip_rule(&handle, rtnetlink::IpVersion::V4, route_table_index, fwmark)
        .await
        .context("Failed to cleanup IPv4 route rules.")?;
    __cleanup_ip_rule(&handle, rtnetlink::IpVersion::V6, route_table_index, fwmark)
        .await
        .context("Failed to cleanup IPv6 route rules.")?;

    Ok(())
}

async fn get_link_by_name(
    handle: &rtnetlink::Handle,
    name: String,
) -> Result<Option<netlink_packet_route::link::LinkMessage>, rtnetlink::Error> {
    use futures::TryStreamExt;

    let mut links = handle.link().get().match_name(name.clone()).execute();
    if let Some(msg) = links.try_next().await? {
        return Ok(Some(msg));
    } else {
        return Ok(None);
    }
}

async fn set_ip_rule(route_table_index: u8, fwmark: u32) -> Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use netlink_packet_route::rule::RuleAttribute;
    use netlink_packet_route::route::{RouteType, RouteScope};

    use rtnetlink::new_connection;

    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // ip rule add
    let mut rule = handle
        .rule()
        .add()
        .v4()
        .table_id(route_table_index.into())
        .action(netlink_packet_route::rule::RuleAction::ToTable);
    rule.message_mut().attributes.push(RuleAttribute::FwMark(fwmark));
    rule.execute().await?;

    if !get_settings().read().await.disable_ipv6 {
        let mut rule = handle
            .rule()
            .add()
            .v6()
            .table_id(route_table_index.into())
            .action(netlink_packet_route::rule::RuleAction::ToTable);
        rule.message_mut().attributes.push(RuleAttribute::FwMark(fwmark));
        rule.execute().await?;
    }

    // ip route add
    // Scope host for local routes, see also /etc/iproute2/rt_scopes
    let lo_link_index = get_link_by_name(&handle, "lo".to_owned())
        .await?
        .unwrap()
        .header
        .index;

    // Add default IPv4 route.
    let mut route = handle
        .route()
        .add()
        .v4()
        .destination_prefix(Ipv4Addr::new(0, 0, 0, 0), 0)
        .output_interface(lo_link_index)
        .table_id(route_table_index.into())
        .scope(RouteScope::Host);
    route.message_mut().header.kind = RouteType::Local;
    route.execute().await?;

    if !get_settings().read().await.disable_ipv6 {
        // Add default IPv6 route.
        let mut route = handle
            .route()
            .add()
            .v6()
            .destination_prefix(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)
            .output_interface(lo_link_index)
            .table_id(route_table_index.into())
            .scope(RouteScope::Host);
        route.message_mut().header.kind = RouteType::Local;
        route.execute().await?;
    }

    Ok(())
}

async fn environment_setup() -> Result<()> {
    use std::net::SocketAddr;

    let settings = get_settings().read().await;
    match &settings.intercept_mode {
        crate::settings::InterceptMode::MANUAL => return Ok(()),
        crate::settings::InterceptMode::TPROXY {
            local_traffic,
            ports,
            proxy_mark: tproxy_mark,
            direct_mark,
            proxy_chain,
            rule_table_index,
            mark_chain,
        } => {
            if crate::utils::geteuid() != 0 {
                return Err(anyhow!("Must be root to set the iptables."));
            }

            match cleanup_iptables(proxy_chain, mark_chain) {
                Ok(()) => {}
                Err(err) => {
                    return Err(anyhow!("Failed on cleaning up iptables rules: {}", err));
                }
            };

            match set_iptables(
                proxy_chain,
                mark_chain,
                settings
                    .tproxy_listen
                    .as_ref()
                    .unwrap()
                    .parse::<SocketAddr>()
                    .unwrap()
                    .port(),
                *tproxy_mark,
                *direct_mark,
                ports,
                *local_traffic,
            )
            .await
            {
                Ok(_) => {}
                Err(err) => {
                    return Err(anyhow!("Failed on setting up iptables rules: {}", err));
                }
            };

            cleanup_ip_rule(*rule_table_index, *tproxy_mark).await?;
            set_ip_rule(*rule_table_index, *tproxy_mark).await?;
            return Ok(());
        }
        crate::settings::InterceptMode::REDIRECT { .. } => return Ok(()),
    }
}

async fn clean_environment() -> Result<()> {
    let settings = get_settings().read().await;
    match &settings.intercept_mode {
        crate::settings::InterceptMode::MANUAL => return Ok(()),
        crate::settings::InterceptMode::TPROXY {
            local_traffic: _,
            ports: _,
            proxy_mark: tproxy_mark,
            direct_mark: _,
            proxy_chain: table_name,
            rule_table_index,
            mark_chain,
        } => {
            let proxy_chain = table_name.to_owned();
            let mark_chain = mark_chain.to_owned();
            let tproxy_mark = *tproxy_mark;
            let rule_table_index = *rule_table_index;

            cleanup_iptables(&proxy_chain, &mark_chain).unwrap();
            cleanup_ip_rule(rule_table_index, tproxy_mark).await?;

            Ok(())
        }
        crate::settings::InterceptMode::REDIRECT { .. } => return Ok(()),
    }
}
