use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::ReplyError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::net::{TcpListener, TcpStream};

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::rules::ProxyDgram;
use crate::{
    rules::{InboundProtocol, RouteContext},
    utils::transfer_tcp,
    get_settings,
};

/// SOCKS5 listeners use the default routing table.
async fn bind_listener(listen_addr: &str) -> Result<TcpListener> {
    #[cfg(target_os = "openbsd")]
    {
        use socket2::{Domain, Type};
        use std::net::SocketAddr;

        let addr: SocketAddr = listen_addr
            .parse()
            .context("invalid socks5-listen address")?;
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        if addr.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.bind(&socket2::SockAddr::from(addr))?;
        socket.listen(1024)?;
        let listener: std::net::TcpListener = socket.into();
        Ok(TcpListener::from_std(listener)?)
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        Ok(TcpListener::bind(listen_addr).await?)
    }
}

async fn bind_udp_relay(bind_addr: &str) -> Result<UdpSocket> {
    #[cfg(target_os = "openbsd")]
    {
        use socket2::{Domain, Type};
        use std::net::SocketAddr;

        let addr: SocketAddr = bind_addr.parse().context("invalid UDP relay address")?;
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        if addr.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.bind(&socket2::SockAddr::from(addr))?;
        let socket: std::net::UdpSocket = socket.into();
        Ok(UdpSocket::from_std(socket)?)
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        Ok(UdpSocket::bind(bind_addr).await?)
    }
}

pub async fn socks5_worker() -> Result<()> {

    if get_settings().read().await.socks5_listen.is_none() {
        return Ok(());
    }

    let Some(listen_addr) = get_settings().read().await.socks5_listen.clone() else {
        return Ok(());
    };
    info!("socks5 listen: {}", listen_addr);

    let listener = bind_listener(&listen_addr).await?;

    loop {
        match listener.accept().await {
            Ok((mut _socket, _)) => {
                tokio::spawn(async {
                    socks5_instance(_socket).await.unwrap_or_else(|e| {
                        error!("socks5 error: {:#}", e);
                    });
                });
            }
            Err(e) => warn!("couldn't get client: {:?}", e),
        }
    }
}

async fn socks5_instance(socket: TcpStream) -> Result<()> {
    // The UDP relay must be bound in the same address family the client used
    // to reach us: OpenBSD IPv6 sockets are v6-only by default, so a single
    // [::]:0 listener silently drops datagrams from IPv4 SOCKS clients.
    let local_addr = socket.local_addr()?;
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket).await?
        .read_command().await?;

    let empty_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let empty_sockaddr = std::net::SocketAddr::new(empty_ip, 0);
    match cmd {
        fast_socks5::Socks5Command::TCPConnect => {
            let mut inner = proto.reply_success(empty_sockaddr).await?;
            let src_addr = inner.peer_addr()?;

            let context = match target_addr {
                fast_socks5::util::target_addr::TargetAddr::Ip(sock_addr) => RouteContext {
                    src_addr: src_addr,
                    dst_addr: crate::rules::TargetAddr::Ip(sock_addr.to_owned()),
                    inbound_proto: Some(InboundProtocol::SOCKS5),
                    socket_type: crate::rules::SocketType::STREAM,
                    sniffed_proto: None,
                },
                fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => RouteContext {
                    src_addr: src_addr,
                    dst_addr: crate::rules::TargetAddr::Domain(
                        domain.to_owned(),
                        port.to_owned(),
                        None,
                    ),
                    inbound_proto: Some(InboundProtocol::SOCKS5),
                    socket_type: crate::rules::SocketType::STREAM,
                    sniffed_proto: None,
                },
            };

            transfer_tcp(&mut inner, context.clone()).await.with_context(
                || format!("failed to relay {}", context),
            )?;
        }
        fast_socks5::Socks5Command::TCPBind => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Err(ReplyError::CommandNotSupported.into());
        }
        fast_socks5::Socks5Command::UDPAssociate => {
            // Bind the relay in the client's address family. A dual-stack
            // [::]:0 socket only works where bindv6only=0; OpenBSD defaults
            // to v6-only, which would make IPv4 UDP associates time out.
            let (bind_addr, relay_ip) = if local_addr.is_ipv4() {
                (
                    "0.0.0.0:0",
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                )
            } else {
                (
                    "[::]:0",
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                )
            };
            let peer_sock = bind_udp_relay(bind_addr).await?;

            let udp_port = peer_sock.local_addr()?.port();
            let mut inner = proto
                .reply_success(std::net::SocketAddr::new(relay_ip, udp_port))
                .await?;

            transfer_udp(&mut inner, peer_sock).await?;
        }
    }

    Ok(())
}

async fn handle_udp_request(inbound: &UdpSocket, outbound: &dyn ProxyDgram) -> Result<()> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, _) = inbound.recv_from(&mut buf).await?;
        let (frag, target_addr, data) = fast_socks5::parse_udp_request(&buf[..size]).await?;

        if frag != 0 {
            return Ok(());
        }

        outbound.send_to(&data, crate::utils::to_target_addr(target_addr)).await?;
    }
}

async fn handle_udp_response(inbound: &UdpSocket, outbound: &dyn ProxyDgram) -> Result<()> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, remote_addr) = outbound.recv_from(&mut buf).await?;

        // 1. prepare the response header
        let mut data = match remote_addr {
            crate::rules::TargetAddr::Ip(sockaddr) => {
                fast_socks5::new_udp_header(sockaddr)
            }
            crate::rules::TargetAddr::Domain(domain, port, _) => {
                fast_socks5::new_udp_header((domain.as_str(), port))
            }
        }.context("target address is not a valid domain or ip")?;

        // 2. append the data to the response header
        data.extend_from_slice(&buf[..size]);

        // 3. send the response to the client
        inbound.send(&data).await?;
    }
}

async fn transfer_udp<T: AsyncRead + AsyncWrite + Unpin + Send>(
    parent_sock: &mut T,
    inbound: UdpSocket,
) -> Result<()> {
    // 1. parse the first UDP request from the client
    let mut buf = vec![0u8; 0x10000];
    let (size, client_addr) = inbound.recv_from(&mut buf).await?;

    // 1.1 connect the inbound socket to the client address
    inbound.connect(client_addr).await?;

    let (frag, target_addr, data) = fast_socks5::parse_udp_request(&buf[..size]).await?;
    if frag != 0 {
        return Ok(());
    }

    let context = match target_addr {
        fast_socks5::util::target_addr::TargetAddr::Ip(sock_addr) => RouteContext {
            src_addr: client_addr,
            dst_addr: crate::rules::TargetAddr::Ip(sock_addr.to_owned()),
            inbound_proto: Some(InboundProtocol::SOCKS5),
            socket_type: crate::rules::SocketType::DGRAM,
            sniffed_proto: None,
        },
        fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => RouteContext {
            src_addr: client_addr,
            dst_addr: crate::rules::TargetAddr::Domain(
                domain.to_owned(),
                port.to_owned(),
                None,
            ),
            inbound_proto: Some(InboundProtocol::SOCKS5),
            socket_type: crate::rules::SocketType::DGRAM,
            sniffed_proto: None,
        },
    };

    // 2. Do the routing decision and send the data to the target
    let dgram_sock = get_settings().read().await.routetable.get_dgram_sock(&context).await?;
    dgram_sock.send_to(&data, context.dst_addr).await?;

    // 3. Start the UDP request/response loop
    //
    // RFC 1928 keeps the UDP associate alive through the TCP control
    // connection, so watch it for EOF and tear the session down once the
    // client disconnects. Any branch finishing ends the session and drops
    // the other futures, which also releases the inbound UDP socket.
    tokio::select! {
        res = async {
            let mut buf = [0u8; 0x400];
            loop {
                if parent_sock.read(&mut buf).await? == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
            }
        } => res?,
        res = handle_udp_request(&inbound, dgram_sock.as_ref()) => res?,
        res = handle_udp_response(&inbound, dgram_sock.as_ref()) => res?,
    }
    Ok(())
}
