use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::ReplyError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::net::{TcpListener, TcpStream};

use anyhow::{Context, Result};

use crate::rules::ProxyDgram;
use crate::{
    rules::{InboundProtocol, RouteContext},
    utils::transfer_tcp,
    SETTINGS,
};

pub async fn socks5_worker() -> Result<()> {
    if SETTINGS.read().await.socks5_listen.is_none() {
        return Ok(());
    }

    let listen_addr = SETTINGS
        .read()
        .await
        .socks5_listen
        .as_ref()
        .unwrap()
        .to_owned();
    println!("socks5 listen: {}", listen_addr);

    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        match listener.accept().await {
            Ok((mut _socket, _)) => {
                tokio::spawn(async {
                    socks5_instance(_socket).await.unwrap_or_else(|e| {
                        println!("socks5 error: {:#}", e);
                    });
                });
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}

async fn socks5_instance(socket: TcpStream) -> Result<()> {
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
            // Listen with UDP6 socket, so the client can connect to it with either
            // IPv4 or IPv6.
            let peer_sock = UdpSocket::bind("[::]:0").await?;

            let mut inner = proto.reply_success(std::net::SocketAddr::new(
                empty_ip, peer_sock.local_addr().unwrap().port())
            ).await?;

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
        },
    };

    // 2. Do the routing decision and send the data to the target
    let dgram_sock = SETTINGS.read().await.routetable.get_dgram_sock(&context).await?;
    dgram_sock.send_to(&data, context.dst_addr).await?;

    // 3. Start the UDP request/response loop
    match tokio::try_join!(
        async {
            let mut buf = [0u8; 0x0];
            parent_sock.read(&mut buf).await?;
            Ok(())
        },
        handle_udp_request(&inbound, dgram_sock.as_ref()),
        handle_udp_response(&inbound, dgram_sock.as_ref())
    ) {
        Ok(_) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}
