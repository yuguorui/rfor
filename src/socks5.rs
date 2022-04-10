use std::sync::Arc;

use fast_socks5::server::Socks5Socket;
use fast_socks5::SocksError;
use futures::FutureExt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use anyhow::{Result, Context};

use crate::{
    rules::{InboundProtocol, RouteContext, TargetAddr},
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
                    let mut config = fast_socks5::server::Config::default();
                    config.set_dns_resolve(false);
                    config.set_connect_callback(Box::new(|addr, t, stream| {
                        socks_executor(addr, t, stream).boxed()
                    }));
                    let socks5_socket = Socks5Socket::new(_socket, Arc::new(config));

                    match socks5_socket.upgrade_to_socks5().await {
                        Ok(_) => {}
                        Err(e) => println!("socks5 error: {}", e),
                    }
                });
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}

async fn socks_executor(
    target_addr: Option<fast_socks5::util::target_addr::TargetAddr>,
    _timeout: u64,
    reply_sock: &mut TcpStream,
) -> Result<(), SocksError> {
    let target_addr = target_addr.context("target_addr empty")?;
    let context = match target_addr {
        fast_socks5::util::target_addr::TargetAddr::Ip(sock_addr) => RouteContext {
            src_sock: reply_sock.peer_addr()?,
            target_addr: TargetAddr::Ip(sock_addr),
            inbound_proto: Some(InboundProtocol::SOCKS5),
        },
        fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => RouteContext {
            src_sock: reply_sock.peer_addr()?,
            target_addr: TargetAddr::Domain(domain.to_owned(), port, None),
            inbound_proto: Some(InboundProtocol::SOCKS5),
        },
    };

    // TODO: convert this to the real address
    reply_sock
        .write(&[
            fast_socks5::consts::SOCKS5_VERSION,
            fast_socks5::consts::SOCKS5_REPLY_SUCCEEDED,
            0x00, // reserved
            1,    // address type (ipv4, v6, domain)
            127,  // ip
            0,
            0,
            1,
            0, // port
            0,
        ])
        .await?;

    reply_sock.flush().await?;

    transfer_tcp(reply_sock, context).await?;
    Ok(())
}
