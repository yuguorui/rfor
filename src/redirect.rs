use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::prelude::AsRawFd,
};

use anyhow::{Context, Result};
use nix::sys::socket::GetSockOpt;

use crate::SETTINGS;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpListener;

pub async fn redirect_worker() -> Result<()> {
    match &SETTINGS.read().await.intercept_mode {
        crate::settings::InterceptMode::REDIRECT {
            local_traffic,
            ports,
            direct_mark,
            proxy_chain,
        } => {
            let listen_addr = match &SETTINGS.read().await.disable_ipv6 {
                true => "0.0.0.0",
                false => "[::]",
            };

            let listener = match &SETTINGS.read().await.redirect_listen {
                Some(addr) => TcpListener::bind(addr).await?,
                None => TcpListener::bind(format!("{}:0", listen_addr)).await?,
            };

            let port = listener
                .local_addr()
                .expect("TCP socket should have local_addr")
                .port();
            println!("redirect listen: {}", listener.local_addr()?);

            if let Err(err) =
                set_nat_iptables(proxy_chain, port, *direct_mark, ports, *local_traffic).await
            {
                cleanup_nat_iptables(proxy_chain).unwrap_or(());
                return Err(err);
            }

            tokio::select! {
                _ = accept_socket_loop(listener) => {},
                Err(err) = crate::utils::receive_signal() => {
                    cleanup_nat_iptables(proxy_chain).unwrap_or(());
                    return Err(err);
                },
            };
        }
        _ => {
            return Ok(());
        }
    }

    Ok(())
}

async fn accept_socket_loop(listener: tokio::net::TcpListener) {
    loop {
        match listener.accept().await {
            Ok((mut _socket, _)) => {
                tokio::spawn(async move {
                    match handle_tcp(&mut _socket).await {
                        Err(e) => {
                            println!("{:#}", e);
                        }
                        _ => {}
                    };
                });
            }
            Err(e) => println!("accept incoming connection failed {:?}", e),
        }
    }
}

async fn handle_tcp(inbound: &mut tokio::net::TcpStream) -> Result<()> {
    use crate::rules::{InboundProtocol, RouteContext, TargetAddr};
    use crate::utils::{is_valid_domain, transfer_tcp};

    let mut buffer = [0u8; 0x800];
    inbound.peek(&mut buffer).await?;

    let domain = crate::sniffer::parse_host(&buffer).filter(|s| is_valid_domain(s.as_str()));

    let origin_addr = match inbound.peer_addr()? {
        SocketAddr::V4(v4) => SocketAddr::V4(v4),
        SocketAddr::V6(v6) => {
            if v6.ip().to_ipv4_mapped().is_none() {
                SocketAddr::V6(v6)
            } else {
                SocketAddr::new(IpAddr::V4(v6.ip().to_ipv4().unwrap()), v6.port())
            }
        }
    };
    let origin_addr = match origin_addr {
        SocketAddr::V4(_) => {
            let addr = nix::sys::socket::sockopt::OriginalDst {}
                .get(inbound.as_raw_fd())
                .context("failed to get original ipv4 addr")?;
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_be())),
                addr.sin_port.to_be(),
            )
        }
        SocketAddr::V6(v6) => {
            let addr = nix::sys::socket::sockopt::Ip6tOriginalDst {}
                .get(inbound.as_raw_fd())
                .context(format!(
                    "failed to get original ipv6 addr with peer addr {}",
                    v6
                ))?;
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                addr.sin6_port.to_be(),
            )
        }
    };

    let target_addr = match domain {
        Some(domain) => TargetAddr::Domain(domain, origin_addr.port(), Some(origin_addr)),
        None => TargetAddr::Ip(origin_addr),
    };

    let rt_context = RouteContext {
        src_sock: inbound.peer_addr()?,
        target_addr,
        inbound_proto: Some(InboundProtocol::REDIRECT),
    };

    transfer_tcp(inbound, rt_context.to_owned())
        .await
        .context(format!("Failed request `{}`", rt_context))?;

    Ok(())
}

fn __setup_nat_iptables(
    ipt: &iptables::IPTables,
    proxy_chain: &str,
    redirect_port: u16,
    direct_mark: u32,
    ports: &[u16],
    local_traffic: bool,
    reserved_ip: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    use itertools::Itertools;

    let table = "nat";

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

    // ignore traffic from rfor
    ipt.append(
        table,
        proxy_chain,
        &format!("-j RETURN -m mark --mark {}", direct_mark),
    )?;

    ipt.append(
        table,
        proxy_chain,
        &format!(
            "-p tcp --match multiport --dports {} -j REDIRECT --to-ports {}",
            ports.into_iter().map(|v| v.to_string()).join(","),
            redirect_port,
        ),
    )?;

    ipt.append(table, "PREROUTING", &format!("-j {}", proxy_chain))?;

    if local_traffic {
        ipt.append(table, "OUTPUT", &format!("-j {}", proxy_chain))?;
    }
    Ok(())
}

async fn set_nat_iptables(
    proxy_chain: &str,
    redirect_port: u16,
    direct_mark: u32,
    ports: &[u16],
    local_traffic: bool,
) -> Result<()> {
    __setup_nat_iptables(
        &iptables::new(false).unwrap(),
        proxy_chain,
        redirect_port,
        direct_mark,
        ports,
        local_traffic,
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

    if !SETTINGS.read().await.disable_ipv6 {
        __setup_nat_iptables(
            &iptables::new(true).unwrap(),
            proxy_chain,
            redirect_port,
            direct_mark,
            ports,
            local_traffic,
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

fn cleanup_nat_iptables(proxy_chain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ipts = [iptables::new(false).unwrap(), iptables::new(true).unwrap()];
    let chains = ["OUTPUT", "PREROUTING"];
    let table = "nat";

    for chain in chains {
        for ipt in &ipts {
            // cleanup proxy chain
            let rules = ipt.list(table, chain)?;

            for rule in rules {
                if rule.contains(&format!("-j {}", proxy_chain)) {
                    ipt.delete_all(
                        table,
                        chain,
                        &rule.trim_start_matches(format!("-A {}", chain).as_str()),
                    )?;
                }
            }
            ipt.flush_chain(table, proxy_chain).unwrap_or(());
            ipt.delete_chain(table, proxy_chain).unwrap_or(());
        }
    }

    Ok(())
}
