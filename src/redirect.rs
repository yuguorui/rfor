// Redirect module - Linux-only functionality using iptables NAT REDIRECT
// On non-Linux platforms, this module provides a no-op implementation

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use anyhow::{Context, Result};
    use nix::sys::socket::GetSockOpt;
    use tracing::{error, info, warn};

    use crate::{get_settings, utils::rfor_bind_addr};
    use std::net::{IpAddr, SocketAddr};
    use tokio::net::TcpListener;

    pub async fn redirect_worker() -> Result<()> {
        let (local_traffic, ports, direct_mark, proxy_chain, disable_ipv6, redirect_listen) = {
            let settings = get_settings().read().await;
            match &settings.intercept_mode {
                crate::settings::InterceptMode::REDIRECT {
                    local_traffic,
                    ports,
                    direct_mark,
                    proxy_chain,
                } => (
                    *local_traffic,
                    ports.clone(),
                    *direct_mark,
                    proxy_chain.clone(),
                    settings.disable_ipv6,
                    settings.redirect_listen.clone(),
                ),
                _ => return Ok(()),
            }
        };

        let listen_addr = rfor_bind_addr(disable_ipv6);
        let listener = match redirect_listen {
            Some(addr) => TcpListener::bind(addr).await?,
            None => TcpListener::bind(format!("{}:0", listen_addr)).await?,
        };

        let port = listener.local_addr()?.port();
        info!("redirect listen: {}", listener.local_addr()?);

        if let Err(err) = set_nat_iptables(
            &proxy_chain,
            port,
            direct_mark,
            &ports,
            local_traffic,
            disable_ipv6,
        ) {
            cleanup_nat_iptables(&proxy_chain).unwrap_or(());
            return Err(err);
        }

        tokio::select! {
            _ = accept_socket_loop(listener) => {},
            Err(err) = crate::utils::receive_signal() => {
                cleanup_nat_iptables(&proxy_chain).unwrap_or(());
                return Err(err);
            },
        }

        Ok(())
    }

    async fn accept_socket_loop(listener: tokio::net::TcpListener) {
        loop {
            match listener.accept().await {
                Ok((mut socket, peer_addr)) => {
                    tokio::spawn(async move {
                        match handle_tcp(&mut socket, peer_addr).await {
                            Err(e) => {
                                error!("{:#}", e);
                            }
                            _ => {}
                        };
                    });
                }
                Err(e) => warn!("accept incoming connection failed {:?}", e),
            }
        }
    }

    async fn handle_tcp(inbound: &mut tokio::net::TcpStream, peer_addr: SocketAddr) -> Result<()> {
        use crate::rules::{InboundProtocol, RouteContext, TargetAddr};
        use crate::utils::{is_valid_domain, transfer_tcp_with_initial_data};

        let Some(sniffed) = crate::sniffer::sniff_tcp(inbound).await? else {
            return Ok(());
        };
        let domain = sniffed.host.filter(|s| is_valid_domain(s.as_str()));

        let origin_addr = match peer_addr {
            SocketAddr::V4(v4) => SocketAddr::V4(v4),
            SocketAddr::V6(v6) => {
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    SocketAddr::new(IpAddr::V4(v4), v6.port())
                } else {
                    SocketAddr::V6(v6)
                }
            }
        };
        let origin_addr = match origin_addr {
            SocketAddr::V4(_) => {
                let addr = nix::sys::socket::sockopt::OriginalDst {}
                    .get(inbound)
                    .context("failed to get original ipv4 addr")?;
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_be())),
                    addr.sin_port.to_be(),
                )
            }
            SocketAddr::V6(v6) => {
                let addr = nix::sys::socket::sockopt::Ip6tOriginalDst {}
                    .get(inbound)
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
            src_addr: peer_addr,
            dst_addr: target_addr,
            inbound_proto: Some(InboundProtocol::REDIRECT),
            socket_type: crate::rules::SocketType::STREAM,
        };

        transfer_tcp_with_initial_data(inbound, rt_context.to_owned(), sniffed.data)
            .await
            .context(format!("Failed request `{}`", rt_context))?;

        Ok(())
    }

    fn __setup_nat_iptables(
        ipt: &iptables::IPTables,
        proxy_chain: &str,
        redirect_port: u16,
        direct_mark: u32,
        ports: &str,
        local_traffic: bool,
        reserved_ip: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
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
                ports, redirect_port,
            ),
        )?;

        ipt.append(table, "PREROUTING", &format!("-j {}", proxy_chain))?;

        if local_traffic {
            ipt.append(table, "OUTPUT", &format!("-j {}", proxy_chain))?;
        }
        Ok(())
    }

    fn set_nat_iptables(
        proxy_chain: &str,
        redirect_port: u16,
        direct_mark: u32,
        ports: &str,
        local_traffic: bool,
        disable_ipv6: bool,
    ) -> Result<()> {
        __setup_nat_iptables(
            &iptables::new(false)
                .map_err(|e| anyhow::anyhow!("command iptables not found: {}", e))?,
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
            error!("failed adding ipv4 iptable rules: {}", e);
            tokio::io::Error::new(
                tokio::io::ErrorKind::Other,
                format!("failed adding ipv4 iptable rules, {}.", e.to_string()),
            )
        })?;

        if !disable_ipv6 {
            __setup_nat_iptables(
                &iptables::new(true)
                    .map_err(|e| anyhow::anyhow!("command ip6tables not found: {}", e))?,
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
                error!("failed adding ipv6 iptable rules: {}", e);
                tokio::io::Error::new(
                    tokio::io::ErrorKind::Other,
                    format!("failed adding ipv6 iptable rules, {}.", e.to_string()),
                )
            })?;
        }
        Ok(())
    }

    fn cleanup_nat_iptables(proxy_chain: &str) -> Result<(), Box<dyn std::error::Error>> {
        let ipts = [
            iptables::new(false).map_err(|e| format!("command iptables not found: {}", e))?,
            iptables::new(true).map_err(|e| format!("command ip6tables not found: {}", e))?,
        ];
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
}

#[cfg(target_os = "linux")]
pub use linux_impl::redirect_worker;

#[cfg(not(target_os = "linux"))]
pub async fn redirect_worker() -> anyhow::Result<()> {
    // Redirect mode is not supported on non-Linux platforms
    Ok(())
}
