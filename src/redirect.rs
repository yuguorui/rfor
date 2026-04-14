// Redirect module - Linux-only functionality using iptables NAT REDIRECT
// On non-Linux platforms, this module provides a no-op implementation

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use anyhow::{Context, Result};
    use nix::sys::socket::GetSockOpt;
    use tracing::{error, info, warn};

    use crate::{utils::rfor_bind_addr, get_settings};
    use std::net::{IpAddr, SocketAddr};
    use tokio::net::TcpListener;

    pub async fn redirect_worker() -> Result<()> {
        match &get_settings().read().await.intercept_mode {
            crate::settings::InterceptMode::REDIRECT {
                local_traffic,
                ports,
                direct_mark,
                proxy_chain,
            } => {
                let listen_addr = rfor_bind_addr().await;

                let listener = match &get_settings().read().await.redirect_listen {
                    Some(addr) => TcpListener::bind(addr).await?,
                    None => TcpListener::bind(format!("{}:0", listen_addr)).await?,
                };

                let port = listener
                    .local_addr()
                    .expect("TCP socket should have local_addr")
                    .port();
                info!("redirect listen: {}", listener.local_addr()?);

                if let Err(err) =
                    set_nat_iptables(proxy_chain, port, *direct_mark, ports, *local_traffic).await
                {
                    cleanup_nat_iptables(proxy_chain).unwrap_or(());
                    return Err(err);
                }

                // Capture owned copies for the reconcile loop so they outlive
                // the borrow on `get_settings()`.
                let reconcile_chain = proxy_chain.clone();
                let reconcile_ports = ports.clone();
                let reconcile_direct_mark = *direct_mark;
                let reconcile_local_traffic = *local_traffic;

                tokio::select! {
                    _ = accept_socket_loop(listener) => {},
                    _ = reconcile_nat_iptables_loop(
                        reconcile_chain,
                        port,
                        reconcile_direct_mark,
                        reconcile_ports,
                        reconcile_local_traffic,
                    ) => {},
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

    async fn handle_tcp(inbound: &mut tokio::net::TcpStream) -> Result<()> {
        use crate::rules::{InboundProtocol, RouteContext, TargetAddr};
        use crate::utils::{is_valid_domain, transfer_tcp};
        use std::time::Duration;

        let mut buffer = [0u8; 0x800];
        // Bound the peek so a silent client cannot pin this fd forever.
        // On timeout we fall through with an empty buffer and route by IP.
        let _ = tokio::time::timeout(Duration::from_secs(5), inbound.peek(&mut buffer)).await;

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
            src_addr: inbound.peer_addr()?,
            dst_addr: target_addr,
            inbound_proto: Some(InboundProtocol::REDIRECT),
            socket_type: crate::rules::SocketType::STREAM,
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
                ports,
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
        ports: &str,
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
            error!("failed adding ipv4 iptable rules: {}", e);
            tokio::io::Error::new(
                tokio::io::ErrorKind::Other,
                format!("failed adding ipv4 iptable rules, {}.", e.to_string()),
            )
        })?;

        if !get_settings().read().await.disable_ipv6 {
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
                error!("failed adding ipv6 iptable rules: {}", e);
                tokio::io::Error::new(
                    tokio::io::ErrorKind::Other,
                    format!("failed adding ipv6 iptable rules, {}.", e.to_string()),
                )
            })?;
        }
        Ok(())
    }

    fn nat_iptables_healthy(
        ipt: &iptables::IPTables,
        proxy_chain: &str,
        local_traffic: bool,
    ) -> bool {
        // Our chain must still exist and still contain rules. Merlin's
        // firewall-restart often flushes the nat table, which either deletes
        // our chain outright or leaves it empty without a PREROUTING jump.
        if !ipt.chain_exists("nat", proxy_chain).unwrap_or(false) {
            return false;
        }
        match ipt.list("nat", proxy_chain) {
            // list() returns the chain header "-N rfor-proxy" plus one entry
            // per rule, so an intact setup has len > 1.
            Ok(rules) if rules.len() > 1 => {}
            _ => return false,
        }
        let jump = format!("-j {}", proxy_chain);
        let referenced_from = |chain: &str| {
            ipt.list("nat", chain)
                .map(|rs| rs.iter().any(|r| r.contains(&jump)))
                .unwrap_or(false)
        };
        if !referenced_from("PREROUTING") {
            return false;
        }
        if local_traffic && !referenced_from("OUTPUT") {
            return false;
        }
        true
    }

    async fn reconcile_nat_iptables_loop(
        proxy_chain: String,
        redirect_port: u16,
        direct_mark: u32,
        ports: String,
        local_traffic: bool,
    ) {
        use std::time::Duration;
        let period = Duration::from_secs(10);
        loop {
            tokio::time::sleep(period).await;

            let ipt4 = match iptables::new(false) {
                Ok(i) => i,
                Err(e) => {
                    warn!("reconcile: failed to open ipv4 iptables: {}", e);
                    continue;
                }
            };
            let v4_ok = nat_iptables_healthy(&ipt4, &proxy_chain, local_traffic);

            let check_v6 = !get_settings().read().await.disable_ipv6;
            let v6_ok = if check_v6 {
                match iptables::new(true) {
                    Ok(ipt6) => nat_iptables_healthy(&ipt6, &proxy_chain, local_traffic),
                    Err(e) => {
                        warn!("reconcile: failed to open ipv6 iptables: {}", e);
                        true // don't trigger a rebuild just because ip6tables is broken
                    }
                }
            } else {
                true
            };

            if v4_ok && v6_ok {
                continue;
            }

            warn!(
                "rfor-proxy nat rules missing or incomplete (v4_ok={}, v6_ok={}), rebuilding",
                v4_ok, v6_ok
            );
            cleanup_nat_iptables(&proxy_chain).unwrap_or(());
            match set_nat_iptables(
                &proxy_chain,
                redirect_port,
                direct_mark,
                &ports,
                local_traffic,
            )
            .await
            {
                Ok(()) => info!("rfor-proxy nat rules rebuilt"),
                Err(e) => error!("reconcile rebuild failed: {:#}", e),
            }
        }
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
}

#[cfg(target_os = "linux")]
pub use linux_impl::redirect_worker;

#[cfg(not(target_os = "linux"))]
pub async fn redirect_worker() -> anyhow::Result<()> {
    // Redirect mode is not supported on non-Linux platforms
    Ok(())
}
