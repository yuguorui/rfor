use anyhow::{anyhow, Context, Result};

use crate::SETTINGS;

pub async fn tproxy_worker() -> Result<()> {
    use nix::sys::socket::sockopt::IpTransparent;
    use nix::sys::socket::{self};
    use std::os::unix::prelude::AsRawFd;
    use tokio::net::TcpListener;

    if SETTINGS.read().await.tproxy_listen.is_none() {
        return Ok(());
    }

    if let Err(err) = environment_setup().await {
        clean_environment().await.unwrap_or(());
        return Err(err);
    }

    let listen_addr = SETTINGS.read().await.tproxy_listen.clone().unwrap();
    println!("tproxy listen: {}", listen_addr);

    let listener = TcpListener::bind(listen_addr).await?;
    socket::setsockopt(listener.as_raw_fd(), IpTransparent, &true)?;

    tokio::select! {
        _ = accept_socket_loop(listener) => {},
        Err(err) = crate::utils::receive_signal() => {
            clean_environment().await?;
            return Err(err);
        },
    };

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
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}

pub fn tproxy_bind_src(
    sock: &tokio::net::TcpSocket,
    src_sock: std::net::SocketAddr,
) -> tokio::io::Result<()> {
    use nix::sys::socket::sockopt::IpTransparent;
    use nix::sys::socket::{self};
    use std::os::unix::prelude::AsRawFd;

    socket::setsockopt(sock.as_raw_fd(), IpTransparent, &true)?;
    match sock.bind(src_sock) {
        Ok(_) => {}
        Err(err) => match err.kind() {
            // In this branch, we are processing the local traffic.
            std::io::ErrorKind::AddrInUse => {}
            _ => return Err(err),
        },
    };
    sock.set_reuseaddr(true)?;
    Ok(())
}

async fn handle_tcp(inbound: &mut tokio::net::TcpStream) -> Result<()> {
    use crate::rules::{InboundProtocol, RouteContext, TargetAddr};
    use crate::utils::{is_valid_domain, transfer_tcp};

    let mut buffer = [0u8; 0x400];
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
        src_sock: inbound.peer_addr()?,
        target_addr,
        inbound_proto: Some(InboundProtocol::TPROXY),
    };

    transfer_tcp(inbound, rt_context.to_owned())
        .await
        .context(format!("Failed request `{}`", rt_context))?;

    Ok(())
}

fn cleanup_iptables(proxy_chain: &str, mark_chain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ipts = [iptables::new(false).unwrap(), iptables::new(true).unwrap()];

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
    ports: &[u16],
    local_traffic: bool,
    reserved_ip: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    use itertools::Itertools;

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
            ports.into_iter().map(|v| v.to_string()).join(","),
            xmark,
            tproxy_port,
        ),
    )?;

    ipt.append(
        table,
        proxy_chain,
        &format!(
            "-p tcp --match multiport --sports {} -j MARK --set-mark {}",
            ports.into_iter().map(|v| v.to_string()).join(","),
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
                ports.into_iter().map(|v| v.to_string()).join(","),
                xmark,
            ),
        )?;

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
    ports: &[u16],
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
        __setup_iptables(
            &iptables::new(true).unwrap(),
            proxy_chain,
            mark_chain,
            tproxy_port,
            xmark,
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
) -> Result<Option<rtnetlink::packet::LinkMessage>, rtnetlink::Error> {
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

    use rtnetlink::{
        new_connection,
        packet::{rule::Nla, FR_ACT_TO_TBL, RTN_LOCAL},
    };

    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // ip rule add
    let mut rule = handle
        .rule()
        .add()
        .v4()
        .table(route_table_index)
        .action(FR_ACT_TO_TBL);
    rule.message_mut().nlas.push(Nla::FwMark(fwmark));
    rule.execute().await?;

    if !SETTINGS.read().await.disable_ipv6 {
        let mut rule = handle
            .rule()
            .add()
            .v6()
            .table(route_table_index)
            .action(FR_ACT_TO_TBL);
        rule.message_mut().nlas.push(Nla::FwMark(fwmark));
        rule.execute().await?;
    }

    // ip route add
    // Scope host for local routes, see also /etc/iproute2/rt_scopes
    let scope_host = 254;
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
        .table(route_table_index)
        .scope(scope_host);
    route.message_mut().header.kind = RTN_LOCAL;
    route.execute().await?;

    if !SETTINGS.read().await.disable_ipv6 {
        // Add default IPv6 route.
        let mut route = handle
            .route()
            .add()
            .v6()
            .destination_prefix(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)
            .output_interface(lo_link_index)
            .table(route_table_index)
            .scope(scope_host);
        route.message_mut().header.kind = RTN_LOCAL;
        route.execute().await?;
    }

    Ok(())
}

async fn environment_setup() -> Result<()> {
    use std::net::SocketAddr;

    let settings = SETTINGS.read().await;
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
    let settings = SETTINGS.read().await;
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
