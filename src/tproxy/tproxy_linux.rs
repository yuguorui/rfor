use anyhow::{anyhow, Context, Result};
use tokio::net::TcpListener;

use crate::{rules::prepare_socket_bypass_mangle, utils::ToV6SockAddr, SETTINGS};
use std::mem::MaybeUninit;

fn setup_iptransparent_opts(sock: socket2::SockRef) -> std::io::Result<()> {
    use nix::sys::socket::sockopt::IpTransparent;
    use nix::sys::socket::{self};
    use std::os::unix::io::AsRawFd;

    socket::setsockopt(sock.as_raw_fd(), IpTransparent, &true)?;
    Ok(())
}

fn setup_udpsock_opts(sock: &tokio::net::UdpSocket) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    setup_iptransparent_opts(socket2::SockRef::from(sock))?;

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

pub async fn tproxy_worker() -> Result<()> {
    if SETTINGS.read().await.tproxy_listen.is_none() {
        return Ok(());
    }

    if let Err(err) = environment_setup().await {
        clean_environment().await.unwrap_or(());
        return Err(err);
    }

    let listen_addr = SETTINGS.read().await.tproxy_listen.clone().unwrap();
    println!("tproxy listen: {}", listen_addr);

    tokio::select! {
        Err(err) = accept_socket_loop(&listen_addr) => {
            clean_environment().await?;
            return Err(err);
        },
        Err(err) = udp_socket_loop(&listen_addr) => {
            clean_environment().await?;
            return Err(err);
        },
        Err(err) = crate::utils::receive_signal() => {
            clean_environment().await?;
            return Err(err);
        },
    };
}

async fn accept_socket_loop(listen_addr: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await.context("failed to bind tcp listener")?;
    setup_iptransparent_opts(socket2::SockRef::from(&listener)).context("failed to set IP_TRANSPARENT")?;

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
    use std::sync::Arc;
    use tokio::io::Interest;

    if !SETTINGS.read().await.udp_enable {
        return Ok(());
    }

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
                let prefilled_data = bytes::Bytes::copy_from_slice(&buffer[..size]);

                println!(
                    "udp relay: create tunnel {:?} <-> {:?}",
                    source_sockaddr, target_sockaddr
                );

                let prefilled_data_clone = prefilled_data.clone();
                tokio::spawn(async move {
                    match relay_udp_packet(prefilled_data_clone, source_sockaddr, target_sockaddr)
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            println!("Failed to relay udp packet: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                return Err(e.into());
            }
        };
    }
}

async fn relay_udp_packet(
    init_packet: bytes::Bytes,
    source_sockaddr: std::net::SocketAddr,
    target_sockaddr: std::net::SocketAddr,
) -> Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use tokio::net::UdpSocket;

    let host = crate::sniffer::parse_host(&init_packet);

    let target_socket = SETTINGS.read().await.routetable.get_dgram_sock(&crate::rules::RouteContext {
            src_addr: source_sockaddr,
            dst_addr: match host {
                None => crate::rules::TargetAddr::Ip(target_sockaddr),
                Some(host) => crate::rules::TargetAddr::Domain(host, target_sockaddr.port(), Some(target_sockaddr)),
            },
            inbound_proto: Some(crate::rules::InboundProtocol::TPROXY),
            socket_type: crate::rules::SocketType::DGRAM,
        }).await?;

    // 2. prepare the intermediate socket which is connect to the source, which should bind to the target address,
    // and pretend to be the target.
    let fd;
    unsafe {
        fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return Err(anyhow!("failed to create socket: {}", std::io::Error::last_os_error()));
        }

        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &1 as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        );
        if ret < 0 {
            return Err(anyhow!("failed to set IP_TRANSPARENT: {}", std::io::Error::last_os_error()));
        }

        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1 as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        );
        if ret < 0 {
            return Err(anyhow!("failed to set SO_REUSEADDR: {}", std::io::Error::last_os_error()));
        }

        let addr = socket2::SockAddr::from(target_sockaddr);
        let ret = libc::bind(
            fd,
            &addr.as_storage() as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as u32,
        );
        if ret < 0 {
            return Err(anyhow!("failed to bind to target address {}: {}", target_sockaddr, std::io::Error::last_os_error()));
        }
    }
    let source_socket =
        unsafe { UdpSocket::from_std(std::net::UdpSocket::from(OwnedFd::from_raw_fd(fd))) }?;
    prepare_socket_bypass_mangle(source_socket.as_raw_fd()).await?;
    source_socket.connect(source_sockaddr).await?;

    // source_socket is ready and the new reply from target_sockaddr will be recv by the source_socket
    target_socket.send_to(&init_packet, crate::rules::TargetAddr::Ip(target_sockaddr)).await?;

    let timeout = std::time::Duration::from_secs(SETTINGS.read().await.udp_timeout);
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);

    const BUFFER_SIZE: usize = 0x10000;
    let mut dst_buffer = [0 as u8; BUFFER_SIZE];
    let mut src_buffer = [0 as u8; BUFFER_SIZE];
    loop {
        tokio::select! {
            data = source_socket.recv(&mut src_buffer) => {
                match data {
                    Ok(size) => {
                        sleep.as_mut().set(tokio::time::sleep(timeout));
                        match target_socket.send_to(&src_buffer[..size], crate::rules::TargetAddr::Ip(target_sockaddr)).await {
                            Ok(_) => {
                                println!("udp relay: {:?} -> {:?} with bytes {}", source_sockaddr, target_sockaddr, size);
                            }
                            Err(e) => {
                                println!("Failed to send udp packet to target: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        println!("Failed to receive udp packet from source: {}", e);
                        break;
                    }
                }
            },
            val = target_socket.recv_from(&mut dst_buffer) => {
                match val {
                    Ok((size, _)) => {
                        sleep.as_mut().set(tokio::time::sleep(timeout));
                        match source_socket.send(&dst_buffer[..size]).await {
                            Ok(_) => {
                                println!("udp relay: {:?} <- {:?} with bytes {}", source_sockaddr, target_sockaddr, size);
                            }
                            Err(e) => {
                                println!("Failed to send back udp packet to source: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        println!("Failed to receive udp packet from target: {}", e);
                        break;
                    }
                }
            },
            _ = &mut sleep => {
                break;
            }
        }
    }

    Ok(())
}

pub fn tproxy_bind_src(
    sock: &tokio::net::TcpSocket,
    src_sock: std::net::SocketAddr,
) -> tokio::io::Result<()> {
    setup_iptransparent_opts(socket2::SockRef::from(sock))?;
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
        iptables::new(true).expect("command ip6tables not found")
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
    ports: &[u16],
    local_traffic: bool,
    udp_enable: bool,
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

    if udp_enable {
        ipt.append(
            table,
            proxy_chain,
            &format!(
                "-p udp --match multiport --dports {} -j TPROXY --tproxy-mark {} --on-port {}",
                ports.into_iter().map(|v| v.to_string()).join(","),
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

        if udp_enable {
            ipt.append(
                table,
                mark_chain,
                &format!(
                    "-p udp --match multiport --dports {} -j MARK --set-mark {}",
                    ports.into_iter().map(|v| v.to_string()).join(","),
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
        SETTINGS.read().await.udp_enable,
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
            SETTINGS.read().await.udp_enable,
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
