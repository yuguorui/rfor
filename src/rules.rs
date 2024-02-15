use anyhow::Context;
use iprange::IpRange;

use ipnet::Ipv6Net;
use tokio::time::Instant;

use std::fmt::Display;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::{
    net::{TcpSocket, TcpStream},
    time::timeout,
};
use url::Url;

use crate::utils::{to_io_err, ToV6Net, ToV6SockAddr};
use crate::SETTINGS;

use fast_socks5::client as socks_client;

pub const RULE_DOMAIN_SUFFIX_TAG: &str = "@";
pub const TIMEOUT: u64 = 3000;

#[derive(Debug, Clone)]
pub struct Outbound {
    pub name: String,
    pub url: Option<Url>,
    pub bind_range: Option<IpRange<Ipv6Net>>,
}

#[derive(Debug)]
pub struct Condition {
    pub maxmind_regions: Vec<String>,
    pub dst_ip_range: IpRange<Ipv6Net>,
    pub domains: Option<std::collections::HashSet<String>>,
}

impl Condition {
    pub fn default() -> Self {
        Self {
            maxmind_regions: Vec::new(),
            dst_ip_range: IpRange::<Ipv6Net>::new(),
            domains: None,
        }
    }

    pub fn match_domain(&self, name: &str) -> bool {
        if let Some(ref domains) = self.domains {
            if domains.get(&name.to_owned()).is_some() {
                return true;
            }

            /* Check the DOMAIN-SUFFIX rules */
            let domain = format!(".{}{}", name, RULE_DOMAIN_SUFFIX_TAG);
            let indices = domain.match_indices(".");
            for index in indices {
                if domains.get(&domain[index.0 + 1..].to_string()).is_some() {
                    return true;
                }
            }
        }

        false
    }

    pub fn match_sockaddr(
        &self,
        dst_sock: &SocketAddr,
        ip_db: Option<&maxminddb::Reader<Vec<u8>>>,
    ) -> bool {
        let dst_ip = dst_sock.ip();
        if self
            .dst_ip_range
            .contains(dst_ip.to_ipv6_net().as_ref().unwrap())
        {
            return true;
        }

        /* Check the maxmind */
        if let Some(reader) = ip_db {
            let region: Result<maxminddb::geoip2::Country, maxminddb::MaxMindDBError> =
                reader.lookup(dst_ip);
            if let Ok(region) = region {
                if self.maxmind_regions.contains(
                    &region
                        .country
                        .unwrap()
                        .iso_code
                        .unwrap()
                        .to_string()
                        .to_lowercase(),
                ) {
                    return true;
                }
            }
        }
        return false;
    }
}

pub struct RouteTable {
    default_outbound: Option<u8>,
    pub rules: Vec<Condition>,
    pub outbounds: Vec<Outbound>,
    pub ip_db: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// Connect to an IP address.
    Ip(SocketAddr),
    /// Connect to a fully qualified domain name.
    ///
    /// The domain name will be passed along to the proxy server and DNS lookup
    /// will happen there.
    Domain(String, u16, Option<SocketAddr>),
}

impl Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Ip(ip) => write!(f, "{}", ip),
            TargetAddr::Domain(domain, port, _) => write!(f, "{}:{}", domain, port),
        }
    }
}

#[derive(Debug, Clone)]
pub enum InboundProtocol {
    SOCKS5,
    #[cfg(target_os = "linux")]
    TPROXY,
    REDIRECT,
    UNKNOWN,
}

#[derive(Debug, Clone)]
pub struct RouteContext {
    pub src_sock: SocketAddr,
    pub target_addr: TargetAddr,
    pub inbound_proto: Option<InboundProtocol>,
}

impl Display for RouteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}:{} -> {}",
            self.inbound_proto
                .as_ref()
                .unwrap_or(&InboundProtocol::UNKNOWN),
            self.src_sock,
            self.target_addr
        )
    }
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            default_outbound: None,
            rules: Vec::new(),
            outbounds: Vec::new(),
            ip_db: None,
        }
    }

    pub fn set_default_route(&mut self, index: u8) {
        self.default_outbound = Some(index);
    }

    pub fn get_outbound_by_name(&self, name: &str) -> Option<&Outbound> {
        for outbound in &self.outbounds {
            if outbound.name == name {
                return Some(outbound);
            }
        }
        return None;
    }

    pub fn get_outbound_index_by_name(&self, name: &str) -> Option<u8> {
        for (index, outbound) in self.outbounds.iter().enumerate() {
            if outbound.name == name {
                return Some(index as u8);
            }
        }
        return None;
    }

    pub fn add_empty_rule<S: ToString>(
        &mut self,
        name: S,
        url: Option<Url>,
        bind_range: Option<IpRange<Ipv6Net>>,
    ) {
        self.outbounds.push(Outbound {
            name: name.to_string(),
            url,
            bind_range,
        });

        self.rules.push(Condition::default());
    }

    fn match_route(&self, context: &RouteContext) -> u8 {
        for (index, cond) in self.rules.iter().enumerate() {
            match &context.target_addr {
                TargetAddr::Ip(dst_sock) => {
                    if cond.match_sockaddr(dst_sock, self.ip_db.as_ref()) {
                        return index as u8;
                    }
                }

                TargetAddr::Domain(domain, _, dst_sock) => {
                    if cond.match_domain(domain) {
                        return index as u8;
                    }

                    if let Some(dst_sock) = dst_sock {
                        if cond.match_sockaddr(dst_sock, self.ip_db.as_ref()) {
                            return index as u8;
                        }
                    }
                }
            }
        }

        return self.default_outbound.context("no default route").unwrap();
    }

    pub async fn get_tcp_sock(&self, context: &RouteContext) -> tokio::io::Result<TcpStream> {
        let start = Instant::now();
        let outbound_index = self.match_route(context);
        let outbound = &self.outbounds[outbound_index as usize];
        let duration = start.elapsed();
        println!(
            "{} -> Outbound({}){}",
            context,
            outbound.name,
            if SETTINGS.read().await.debug {
                format!(", time: {}us", duration.as_micros())
            } else {
                "".to_owned()
            },
        );

        if outbound.url.is_none() {
            let sock = match SETTINGS.read().await.disable_ipv6 {
                false => TcpSocket::new_v6()?,
                true => TcpSocket::new_v4()?,
            };

            if let Some(bind_range) = &outbound.bind_range {
                if bind_range.contains(context.src_sock.ip().to_ipv6_net().as_ref().unwrap()) {
                    crate::tproxy::tproxy_bind_src(&sock, context.src_sock)?;
                }
            }

            prepare_socket_bypass_mangle(sock.as_raw_fd()).await?;

            match &context.target_addr {
                TargetAddr::Ip(dst_sock) => {
                    return Ok(sock
                        .connect(match SETTINGS.read().await.disable_ipv6 {
                            false => dst_sock.to_ipv6_sockaddr(),
                            true => *dst_sock,
                        })
                        .await?);
                }
                TargetAddr::Domain(domain, port, sock_addr) => {
                    let sock_addr = match sock_addr {
                        Some(addr) => match SETTINGS.read().await.disable_ipv6 {
                            false => addr.to_ipv6_sockaddr(),
                            true => *addr,
                        },
                        None => {
                            let sock = (domain.as_str(), *port)
                                .to_socket_addrs()?
                                .next()
                                .expect("unreachable");

                            match SETTINGS.read().await.disable_ipv6 {
                                false => sock.to_ipv6_sockaddr(),
                                true => sock,
                            }
                        }
                    };
                    let fut = sock.connect(sock_addr);
                    return timeout(Duration::from_millis(TIMEOUT), fut).await?;
                }
            }
        }

        let proxy_url = outbound.url.as_ref().unwrap();
        match proxy_url.scheme() {
            "drop" => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Connection dropped",
                ));
            }
            "socks" | "socks5" => {
                let socks_server = format!(
                    "{}:{}",
                    proxy_url.host_str().unwrap(),
                    proxy_url
                        .port_or_known_default()
                        .expect("Not found default fault for this scheme.")
                );

                let target_addr = match &context.target_addr {
                    TargetAddr::Ip(dst_sock) => dst_sock.ip().to_string(),
                    TargetAddr::Domain(domain, _, _) => domain.to_owned(),
                };
                let target_port = match context.target_addr {
                    TargetAddr::Ip(dst_sock) => dst_sock.port(),
                    TargetAddr::Domain(_, port, _) => port,
                };

                match proxy_url.username().is_empty() {
                    true => {
                        let fut = socks_client::Socks5Stream::connect(
                            socks_server,
                            target_addr,
                            target_port,
                            socks_client::Config::default(),
                        );
                        let sock = timeout(Duration::from_millis(TIMEOUT), fut)
                            .await?
                            .map_err(to_io_err)?;
                        return Ok(sock.get_socket());
                    }
                    false => {
                        let fut = socks_client::Socks5Stream::connect_with_password(
                            socks_server,
                            target_addr,
                            target_port,
                            proxy_url.username().to_string(),
                            proxy_url.password().unwrap_or("").to_string(),
                            socks_client::Config::default(),
                        );
                        let sock = timeout(Duration::from_millis(TIMEOUT), fut)
                            .await?
                            .map_err(to_io_err)?;
                        return Ok(sock.get_socket());
                    }
                }
            }
            _ => {
                panic!("only socks5 scheme is implemented.");
            }
        }
    }
}

pub async fn prepare_socket_bypass_mangle(sockfd: i32) -> tokio::io::Result<()> {
    match &SETTINGS.read().await.intercept_mode {
        crate::settings::InterceptMode::TPROXY {
            direct_mark, ..
        } | crate::settings::InterceptMode::REDIRECT {
            direct_mark, ..
        }=> {
            // Avoid local traffic looping
            nix::sys::socket::setsockopt(
                sockfd,
                nix::sys::socket::sockopt::Mark,
                &direct_mark,
            )?;
        }
        crate::settings::InterceptMode::MANUAL => {}
    }

    Ok(())
}
