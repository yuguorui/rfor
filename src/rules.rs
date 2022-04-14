use iprange::IpRange;

use ipnet::Ipv6Net;
use tokio::time::Instant;

use std::fmt::Display;
use std::time::Duration;
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
};
use tokio::{
    net::{TcpSocket, TcpStream},
    time::timeout,
};
use url::Url;

use crate::tproxy::handle_intercept_sock;
use crate::utils::{to_io_err, BoomHashSet, ToV6Net, ToV6SockAddr};
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
    pub domains: Option<BoomHashSet<String>>,
    pub suffix_domains: Option<BoomHashSet<String>>,
}

impl Condition {
    pub fn default() -> Self {
        Self {
            maxmind_regions: Vec::new(),
            dst_ip_range: IpRange::<Ipv6Net>::new(),
            domains: None,
            suffix_domains: None,
        }
    }
}

#[derive(Debug)]
pub struct RouteRule(pub Outbound, pub Option<Condition>);

pub type OutboundName = String;

pub struct RouteTable {
    pub default: Outbound,
    pub outbound_dict: HashMap<OutboundName, RouteRule>,
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

fn match_rule_with_sockaddr(
    dst_sock: &SocketAddr,
    rule: &Condition,
    ip_db: Option<&maxminddb::Reader<Vec<u8>>>,
) -> bool {
    let dst_ip = dst_sock.ip();
    if rule
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
            if rule
                .maxmind_regions
                .contains(&region.country.unwrap().iso_code.unwrap().to_string())
            {
                return true;
            }
        }
    }
    return false;
}

impl RouteTable {
    pub fn add<S: ToString>(
        &mut self,
        name: S,
        url: Option<Url>,
        bind_range: Option<IpRange<Ipv6Net>>,
    ) {
        self.outbound_dict.insert(
            name.to_string(),
            RouteRule(
                Outbound {
                    name: name.to_string(),
                    url,
                    bind_range,
                },
                None,
            ),
        );
    }

    pub fn match_route(&self, context: &RouteContext) -> (&str, &Outbound) {
        for (name, outbound_rule) in self.outbound_dict.iter() {
            if let Some(rule) = outbound_rule.1.as_ref() {
                match &context.target_addr {
                    TargetAddr::Ip(dst_sock) => {
                        if match_rule_with_sockaddr(dst_sock, rule, self.ip_db.as_ref()) {
                            return (name, &outbound_rule.0);
                        }
                    }
                    TargetAddr::Domain(domain, _port, dst_sock) => {
                        if let Some(phf) = &rule.domains {
                            /* Check the DOMAIN rules. */
                            if phf.get(&domain) {
                                return (name, &outbound_rule.0);
                            }

                            /* Check the DOMAIN-SUFFIX rules */
                            let domain = format!(".{}{}", domain, RULE_DOMAIN_SUFFIX_TAG);
                            let indices = domain.match_indices(".");
                            for index in indices {
                                if phf.get(&domain[index.0 + 1..].to_string()) {
                                    return (name, &outbound_rule.0);
                                }
                            }
                        }

                        if let Some(dst_sock) = dst_sock {
                            if match_rule_with_sockaddr(
                                dst_sock,
                                rule,
                                self.ip_db.as_ref(),
                            ) {
                                return (name, &outbound_rule.0);
                            }
                        }
                    }
                }
            }
        }
        (&self.default.name, &self.default)
    }

    pub async fn get_tcp_sock(&self, context: &RouteContext) -> tokio::io::Result<TcpStream> {
        let start = Instant::now();
        let (name, outbound) = self.match_route(context);
        let duration = start.elapsed();
        println!(
            "{} -> Outbound({}){}",
            context,
            name,
            if SETTINGS.read().await.debug {
                format!(", time: {}us", duration.as_micros())
            } else {
                "".to_owned()
            },
        );

        if outbound.url.is_none() {
            let sock = TcpSocket::new_v6()?;

            if let Some(bind_range) = &outbound.bind_range {
                if bind_range.contains(context.src_sock.ip().to_ipv6_net().as_ref().unwrap()) {
                    crate::tproxy::tproxy_bind_src(&sock, context.src_sock)?;
                }
            }

            handle_intercept_sock(&sock).await?;

            match &context.target_addr {
                TargetAddr::Ip(dst_sock) => {
                    return Ok(sock.connect(dst_sock.to_ipv6_sockaddr()).await?);
                }
                TargetAddr::Domain(domain, port, sock_addr) => {
                    let sock_addr = match sock_addr {
                        Some(addr) => addr.to_ipv6_sockaddr(),
                        None => (domain.as_str(), *port)
                            .to_socket_addrs()?
                            .next()
                            .expect("unreachable")
                            .to_ipv6_sockaddr(),
                    };
                    let fut = sock.connect(sock_addr);
                    return timeout(Duration::from_millis(TIMEOUT), fut).await?;
                }
            }
        }

        let proxy_url = outbound.url.as_ref().unwrap();
        match proxy_url.scheme() {
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
