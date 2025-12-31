use crate::utils::ToV6Net;
use ipnet::Ipv6Net;
use iprange::IpRange;
#[cfg(target_os = "linux")]
use socket2::SockRef;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use std::fmt::Display;
use std::net::{Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::{
    net::{TcpSocket, TcpStream},
    time::timeout,
};
use url::Url;

use tracing::info;

use crate::get_settings;
use crate::utils::{rfor_bind_addr, to_io_err, ToV6SockAddr};

use fast_socks5::client as socks_client;

pub const RULE_DOMAIN_SUFFIX_TAG: &str = "@";
pub const TIMEOUT: u64 = 3000;

#[derive(Debug, Clone)]
pub struct Outbound {
    pub name: String,
    pub url: Option<Url>,
    pub bind_range: Option<IpRange<Ipv6Net>>,
}

pub struct Condition {
    pub maxmind_regions: Vec<String>,
    pub dst_ip_table: treebitmap::IpLookupTable<Ipv6Addr, u8>,
    pub domains: Option<aho_corasick::AhoCorasick>,
}

impl std::fmt::Debug for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Condition")
            .field("maxmind_regions", &self.maxmind_regions)
            .field("dst_ip_table", &"IpLookupTable")
            .field("domains", &self.domains)
            .finish()
    }
}

impl Condition {
    pub fn default() -> Self {
        Self {
            maxmind_regions: Vec::new(),
            dst_ip_table: treebitmap::IpLookupTable::new(),
            domains: None,
        }
    }

    pub fn match_domain(&self, name: &str) -> Option<usize> {
        let domains = self.domains.as_ref()?;
        let mut max_match_len = 0;

        if let Some(m) = domains.find(name) {
            max_match_len = max_match_len.max(m.end() - m.start());
        }
        if let Some(m) = domains.find(&format!(".{name}{RULE_DOMAIN_SUFFIX_TAG}")) {
            max_match_len = max_match_len.max(m.end() - m.start());
        }
        if let Some(m) = domains.find(&format!("^{}$", name)) {
            max_match_len = max_match_len.max(m.end() - m.start());
        }

        if max_match_len > 0 {
            Some(max_match_len)
        } else {
            None
        }
    }

    pub fn match_sockaddr(
        &self,
        dst_sock: &SocketAddr,
        ip_db: Option<&maxminddb::Reader<Vec<u8>>>,
    ) -> Option<u8> {
        let dst_ip = dst_sock.ip();

        let ipv6_addr = match dst_ip {
             std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
             std::net::IpAddr::V6(v6) => v6,
        };

        if let Some((_, _, score)) = self.dst_ip_table.longest_match(ipv6_addr) {
            return Some(*score);
        }

        /* Check the maxmind */
        let reader = ip_db?;

        let region: maxminddb::geoip2::Country = reader.lookup(dst_ip).ok()?;
        let isocode = region.country.and_then(|c| c.iso_code)?;

        if self.maxmind_regions.contains(&isocode.to_string().to_lowercase()) {
             return Some(0);
        }

        None
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
pub enum SocketType {
    STREAM,
    DGRAM,
}

#[derive(Debug, Clone)]
pub struct RouteContext {
    pub src_addr: SocketAddr,
    pub dst_addr: TargetAddr,
    pub inbound_proto: Option<InboundProtocol>,
    pub socket_type: SocketType,
}

impl Display for RouteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}:{}:{:?} -> {}",
            self.inbound_proto
                .as_ref()
                .unwrap_or(&InboundProtocol::UNKNOWN),
            self.src_addr,
            self.socket_type,
            self.dst_addr
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

    fn match_route(&self, context: &RouteContext) -> tokio::io::Result<u8> {
        let mut best_domain_match: Option<(usize, usize)> = None; // (index, score)
        let mut best_ip_match: Option<(usize, u8)> = None; // (index, score)

        for (index, cond) in self.rules.iter().enumerate() {
            // Check Domain matches
            if let TargetAddr::Domain(domain, _, _) = &context.dst_addr {
                if let Some(score) = cond.match_domain(domain) {
                    if best_domain_match.map_or(true, |(_, best_score)| score > best_score) {
                        best_domain_match = Some((index, score));
                    }
                    // If we matched domain in this rule, this rule is a candidate.
                    // But we iterate all rules to find the BEST domain match.
                    continue; 
                }
            }

            // Check IP matches (only if no domain match in this rule, or target is IP)
            // Note: If TargetAddr::Domain, we also check resolved IP (dst_sock).
            let dst_sock = match &context.dst_addr {
                TargetAddr::Ip(sock) => Some(sock),
                TargetAddr::Domain(_, _, sock) => sock.as_ref(),
            };

            if let Some(sock) = dst_sock {
                if let Some(score) = cond.match_sockaddr(sock, self.ip_db.as_ref()) {
                    if best_ip_match.map_or(true, |(_, best_score)| score > best_score) {
                        best_ip_match = Some((index, score));
                    }
                }
            }
        }

        if let Some((index, _)) = best_domain_match {
            return Ok(index as u8);
        }

        if let Some((index, _)) = best_ip_match {
            return Ok(index as u8);
        }

        self.default_outbound.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no default route configured")
        })
    }

    pub async fn get_tcp_sock(&self, context: &RouteContext) -> tokio::io::Result<TcpStream> {
        let start = Instant::now();
        let outbound_index = self.match_route(context)?;
        let outbound = &self.outbounds[outbound_index as usize];
        let duration = start.elapsed();
        info!(
            "{} -> Outbound({}){}",
            context,
            outbound.name,
            if get_settings().read().await.debug {
                format!(", time: {}us", duration.as_micros())
            } else {
                "".to_owned()
            },
        );

        if outbound.url.is_none() {
            let sock = match get_settings().read().await.disable_ipv6 {
                false => TcpSocket::new_v6()?,
                true => TcpSocket::new_v4()?,
            };

            let inbound_proto = context.inbound_proto.as_ref().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "inbound_proto is None")
            })?;

            #[cfg(target_os = "linux")]
            if let InboundProtocol::TPROXY = inbound_proto {
                if let Some(bind_range) = &outbound.bind_range {
                    if let Ok(ipv6_net) = context.src_addr.ip().to_ipv6_net() {
                        if bind_range.contains(&ipv6_net) {
                            crate::tproxy::tproxy_bind_src(
                                socket2::SockRef::from(&sock),
                                context.src_addr,
                            )?;
                            sock.set_reuseaddr(true)?;
                        }
                    }
                }

                prepare_socket_bypass_mangle(sock.as_raw_fd()).await?;
            }

            #[cfg(not(target_os = "linux"))]
            let _ = inbound_proto; // Suppress unused variable warning

            let sock_addr = resolve_target_addr(context.dst_addr.clone()).await?;
            return timeout(Duration::from_millis(TIMEOUT), sock.connect(sock_addr)).await?;
        }

        let proxy_url = outbound.url.as_ref().unwrap();
        match proxy_url.scheme() {
            "drop" => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Connection dropped",
                ))
            }
            "socks" | "socks5" => {
                let socks_server = format!(
                    "{}:{}",
                    proxy_url.host_str().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proxy host")
                    })?,
                    proxy_url.port_or_known_default().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proxy port")
                    })?
                );

                let target_addr = match &context.dst_addr {
                    TargetAddr::Ip(dst_sock) => dst_sock.ip().to_string(),
                    TargetAddr::Domain(domain, _, _) => domain.to_owned(),
                };
                let target_port = match context.dst_addr {
                    TargetAddr::Ip(dst_sock) => dst_sock.port(),
                    TargetAddr::Domain(_, port, _) => port,
                };

                let sock = if proxy_url.username().is_empty() {
                    let fut = socks_client::Socks5Stream::connect(
                        socks_server,
                        target_addr,
                        target_port,
                        socks_client::Config::default(),
                    );
                    timeout(Duration::from_millis(TIMEOUT), fut)
                        .await?
                        .map_err(to_io_err)?
                } else {
                    let fut = socks_client::Socks5Stream::connect_with_password(
                        socks_server,
                        target_addr,
                        target_port,
                        proxy_url.username().to_string(),
                        proxy_url.password().unwrap_or("").to_string(),
                        socks_client::Config::default(),
                    );
                    timeout(Duration::from_millis(TIMEOUT), fut)
                        .await?
                        .map_err(to_io_err)?
                };
                Ok(sock.get_socket())
            }
            scheme => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("unsupported proxy scheme: {}", scheme),
            )),
        }
    }

    pub async fn get_dgram_sock(
        &self,
        context: &RouteContext,
    ) -> tokio::io::Result<Box<dyn ProxyDgram>> {
        let start = Instant::now();
        let outbound_index = self.match_route(context)?;
        let outbound = &self.outbounds[outbound_index as usize];
        let duration = start.elapsed();
        info!(
            "{} -> Outbound({}){}",
            context,
            outbound.name,
            if get_settings().read().await.debug {
                format!(", time: {}us", duration.as_micros())
            } else {
                "".to_owned()
            },
        );

        if outbound.url.is_none() {
            let raw_sock = socket2::Socket::new(
                match get_settings().read().await.disable_ipv6 {
                    false => socket2::Domain::IPV6,
                    true => socket2::Domain::IPV4,
                },
                socket2::Type::DGRAM,
                None,
            )?;

            raw_sock.set_nonblocking(true)?;

            let inbound_proto = context.inbound_proto.as_ref().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "inbound_proto is None")
            })?;

            #[cfg(target_os = "linux")]
            if let InboundProtocol::TPROXY = inbound_proto {
                if let Some(bind_range) = &outbound.bind_range {
                    if let Ok(ipv6_net) = context.src_addr.ip().to_ipv6_net() {
                        if bind_range.contains(&ipv6_net) {
                            crate::tproxy::tproxy_bind_src(
                                SockRef::from(&raw_sock),
                                context.src_addr,
                            )?;
                        }
                    }
                }

                prepare_socket_bypass_mangle(raw_sock.as_raw_fd()).await?;
            }

            #[cfg(not(target_os = "linux"))]
            let _ = inbound_proto; // Suppress unused variable warning

            let sock = UdpSocket::from_std(unsafe {
                use std::os::fd::FromRawFd;
                std::net::UdpSocket::from_raw_fd(raw_sock.as_raw_fd())
            })?;

            core::mem::forget(raw_sock);
            return Ok(Box::new(sock));
        }

        let proxy_url = outbound.url.as_ref().unwrap();
        match proxy_url.scheme() {
            "drop" => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Connection dropped",
                ))
            }
            "socks" | "socks5" => {
                let socks_server = format!(
                    "{}:{}",
                    proxy_url.host_str().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proxy host")
                    })?,
                    proxy_url.port_or_known_default().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proxy port")
                    })?
                );

                let backing_socket = timeout(
                    Duration::from_millis(TIMEOUT),
                    TcpStream::connect(&socks_server),
                )
                .await??;

                let sock = if proxy_url.username().is_empty() {
                    let fut = socks_client::Socks5Datagram::bind(
                        backing_socket,
                        rfor_bind_addr().await,
                    );
                    timeout(Duration::from_millis(TIMEOUT), fut)
                        .await?
                        .map_err(to_io_err)?
                } else {
                    let fut = socks_client::Socks5Datagram::bind_with_password(
                        backing_socket,
                        rfor_bind_addr().await,
                        proxy_url.username(),
                        proxy_url.password().unwrap_or(""),
                    );
                    timeout(Duration::from_millis(TIMEOUT), fut)
                        .await?
                        .map_err(to_io_err)?
                };
                Ok(Box::new(sock))
            }
            scheme => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("unsupported proxy scheme: {}", scheme),
            )),
        }
    }
}

async fn resolve_target_addr(target: TargetAddr) -> tokio::io::Result<SocketAddr> {
    match target {
        TargetAddr::Ip(addr) => {
            let sock = match get_settings().read().await.disable_ipv6 {
                false => addr.to_ipv6_sockaddr(),
                true => addr,
            };
            Ok(sock)
        }
        TargetAddr::Domain(domain, port, osock) => {
            let sock = match osock {
                Some(sock) => sock,
                None => {
                    let sock = tokio::net::lookup_host((domain.as_str(), port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                format!("DNS lookup returned no results for {}:{}", domain, port),
                            )
                        })?;
                    match get_settings().read().await.disable_ipv6 {
                        false => sock.to_ipv6_sockaddr(),
                        true => sock,
                    }
                }
            };
            Ok(sock)
        }
    }
}

pub async fn prepare_socket_bypass_mangle(sockfd: i32) -> tokio::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::BorrowedFd;
        match &get_settings().read().await.intercept_mode {
            crate::settings::InterceptMode::TPROXY { direct_mark, .. }
            | crate::settings::InterceptMode::REDIRECT { direct_mark, .. } => {
                // Avoid local traffic looping
                // SAFETY: sockfd is a valid file descriptor for the duration of this call
                let fd = unsafe { BorrowedFd::borrow_raw(sockfd) };
                nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::Mark, &direct_mark)?;
            }
            crate::settings::InterceptMode::MANUAL => {}
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = sockfd; // Suppress unused variable warning
    }

    Ok(())
}

#[async_trait::async_trait]
pub trait ProxyDgram: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> tokio::io::Result<(usize, TargetAddr)>;
    async fn send_to(&self, buf: &[u8], target: TargetAddr) -> tokio::io::Result<usize>;
}

#[async_trait::async_trait]
impl ProxyDgram for UdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> tokio::io::Result<(usize, TargetAddr)> {
        self.recv_from(buf)
            .await
            .map(|(size, addr)| (size, TargetAddr::Ip(addr)))
    }

    async fn send_to(&self, buf: &[u8], target: TargetAddr) -> tokio::io::Result<usize> {
        match target {
            TargetAddr::Ip(addr) => self.send_to(buf, addr).await,
            TargetAddr::Domain(domain, port, osock) => {
                let sock = match osock {
                    Some(sock) => sock,
                    None => {
                        let sock = tokio::net::lookup_host((domain.as_str(), port))
                            .await?
                            .next()
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::NotFound,
                                    format!("DNS lookup returned no results for {}:{}", domain, port),
                                )
                            })?;
                        match get_settings().read().await.disable_ipv6 {
                            false => sock.to_ipv6_sockaddr(),
                            true => sock,
                        }
                    }
                };
                self.send_to(buf, sock).await
            }
        }
    }
}

#[async_trait::async_trait]
impl ProxyDgram for fast_socks5::client::Socks5Datagram<tokio::net::TcpStream> {
    async fn recv_from(&self, buf: &mut [u8]) -> tokio::io::Result<(usize, TargetAddr)> {
        let (size, addr) = self
            .recv_from(buf)
            .await
            .map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::NetworkUnreachable, e))?;
        Ok((
            size,
            match addr {
                fast_socks5::util::target_addr::TargetAddr::Ip(addr) => TargetAddr::Ip(addr),
                fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => {
                    TargetAddr::Domain(domain, port, None)
                }
            },
        ))
    }

    async fn send_to(&self, buf: &[u8], target: TargetAddr) -> tokio::io::Result<usize> {
        match target {
            TargetAddr::Ip(addr) => self.send_to(buf, addr).await,
            TargetAddr::Domain(domain, port, _) => self.send_to(buf, (domain.as_str(), port)).await,
        }
        .map_err(to_io_err)
    }
}
