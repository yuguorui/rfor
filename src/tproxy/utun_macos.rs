//! macOS `utun` interface management, routing table configuration, and
//! forwarded-only PF `route-to` control plane.
//!
//! Two interception modes share a single `utun` data plane:
//! - `local-traffic: true`: installs private/local bypass routes plus split
//!   default routes (`0.0.0.0/1`, `128.0.0.0/1`, and `::/1`, `8000::/1` when
//!   IPv6 egress exists) pointing at `utunX`. Outbound sockets created by `rfor`
//!   bind to the physical egress interface via `IP_BOUND_IF`/`IPV6_BOUND_IF` so
//!   upstream traffic never loops back into `utunX`.
//! - `local-traffic: false`: leaves host routes untouched and installs a
//!   `route-to (<utunX> ...)` rule inside PF anchor `rfor/<chain>`, capturing
//!   only forwarded packets arriving on non-loopback interfaces.

use anyhow::{anyhow, Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use nix::libc;
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Output, Stdio};
use std::sync::RwLock;

use crate::settings::BypassCidrs;

pub const UTUN_MTU: u16 = 1500;
const UTUN_V4_LOCAL: &str = "198.19.254.1";
const UTUN_V4_PEER: &str = "198.19.254.2";
const UTUN_V6_LOCAL: &str = "fd72:666f:7200::1";
const UTUN_V6_PEER: &str = "fd72:666f:7200::2";

const ANCHOR_PARENT: &str = "rfor";

const AF_SYSTEM: libc::c_int = 32;
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: u16 = 2;
const UTUN_OPT_IFNAME: libc::c_int = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
// _IOWR('N', 3, struct ctl_info) where sizeof(struct ctl_info) == 100
const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;

const IP_BOUND_IF: libc::c_int = 25;
const IPV6_BOUND_IF: libc::c_int = 125;

const BYPASS_V4_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
];

const BYPASS_V6_CIDRS: &[&str] = &["fc00::/7"];

const RESERVED_PF_V4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

const RESERVED_PF_V6: &[&str] = &[
    "::/128",
    "::1/128",
    "100::/64",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "::ffff:0:0/96",
    "::ffff:0:0:0/96",
];

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InstalledRoute {
    InetNet { cidr: String, gateway: String },
    InetHostInterface { host: String, iface: String },
    InetInterface { cidr: String, iface: String },
    InetScopedDefault { iface: String, gateway: String },
    Inet6Net { cidr: String, gateway: String },
    Inet6Interface { cidr: String, iface: String },
    Inet6ScopedDefault { iface: String, gateway: String },
}

impl InstalledRoute {
    fn add_args(&self) -> Vec<String> {
        self.args("add")
    }

    fn delete_args(&self) -> Vec<String> {
        self.args("delete")
    }

    fn args(&self, op: &str) -> Vec<String> {
        let mut args = vec!["-n".to_owned(), op.to_owned()];
        let include_iface = op == "add";
        match self {
            InstalledRoute::InetNet { cidr, gateway } => {
                args.extend(["-net".to_owned(), cidr.clone(), gateway.clone()]);
            }
            InstalledRoute::InetHostInterface { host, iface } => {
                args.extend(["-host".to_owned(), host.clone()]);
                if include_iface {
                    args.extend(["-interface".to_owned(), iface.clone()]);
                }
            }
            InstalledRoute::InetInterface { cidr, iface } => {
                args.extend(["-net".to_owned(), cidr.clone()]);
                if include_iface {
                    args.extend(["-interface".to_owned(), iface.clone()]);
                }
            }
            InstalledRoute::InetScopedDefault { iface, gateway } => {
                args.extend([
                    "-inet".to_owned(),
                    "-ifscope".to_owned(),
                    iface.clone(),
                    "default".to_owned(),
                    gateway.clone(),
                ]);
            }
            InstalledRoute::Inet6Net { cidr, gateway } => {
                args.extend(["-inet6".to_owned(), cidr.clone(), gateway.clone()]);
            }
            InstalledRoute::Inet6Interface { cidr, iface } => {
                args.extend(["-inet6".to_owned(), cidr.clone()]);
                if include_iface {
                    args.extend(["-interface".to_owned(), iface.clone()]);
                }
            }
            InstalledRoute::Inet6ScopedDefault { iface, gateway } => {
                args.extend([
                    "-inet6".to_owned(),
                    "-ifscope".to_owned(),
                    iface.clone(),
                    "default".to_owned(),
                    gateway.clone(),
                ]);
            }
        }
        args
    }
}

#[derive(Debug, Default)]
struct ActiveState {
    local_traffic: bool,
    egress_v4_ifindex: Option<u32>,
    egress_v6_ifindex: Option<u32>,
    installed_routes: Vec<InstalledRoute>,
    pf_anchor: Option<String>,
    pf_token: Option<String>,
}

static ACTIVE_STATE: RwLock<Option<ActiveState>> = RwLock::new(None);

/// Return the egress interface index to bind outbound sockets onto when
/// `local-traffic: true` split-default routes are active.
pub(crate) fn egress_ifindex(is_ipv4: bool) -> Option<u32> {
    let guard = ACTIVE_STATE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = guard.as_ref()?;
    if !state.local_traffic {
        return None;
    }
    if is_ipv4 {
        state.egress_v4_ifindex
    } else {
        state.egress_v6_ifindex
    }
}

/// Pin outbound sockets to `iface_name` via `IP_BOUND_IF`/`IPV6_BOUND_IF`
/// when running without `utun` (for example, a local upstream SOCKS5
/// instance running alongside `local-traffic: true` split-default routes).
pub(crate) fn configure_manual_egress(iface_name: &str) -> Result<()> {
    let ifindex = nix::net::if_::if_nametoindex(iface_name)
        .with_context(|| format!("failed to resolve egress interface '{}'", iface_name))?;
    let state = ActiveState {
        local_traffic: true,
        egress_v4_ifindex: Some(ifindex),
        egress_v6_ifindex: Some(ifindex),
        installed_routes: Vec::new(),
        pf_anchor: None,
        pf_token: None,
    };
    *ACTIVE_STATE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(state);
    Ok(())
}

/// Bind a socket to `ifindex` via `IP_BOUND_IF` or `IPV6_BOUND_IF` so packets
/// bypass the `utun` split-default routes.
pub(crate) fn bind_socket_to_ifindex(
    sockfd: i32,
    is_ipv4: bool,
    ifindex: u32,
) -> std::io::Result<()> {
    let (level, option) = if is_ipv4 {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    };
    let ret = unsafe {
        libc::setsockopt(
            sockfd,
            level,
            option,
            &ifindex as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn parse_utun_unit(name: &str) -> Result<u32> {
    let suffix = name
        .strip_prefix("utun")
        .ok_or_else(|| anyhow!("invalid utun-name '{}': expected format utun<N>", name))?;
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!(
            "invalid utun-name '{}': expected format utun<N>",
            name
        ));
    }
    let unit: u32 = suffix
        .parse()
        .with_context(|| format!("invalid utun unit number in '{}'", name))?;
    unit.checked_add(1)
        .ok_or_else(|| anyhow!("utun unit number overflow in '{}'", name))
}

fn set_nonblocking_cloexec(fd: i32) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        if fd_flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn open_utun(requested_name: Option<&str>) -> Result<(OwnedFd, String)> {
    let sc_unit = match requested_name {
        Some(name) => parse_utun_unit(name)?,
        None => 0,
    };

    let raw_fd = unsafe { libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create AF_SYSTEM utun socket");
    }
    // Wrap immediately so Drop closes the descriptor on any error below.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0; 96],
    };
    info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);

    let ioctl_ret = unsafe { libc::ioctl(owned_fd.as_raw_fd(), CTLIOCGINFO, &mut info) };
    if ioctl_ret < 0 {
        return Err(std::io::Error::last_os_error())
            .context("CTLIOCGINFO failed for com.apple.net.utun_control");
    }

    let addr = SockaddrCtl {
        sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
        sc_family: AF_SYSTEM as u8,
        ss_sysaddr: AF_SYS_CONTROL,
        sc_id: info.ctl_id,
        sc_unit,
        sc_reserved: [0; 5],
    };

    let conn_ret = unsafe {
        libc::connect(
            owned_fd.as_raw_fd(),
            &addr as *const SockaddrCtl as *const libc::sockaddr,
            std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
        )
    };
    if conn_ret < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to connect utun control socket");
    }

    let mut ifname_buf = [0u8; 64];
    let mut ifname_len = ifname_buf.len() as libc::socklen_t;
    let opt_ret = unsafe {
        libc::getsockopt(
            owned_fd.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            ifname_buf.as_mut_ptr() as *mut libc::c_void,
            &mut ifname_len,
        )
    };
    if opt_ret < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to query utun interface name (UTUN_OPT_IFNAME)");
    }

    let used_len = (ifname_len as usize).min(ifname_buf.len());
    let ifname = CStr::from_bytes_until_nul(&ifname_buf[..used_len])
        .ok()
        .and_then(|s| s.to_str().ok())
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("kernel returned invalid utun interface name"))?;

    set_nonblocking_cloexec(owned_fd.as_raw_fd()).context("failed to configure utun fd flags")?;

    Ok((owned_fd, ifname))
}

fn run_cmd(program: &str, args: &[String]) -> Result<Output> {
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {} {}", program, args.join(" ")))
}

fn run_cmd_ok(program: &str, args: &[String]) -> Result<()> {
    let output = run_cmd(program, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(anyhow!("{} {} failed: {}", program, args.join(" "), msg));
    }
    Ok(())
}

fn configure_utun_interface(utun_name: &str, disable_ipv6: bool) -> Result<()> {
    run_cmd_ok(
        "ifconfig",
        &[
            utun_name.to_owned(),
            "inet".to_owned(),
            UTUN_V4_LOCAL.to_owned(),
            UTUN_V4_PEER.to_owned(),
            "netmask".to_owned(),
            "255.255.255.255".to_owned(),
            "mtu".to_owned(),
            UTUN_MTU.to_string(),
            "up".to_owned(),
        ],
    )?;

    if !disable_ipv6 {
        run_cmd_ok(
            "ifconfig",
            &[
                utun_name.to_owned(),
                "inet6".to_owned(),
                UTUN_V6_LOCAL.to_owned(),
                "prefixlen".to_owned(),
                "64".to_owned(),
                "up".to_owned(),
            ],
        )?;
    }

    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RouteGetInfo {
    interface: Option<String>,
    gateway: Option<String>,
}

fn parse_route_get_output(output: &str) -> RouteGetInfo {
    let mut info = RouteGetInfo::default();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let val = rest.trim();
            if !val.is_empty() {
                info.interface = Some(val.to_owned());
            }
        } else if let Some(rest) = trimmed.strip_prefix("gateway:") {
            let val = rest.trim();
            if !val.is_empty() {
                info.gateway = Some(val.to_owned());
            }
        }
    }
    info
}

#[derive(Debug)]
struct EgressInfo {
    v4_ifname: String,
    v4_ifindex: u32,
    v4_gateway: Option<String>,
    v6_ifname: Option<String>,
    v6_ifindex: Option<u32>,
    v6_gateway: Option<String>,
}

fn route_get(args: &[&str]) -> Result<Option<RouteGetInfo>> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let output = run_cmd("route", &owned)?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(parse_route_get_output(&String::from_utf8_lossy(
        &output.stdout,
    ))))
}

fn detect_egress(
    override_if: Option<&str>,
    utun_name: &str,
    disable_ipv6: bool,
) -> Result<EgressInfo> {
    let v4_query = match override_if {
        Some(ifname) => route_get(&["-n", "get", "-ifscope", ifname, "default"])?
            .or(route_get(&["-n", "get", "default"])?),
        None => route_get(&["-n", "get", "default"])?,
    };

    let (v4_ifname, v4_gateway) = match override_if {
        Some(ifname) => {
            let gw = v4_query.and_then(|q| {
                if q.interface.as_deref() == Some(ifname) {
                    q.gateway
                } else {
                    None
                }
            });
            (ifname.to_owned(), gw)
        }
        None => {
            let q = v4_query.ok_or_else(|| {
                anyhow!("failed to determine default IPv4 route; set traffic-intercept.egress-interface explicitly")
            })?;
            let iface = q.interface.ok_or_else(|| {
                anyhow!("default IPv4 route has no interface; set traffic-intercept.egress-interface explicitly")
            })?;
            (iface, q.gateway)
        }
    };

    if v4_ifname == utun_name {
        return Err(anyhow!(
            "egress interface '{}' cannot be the rfor utun device itself",
            v4_ifname
        ));
    }

    let v4_ifindex = nix::net::if_::if_nametoindex(v4_ifname.as_str())
        .with_context(|| format!("failed to resolve interface index for '{}'", v4_ifname))?;

    let (v6_ifname, v6_ifindex, v6_gateway) = if !disable_ipv6 {
        let v6_query = match override_if {
            Some(ifname) => route_get(&["-n", "get", "-inet6", "-ifscope", ifname, "default"])?
                .or(route_get(&["-n", "get", "-inet6", "default"])?),
            None => route_get(&["-n", "get", "-inet6", "default"])?,
        };
        match v6_query {
            Some(q) => {
                let candidate_if = match override_if {
                    Some(ifname) => Some(ifname.to_owned()),
                    None => q.interface.clone(),
                };
                if let Some(iface) = candidate_if.filter(|name| name != utun_name) {
                    if let Ok(idx) = nix::net::if_::if_nametoindex(iface.as_str()) {
                        let gw = if q.interface.as_deref() == Some(iface.as_str()) {
                            q.gateway
                        } else {
                            None
                        };
                        (Some(iface), Some(idx), gw)
                    } else {
                        (None, None, None)
                    }
                } else {
                    (None, None, None)
                }
            }
            None => (None, None, None),
        }
    } else {
        (None, None, None)
    };

    Ok(EgressInfo {
        v4_ifname,
        v4_ifindex,
        v4_gateway,
        v6_ifname,
        v6_ifindex,
        v6_gateway,
    })
}

fn is_already_exists_error(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr.contains("File exists")
        || stdout.contains("File exists")
        || stderr.contains("in table")
        || stdout.contains("in table")
}

fn is_not_in_table_error(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr.contains("not in table") || stdout.contains("not in table")
}

fn try_install_optional_route(
    installed: &mut Vec<InstalledRoute>,
    route: InstalledRoute,
) -> Result<()> {
    let args = route.add_args();
    let output = run_cmd("route", &args)?;
    if output.status.success() {
        installed.push(route);
        return Ok(());
    }
    if is_already_exists_error(&output) {
        return Ok(());
    }
    // Optional bypass routes may fail on link-only or unroutable configs; log
    // only via caller or return error? Private bypass routes are important for
    // LAN/SSH reachability when a gateway exists, so surface unexpected errors.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "route {} failed: {}",
        args.join(" "),
        if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        }
    ))
}

fn install_required_route(
    installed: &mut Vec<InstalledRoute>,
    route: InstalledRoute,
) -> Result<()> {
    run_cmd_ok("route", &route.add_args())?;
    installed.push(route);
    Ok(())
}

fn delete_routes(routes: &[InstalledRoute]) {
    for route in routes.iter().rev() {
        if let Ok(output) = run_cmd("route", &route.delete_args()) {
            if !output.status.success() && !is_not_in_table_error(&output) {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(
                    "failed to delete route ({}): {}",
                    route.delete_args().join(" "),
                    stderr.trim()
                );
            }
        }
    }
}

fn on_link_subnets(
    exclude_iface: &str,
) -> Result<(Vec<(String, Ipv4Net)>, Vec<(String, Ipv6Net)>)> {
    use nix::sys::socket::{AddressFamily, SockaddrLike};

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for interface in nix::ifaddrs::getifaddrs()? {
        if interface.interface_name == exclude_iface {
            continue;
        }
        let (Some(address), Some(netmask)) = (interface.address, interface.netmask) else {
            continue;
        };
        match address.family() {
            Some(AddressFamily::Inet) => {
                if let (Some(addr), Some(mask)) =
                    (address.as_sockaddr_in(), netmask.as_sockaddr_in())
                {
                    if let Ok(net) = Ipv4Net::with_netmask(addr.ip(), mask.ip()) {
                        let net = net.trunc();
                        if net.prefix_len() > 1 && net.prefix_len() < 32 {
                            v4.push((interface.interface_name, net));
                        }
                    }
                }
            }
            Some(AddressFamily::Inet6) => {
                if let (Some(addr), Some(mask)) =
                    (address.as_sockaddr_in6(), netmask.as_sockaddr_in6())
                {
                    let ip = addr.ip();
                    // Skip link-local addresses (fe80::/10) where BSD kernels embed scope IDs.
                    if (ip.segments()[0] & 0xffc0) == 0xfe80 {
                        continue;
                    }
                    if let Ok(net) = Ipv6Net::with_netmask(ip, mask.ip()) {
                        let net = net.trunc();
                        if net.prefix_len() > 1 && net.prefix_len() < 128 {
                            v6.push((interface.interface_name, net));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok((v4, v6))
}

fn is_kernel_special_v4(net: Ipv4Net) -> bool {
    const SPECIAL: &[&str] = &[
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ];
    SPECIAL.iter().any(|cidr| {
        cidr.parse::<Ipv4Net>()
            .map(|special| special.contains(&net))
            .unwrap_or(false)
    })
}

fn is_kernel_special_v6(net: Ipv6Net) -> bool {
    const SPECIAL: &[&str] = &["::/128", "::1/128", "fe80::/10", "ff00::/8"];
    SPECIAL.iter().any(|cidr| {
        cidr.parse::<Ipv6Net>()
            .map(|special| special.contains(&net))
            .unwrap_or(false)
    })
}

fn build_local_bypass_cidrs<N>(
    defaults: &[&str],
    extra: &[String],
    on_link: &[N],
    trunc: fn(&N) -> N,
    prefix_len: fn(N) -> u8,
    is_special: fn(N) -> bool,
    contains: fn(&N, &N) -> bool,
) -> Vec<N>
where
    N: std::str::FromStr + Copy + Eq,
{
    let mut out = Vec::new();
    for raw in defaults
        .iter()
        .copied()
        .chain(extra.iter().map(String::as_str))
    {
        let Ok(parsed) = raw.parse::<N>() else {
            continue;
        };
        let net = trunc(&parsed);
        if prefix_len(net) <= 1 || is_special(net) {
            continue;
        }
        // Skip bypass routes covered by an already-existing on-link UCS subnet
        // route, while allowing supernets (such as 30.0.0.0/8 over 30.221.96.0/19).
        if on_link
            .iter()
            .any(|subnet| prefix_len(*subnet) > 1 && contains(subnet, &net))
        {
            continue;
        }
        if !out.contains(&net) {
            out.push(net);
        }
    }
    out
}

fn build_local_v4_bypass_cidrs(extra_v4: &[String], on_link_v4: &[Ipv4Net]) -> Vec<Ipv4Net> {
    build_local_bypass_cidrs(
        BYPASS_V4_CIDRS,
        extra_v4,
        on_link_v4,
        Ipv4Net::trunc,
        |n| n.prefix_len(),
        is_kernel_special_v4,
        |subnet, net| subnet.contains(net),
    )
}

fn build_local_v6_bypass_cidrs(extra_v6: &[String], on_link_v6: &[Ipv6Net]) -> Vec<Ipv6Net> {
    build_local_bypass_cidrs(
        BYPASS_V6_CIDRS,
        extra_v6,
        on_link_v6,
        Ipv6Net::trunc,
        |n| n.prefix_len(),
        is_kernel_special_v6,
        |subnet, net| subnet.contains(net),
    )
}

fn gateway_needs_host_route(
    gw: Ipv4Addr,
    bypass_v4: &[Ipv4Net],
    egress_on_link_v4: &[Ipv4Net],
) -> bool {
    !gw.is_link_local()
        && !egress_on_link_v4.iter().any(|s| s.contains(&gw))
        && !bypass_v4.iter().any(|s| s.contains(&gw))
}

fn setup_local_routes(
    utun_name: &str,
    egress: &EgressInfo,
    bypass_cidrs: &BypassCidrs,
) -> Result<Vec<InstalledRoute>> {
    let (iface_v4, iface_v6) = on_link_subnets(utun_name)?;
    let all_on_link_v4: Vec<Ipv4Net> = iface_v4.iter().map(|(_, net)| *net).collect();
    let egress_on_link_v4: Vec<Ipv4Net> = iface_v4
        .iter()
        .filter(|(iface, _)| iface == &egress.v4_ifname)
        .map(|(_, net)| *net)
        .collect();
    let all_on_link_v6: Vec<Ipv6Net> = iface_v6.iter().map(|(_, net)| *net).collect();

    let v4_bypass = build_local_v4_bypass_cidrs(&bypass_cidrs.v4, &all_on_link_v4);
    let v6_bypass = build_local_v6_bypass_cidrs(&bypass_cidrs.v6, &all_on_link_v6);

    let mut installed = Vec::new();
    let res = (|| -> Result<()> {
        if let Some(gw4) = egress.v4_gateway.as_deref() {
            // Ensure an interface-scoped default route exists for the physical
            // egress interface so sockets bound via IP_BOUND_IF still resolve
            // a route once 0.0.0.0/1 and 128.0.0.0/1 point at utun.
            try_install_optional_route(
                &mut installed,
                InstalledRoute::InetScopedDefault {
                    iface: egress.v4_ifname.clone(),
                    gateway: gw4.to_owned(),
                },
            )?;

            for net in &v4_bypass {
                try_install_optional_route(
                    &mut installed,
                    InstalledRoute::InetNet {
                        cidr: net.to_string(),
                        gateway: gw4.to_owned(),
                    },
                )?;
            }

            if let Ok(gw_ip) = gw4.parse::<Ipv4Addr>() {
                if gateway_needs_host_route(gw_ip, &v4_bypass, &egress_on_link_v4) {
                    try_install_optional_route(
                        &mut installed,
                        InstalledRoute::InetHostInterface {
                            host: gw4.to_owned(),
                            iface: egress.v4_ifname.clone(),
                        },
                    )?;
                }
            }
        }

        install_required_route(
            &mut installed,
            InstalledRoute::InetInterface {
                cidr: "0.0.0.0/1".to_owned(),
                iface: utun_name.to_owned(),
            },
        )?;
        install_required_route(
            &mut installed,
            InstalledRoute::InetInterface {
                cidr: "128.0.0.0/1".to_owned(),
                iface: utun_name.to_owned(),
            },
        )?;

        if egress.v6_ifindex.is_some() {
            if let (Some(ifname6), Some(gw6)) =
                (egress.v6_ifname.as_deref(), egress.v6_gateway.as_deref())
            {
                if let Err(err) = try_install_optional_route(
                    &mut installed,
                    InstalledRoute::Inet6ScopedDefault {
                        iface: ifname6.to_owned(),
                        gateway: gw6.to_owned(),
                    },
                ) {
                    tracing::warn!("failed to install IPv6 scoped default route: {err:#}");
                }
                for net in &v6_bypass {
                    if let Err(err) = try_install_optional_route(
                        &mut installed,
                        InstalledRoute::Inet6Net {
                            cidr: net.to_string(),
                            gateway: gw6.to_owned(),
                        },
                    ) {
                        tracing::warn!("failed to install IPv6 bypass route {}: {err:#}", net);
                    }
                }
            }

            install_required_route(
                &mut installed,
                InstalledRoute::Inet6Interface {
                    cidr: "::/1".to_owned(),
                    iface: utun_name.to_owned(),
                },
            )?;
            install_required_route(
                &mut installed,
                InstalledRoute::Inet6Interface {
                    cidr: "8000::/1".to_owned(),
                    iface: utun_name.to_owned(),
                },
            )?;
        }

        Ok(())
    })();

    if let Err(err) = res {
        delete_routes(&installed);
        return Err(err);
    }

    Ok(installed)
}

fn sanitize_anchor_suffix(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect();
    if sanitized.is_empty() {
        "rfor".to_owned()
    } else {
        sanitized
    }
}

fn anchor_name(chain: &str) -> String {
    format!("{ANCHOR_PARENT}/{}", sanitize_anchor_suffix(chain))
}

fn validate_ports(ports: &str) -> Result<()> {
    if !ports
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, ',' | ':'))
    {
        return Err(anyhow!(
            "invalid traffic-intercept.ports value for macOS pf: {ports}"
        ));
    }
    Ok(())
}

fn local_addresses() -> Result<(Vec<String>, Vec<String>)> {
    use nix::sys::socket::{AddressFamily, SockaddrLike};

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for interface in nix::ifaddrs::getifaddrs()? {
        let Some(address) = interface.address else {
            continue;
        };
        match address.family() {
            Some(AddressFamily::Inet) => {
                if let Some(addr) = address.as_sockaddr_in() {
                    v4.push(format!("{}/32", addr.ip()));
                }
            }
            Some(AddressFamily::Inet6) => {
                if let Some(addr) = address.as_sockaddr_in6() {
                    v6.push(format!("{}/128", addr.ip()));
                }
            }
            _ => {}
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    Ok((v4, v6))
}

fn pf_table(entries: impl IntoIterator<Item = String>) -> String {
    let entries: Vec<String> = entries.into_iter().collect();
    format!("{{ {} }}", entries.join(", "))
}

fn render_pf_rules(
    utun_name: &str,
    ports: &str,
    disable_ipv6: bool,
    udp_enable: bool,
    local_v4: &[String],
    local_v6: &[String],
    bypass_cidrs: &BypassCidrs,
) -> Result<String> {
    use std::fmt::Write as _;

    validate_ports(ports)?;

    let v4 = bypass_cidrs.merged_v4(RESERVED_PF_V4, local_v4);
    let v6 = bypass_cidrs.merged_v6(RESERVED_PF_V6, local_v6);

    let port_clause = if ports.trim().is_empty() {
        String::new()
    } else {
        format!(" port {{ {ports} }}")
    };

    let mut rules = String::new();
    writeln!(rules, "# rfor macOS forwarded PF anchor")?;
    writeln!(rules, "table <rfor_np4> {}", pf_table(v4))?;
    if !disable_ipv6 {
        writeln!(rules, "table <rfor_np6> {}", pf_table(v6))?;
    }
    // Reply packets injected by rfor back through utun must never be re-routed.
    writeln!(rules, "pass in quick on {utun_name} all no state")?;

    let mut protos = vec!["tcp"];
    if udp_enable {
        protos.push("udp");
    }

    for proto in &protos {
        writeln!(
            rules,
            "pass in quick on !lo0 route-to ({utun_name} {UTUN_V4_PEER}) inet proto {proto} from any to !<rfor_np4>{port_clause} no state"
        )?;
        if !disable_ipv6 {
            writeln!(
                rules,
                "pass in quick on !lo0 route-to ({utun_name} {UTUN_V6_PEER}) inet6 proto {proto} from any to !<rfor_np6>{port_clause} no state"
            )?;
        }
    }

    Ok(rules)
}

fn pfctl(args: &[&str], stdin: Option<&str>) -> Result<Output> {
    let mut command = Command::new("pfctl");
    command.args(args);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .context("failed to execute pfctl; is pf available?")?;
    if let Some(input) = stdin {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to open pfctl stdin"))?
            .write_all(input.as_bytes())
            .context("failed to write pf rules to pfctl")?;
    }
    child.wait_with_output().context("failed to wait for pfctl")
}

fn pfctl_error(args: &[&str], output: &Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    anyhow!("pfctl {} failed: {}", args.join(" "), detail)
}

fn ensure_anchor_reference(anchor: &str) -> Result<()> {
    let output = pfctl(&["-sr"], None)?;
    if !output.status.success() {
        return Err(pfctl_error(&["-sr"], &output));
    }

    let exact = format!("anchor \"{anchor}\"");
    let wildcard = format!("anchor \"{ANCHOR_PARENT}/*\"");
    let referenced = String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
        normalized.starts_with(&exact) || normalized.starts_with(&wildcard)
    });
    if !referenced {
        return Err(anyhow!(
            "pf is not evaluating the rfor anchor; add 'anchor \"rfor/*\"' to /etc/pf.conf and reload pf with 'pfctl -f /etc/pf.conf'"
        ));
    }
    Ok(())
}

fn parse_pf_enable_token(output: &Output) -> Option<String> {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in combined.lines() {
        let trimmed = line.trim();
        if let Some((_, rest)) = trimmed.split_once("Token") {
            if let Some((_, token)) = rest.split_once(':') {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token.to_owned());
                }
            }
        }
    }
    None
}

fn enable_pf_with_token() -> Result<String> {
    let output = pfctl(&["-E"], None)?;
    if !output.status.success() {
        return Err(pfctl_error(&["-E"], &output));
    }
    parse_pf_enable_token(&output).ok_or_else(|| {
        anyhow!(
            "pfctl -E did not return a reference token (stdout='{}', stderr='{}')",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })
}

fn release_pf_token(token: &str) {
    let _ = pfctl(&["-X", token], None);
}

fn flush_anchor(anchor: &str) {
    let _ = pfctl(&["-a", anchor, "-F", "all"], None);
}

fn setup_forwarded_pf(
    utun_name: &str,
    ports: &str,
    chain: &str,
    disable_ipv6: bool,
    udp_enable: bool,
    bypass_cidrs: &BypassCidrs,
) -> Result<(String, String)> {
    let anchor = anchor_name(chain);
    ensure_anchor_reference(&anchor)?;

    let (local_v4, local_v6) = local_addresses()?;
    let rules = render_pf_rules(
        utun_name,
        ports,
        disable_ipv6,
        udp_enable,
        &local_v4,
        &local_v6,
        bypass_cidrs,
    )?;

    let token = enable_pf_with_token()?;
    flush_anchor(&anchor);

    let load_res = (|| -> Result<()> {
        let load = pfctl(&["-a", &anchor, "-f", "-"], Some(&rules))?;
        if !load.status.success() {
            return Err(pfctl_error(&["-a", &anchor, "-f", "-"], &load));
        }

        let verify = pfctl(&["-a", &anchor, "-sr"], None)?;
        if !verify.status.success() {
            return Err(pfctl_error(&["-a", &anchor, "-sr"], &verify));
        }
        if String::from_utf8_lossy(&verify.stdout).trim().is_empty() {
            return Err(anyhow!("pf loaded no rules into anchor {anchor}"));
        }
        Ok(())
    })();

    if let Err(err) = load_res {
        flush_anchor(&anchor);
        release_pf_token(&token);
        return Err(err);
    }

    Ok((anchor, token))
}

/// Create and configure `utun` along with either split-default local routes
/// (`local_traffic: true`) or PF `route-to` anchor rules (`local_traffic: false`).
pub async fn setup(
    local_traffic: bool,
    ports: &str,
    utun_name_pref: Option<&str>,
    egress_interface: Option<&str>,
    chain: &str,
    disable_ipv6: bool,
    udp_enable: bool,
    bypass_cidrs: &BypassCidrs,
) -> Result<(OwnedFd, String)> {
    if crate::utils::geteuid() != 0 {
        return Err(anyhow!("must be root to create utun and configure macOS interception"));
    }

    cleanup().await?;

    let (utun_fd, utun_name) = open_utun(utun_name_pref)?;
    configure_utun_interface(&utun_name, disable_ipv6)?;

    if local_traffic {
        let egress = detect_egress(egress_interface, &utun_name, disable_ipv6)?;
        let installed_routes = setup_local_routes(&utun_name, &egress, bypass_cidrs)?;
        let state = ActiveState {
            local_traffic: true,
            egress_v4_ifindex: Some(egress.v4_ifindex),
            egress_v6_ifindex: egress.v6_ifindex,
            installed_routes,
            pf_anchor: None,
            pf_token: None,
        };
        *ACTIVE_STATE
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(state);
    } else {
        let (anchor, token) = setup_forwarded_pf(
            &utun_name,
            ports,
            chain,
            disable_ipv6,
            udp_enable,
            bypass_cidrs,
        )?;
        let state = ActiveState {
            local_traffic: false,
            egress_v4_ifindex: None,
            egress_v6_ifindex: None,
            installed_routes: Vec::new(),
            pf_anchor: Some(anchor),
            pf_token: Some(token),
        };
        *ACTIVE_STATE
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(state);
    }

    Ok((utun_fd, utun_name))
}

/// Remove installed routes and PF anchor/reference token idempotently.
pub async fn cleanup() -> Result<()> {
    let state = ACTIVE_STATE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();

    let Some(state) = state else {
        return Ok(());
    };

    if crate::utils::geteuid() != 0 {
        return Ok(());
    }

    if let Some(anchor) = state.pf_anchor.as_deref() {
        flush_anchor(anchor);
    }
    if let Some(token) = state.pf_token.as_deref() {
        release_pf_token(token);
    }
    if !state.installed_routes.is_empty() {
        delete_routes(&state.installed_routes);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_structs_match_xnu_abi_sizes() {
        assert_eq!(std::mem::size_of::<CtlInfo>(), 100);
        assert_eq!(std::mem::size_of::<SockaddrCtl>(), 32);
    }

    #[test]
    fn parses_utun_unit_numbers() {
        assert_eq!(parse_utun_unit("utun0").unwrap(), 1);
        assert_eq!(parse_utun_unit("utun12").unwrap(), 13);
        assert!(parse_utun_unit("utun").is_err());
        assert!(parse_utun_unit("tun0").is_err());
        assert!(parse_utun_unit("utun-1").is_err());
    }

    #[test]
    fn parses_route_get_outputs() {
        let v4 = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.64.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>";
        assert_eq!(
            parse_route_get_output(v4),
            RouteGetInfo {
                interface: Some("en0".to_owned()),
                gateway: Some("192.168.64.1".to_owned()),
            }
        );

        let v6 = "\
   route to: default
destination: default
    gateway: fe80::1%en0
  interface: en0";
        assert_eq!(
            parse_route_get_output(v6),
            RouteGetInfo {
                interface: Some("en0".to_owned()),
                gateway: Some("fe80::1%en0".to_owned()),
            }
        );
    }

    #[test]
    fn parses_pf_enable_token_from_stdout_or_stderr() {
        use std::os::unix::process::ExitStatusExt;

        let output = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: b"pf enabled\nToken : 17492837162\n".to_vec(),
        };
        assert_eq!(
            parse_pf_enable_token(&output).as_deref(),
            Some("17492837162")
        );
    }

    #[test]
    fn renders_pf_rules_for_forwarded_utun() {
        let bypass = BypassCidrs {
            v4: vec!["30.0.0.0/8".to_owned(), "29.29.29.29/32".to_owned()],
            v6: vec!["2001:db8:cafe::/48".to_owned()],
        };
        let rules = render_pf_rules(
            "utun9",
            "80,443,8080:8082",
            false,
            true,
            &["192.168.64.2/32".to_owned()],
            &["fd00::2/128".to_owned()],
            &bypass,
        )
        .unwrap();

        assert!(rules.contains("table <rfor_np4>"));
        assert!(rules.contains("table <rfor_np6>"));
        assert!(rules.contains("30.0.0.0/8"));
        assert!(rules.contains("29.29.29.29/32"));
        assert!(rules.contains("2001:db8:cafe::/48"));
        assert!(rules.contains("pass in quick on utun9 all no state"));
        assert!(rules.contains(
            "pass in quick on !lo0 route-to (utun9 198.19.254.2) inet proto tcp from any to !<rfor_np4> port { 80,443,8080:8082 } no state"
        ));
        assert!(rules.contains(
            "pass in quick on !lo0 route-to (utun9 198.19.254.2) inet proto udp from any to !<rfor_np4> port { 80,443,8080:8082 } no state"
        ));
        assert!(rules.contains(
            "pass in quick on !lo0 route-to (utun9 fd72:666f:7200::2) inet6 proto tcp from any to !<rfor_np6> port { 80,443,8080:8082 } no state"
        ));
    }

    #[test]
    fn renders_pf_rules_without_ports_ipv6_or_udp() {
        let rules = render_pf_rules(
            "utun4",
            "",
            true,
            false,
            &[],
            &[],
            &BypassCidrs::default(),
        )
        .unwrap();
        assert!(!rules.contains("inet6"));
        assert!(!rules.contains("proto udp"));
        assert!(!rules.contains("port {"));
        assert!(rules.contains("pass in quick on utun4 all no state"));
        assert!(rules.contains(
            "pass in quick on !lo0 route-to (utun4 198.19.254.2) inet proto tcp from any to !<rfor_np4> no state"
        ));
    }

    #[test]
    fn validates_pf_ports_against_injection() {
        assert!(validate_ports("80,443,8080:8082").is_ok());
        assert!(validate_ports("").is_ok());
        assert!(validate_ports("80 }\npass all").is_err());
    }

    #[test]
    fn anchor_name_is_bounded_and_safe() {
        assert_eq!(anchor_name("rfor-proxy"), "rfor/rforproxy");
        assert!(anchor_name(&"x".repeat(200)).len() < 32);
    }

    #[test]
    fn route_delete_omits_utun_interface_modifier() {
        let v4_split = InstalledRoute::InetInterface {
            cidr: "0.0.0.0/1".to_owned(),
            iface: "utun4".to_owned(),
        };
        assert_eq!(
            v4_split.add_args(),
            vec!["-n", "add", "-net", "0.0.0.0/1", "-interface", "utun4"]
        );
        assert_eq!(v4_split.delete_args(), vec!["-n", "delete", "-net", "0.0.0.0/1"]);

        let v4_host = InstalledRoute::InetHostInterface {
            host: "198.19.254.2".to_owned(),
            iface: "utun4".to_owned(),
        };
        assert_eq!(
            v4_host.delete_args(),
            vec!["-n", "delete", "-host", "198.19.254.2"]
        );

        let v6_split = InstalledRoute::Inet6Interface {
            cidr: "::/1".to_owned(),
            iface: "utun4".to_owned(),
        };
        assert_eq!(
            v6_split.delete_args(),
            vec!["-n", "delete", "-inet6", "::/1"]
        );

        let scoped = InstalledRoute::InetScopedDefault {
            iface: "en0".to_owned(),
            gateway: "192.168.64.1".to_owned(),
        };
        assert_eq!(
            scoped.delete_args(),
            vec!["-n", "delete", "-inet", "-ifscope", "en0", "default", "192.168.64.1"]
        );
    }

    #[test]
    fn manual_egress_resolves_loopback_and_rejects_missing_interface() {
        struct ClearActiveState;
        impl Drop for ClearActiveState {
            fn drop(&mut self) {
                *ACTIVE_STATE
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            }
        }

        let _guard = ClearActiveState;
        configure_manual_egress("lo0").expect("lo0 interface should resolve");
        let v4 = egress_ifindex(true).expect("v4 egress ifindex should be set");
        let v6 = egress_ifindex(false).expect("v6 egress ifindex should be set");
        assert!(v4 > 0);
        assert_eq!(v4, v6);

        drop(_guard);
        assert_eq!(egress_ifindex(true), None);
        assert!(configure_manual_egress("rfor_nonexistent_if99").is_err());
    }

    #[test]
    fn bypass_cidrs_preserve_kernel_special_and_on_link_subnets() {
        assert!(!BYPASS_V4_CIDRS.contains(&"169.254.0.0/16"));
        assert!(!BYPASS_V4_CIDRS.contains(&"224.0.0.0/4"));
        assert!(BYPASS_V4_CIDRS.contains(&"10.0.0.0/8"));
        assert!(BYPASS_V4_CIDRS.contains(&"172.16.0.0/12"));
        assert!(BYPASS_V4_CIDRS.contains(&"192.168.0.0/16"));
        assert!(BYPASS_V4_CIDRS.contains(&"100.64.0.0/10"));
        assert_eq!(BYPASS_V6_CIDRS, &["fc00::/7"]);

        let on_link_v4: Vec<Ipv4Net> = vec!["30.221.96.0/19".parse().unwrap()];
        let extra_v4 = vec![
            "30.0.0.0/8".to_owned(),
            "30.221.96.0/19".to_owned(),
            "30.221.100.0/24".to_owned(),
            "169.254.1.0/24".to_owned(),
            "224.0.0.0/4".to_owned(),
            "0.0.0.0/1".to_owned(),
            "10.0.0.0/8".to_owned(),
            "29.29.29.29/32".to_owned(),
        ];
        let built_v4 = build_local_v4_bypass_cidrs(&extra_v4, &on_link_v4);
        assert_eq!(
            built_v4,
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
                "100.64.0.0/10".parse().unwrap(),
                "30.0.0.0/8".parse().unwrap(),
                "29.29.29.29/32".parse().unwrap(),
            ]
        );

        let on_link_v6: Vec<Ipv6Net> = vec![
            "fd00:1:5:5180::/64".parse().unwrap(),
            "2001:db8:1::/64".parse().unwrap(),
        ];
        let extra_v6 = vec![
            "2001:db8::/32".to_owned(),
            "2001:db8:1::/64".to_owned(),
            "2001:db8:1:0:1::/80".to_owned(),
            "fe80::/10".to_owned(),
            "ff00::/8".to_owned(),
            "::1/128".to_owned(),
            "::/1".to_owned(),
            "2606:4700:4700::1111/128".to_owned(),
        ];
        let built_v6 = build_local_v6_bypass_cidrs(&extra_v6, &on_link_v6);
        assert_eq!(
            built_v6,
            vec![
                "fc00::/7".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
                "2606:4700:4700::1111/128".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn gateway_host_route_skips_on_link_and_bypassed_gateways() {
        let on_link_v4: Vec<Ipv4Net> = vec!["30.221.96.0/19".parse().unwrap()];
        let default_only = build_local_v4_bypass_cidrs(&[], &on_link_v4);
        assert!(!gateway_needs_host_route(
            Ipv4Addr::new(30, 221, 96, 1),
            &default_only,
            &on_link_v4
        ));
        assert!(!gateway_needs_host_route(
            Ipv4Addr::new(192, 168, 64, 1),
            &default_only,
            &on_link_v4
        ));
        assert!(!gateway_needs_host_route(
            Ipv4Addr::new(169, 254, 1, 1),
            &default_only,
            &on_link_v4
        ));
        assert!(gateway_needs_host_route(
            Ipv4Addr::new(203, 0, 113, 1),
            &default_only,
            &on_link_v4
        ));

        let with_gw_bypass = build_local_v4_bypass_cidrs(&["203.0.113.0/24".to_owned()], &[]);
        assert!(!gateway_needs_host_route(
            Ipv4Addr::new(203, 0, 113, 1),
            &with_gw_bypass,
            &[]
        ));
    }
}
