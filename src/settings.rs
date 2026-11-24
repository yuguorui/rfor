use std::collections::HashSet;

use clap::Parser;
use fqdn::FQDN;
use itertools::Itertools;
use serde::Serialize;
use tracing::warn;

use config::{Config, ConfigError, Environment, File};
use ipnet::IpNet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::rules::RouteTable;
use crate::utils::{vec_to_array, ToV6Net};

const DIRECT_OUTBOUND_NAME: &str = "DIRECT";
const DROP_OUTBOUND_NAME: &str = "DROP";
const DEFAULT_IPTABLES_PROXY_MARK: u32 = 0xff42;
const DEFAULT_IPTABLES_DIRECT_MARK: u32 = 0xff43;
const DEFAULT_IPTABLES_PROXY_CHAIN_NAME: &str = "rfor-proxy";
const DEFAULT_IPTABLES_MARK_CHAIN_NAME: &str = "rfor-mark";
const DEFAULT_IPRULE_TABLE: u8 = 0x42;
const DEFAULT_IPFW_RULE_BASE: u16 = 64000;

/// A simple but fast traffic forwarder with routing.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// config file filepath
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// working directory
    #[arg(short, long, default_value = ".")]
    work_dir: String,

    /// enable pprof
    #[arg(long, num_args(0..=1), default_missing_value = "flamegraph.svg")]
    pprof: Option<String>,
}

#[derive(Serialize)]
pub enum InterceptMode {
    TPROXY {
        local_traffic: bool,
        ports: String,
        proxy_mark: u32,
        direct_mark: u32,
        proxy_chain: String,
        mark_chain: String,
        rule_table_index: u8,
    },
    REDIRECT {
        local_traffic: bool,
        ports: String,
        direct_mark: u32,
        proxy_chain: String,
    },
    IPFW {
        local_traffic: bool,
        ports: String,
        rule_base: u16,
        proxy_chain: String,
    },
    PF {
        local_traffic: bool,
        ports: String,
        proxy_chain: String,
    },
    UTUN {
        local_traffic: bool,
        ports: String,
        utun_name: Option<String>,
        egress_interface: Option<String>,
        proxy_chain: String,
    },
    MANUAL,
}

#[derive(Serialize, Default, Clone, Debug, PartialEq, Eq)]
pub struct BypassCidrs {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

impl BypassCidrs {
    #[allow(dead_code)]
    pub(crate) fn merged_v4(&self, base: &[&str], local: &[String]) -> Vec<String> {
        merge_cidr_lists(base, local, &self.v4)
    }

    #[allow(dead_code)]
    pub(crate) fn merged_v6(&self, base: &[&str], local: &[String]) -> Vec<String> {
        merge_cidr_lists(base, local, &self.v6)
    }
}

#[allow(dead_code)]
fn merge_cidr_lists(base: &[&str], local: &[String], bypass: &[String]) -> Vec<String> {
    let mut out: Vec<String> = base.iter().map(|s| (*s).to_owned()).collect();
    out.extend(local.iter().cloned());
    out.extend(bypass.iter().cloned());
    out.sort();
    out.dedup();
    out
}

#[derive(Serialize)]
pub struct Settings {
    pub debug: bool,
    pub pprof: Option<String>,
    pub disable_ipv6: bool,
    pub tproxy_listen: Option<String>,
    pub socks5_listen: Option<String>,
    pub redirect_listen: Option<String>,
    #[serde(skip)]
    pub routetable: RouteTable,
    pub intercept_mode: InterceptMode,
    pub bypass_cidrs: BypassCidrs,
    pub egress_interface: Option<String>,
    pub udp_enable: bool,
    pub udp_timeout: u64,
    pub udp_fullcone: bool,
    /// Maximum number of sockets per fullcone session (0 = unlimited)
    pub udp_fullcone_max_sockets: usize,
    /// Per-socket idle timeout in fullcone mode (seconds)
    pub udp_fullcone_socket_timeout: u64,
    /// Maximum new fullcone connections per second per session (0 = unlimited)
    pub udp_fullcone_rate_limit: u32,
    /// Maximum number of concurrent UDP sessions (0 = unlimited)
    pub udp_max_sessions: usize,
    /// How to answer requests rejected by a DROP outbound, per protocol
    pub drop_reply: DropReply,
}

/// Per-protocol reply behavior for requests rejected by a DROP outbound.
/// Silent by default; extend with more protocols (e.g. tls: alert) as needed.
#[derive(Serialize, Default)]
pub struct DropReply {
    pub dns: DnsDropReply,
}

#[derive(Serialize, Default, Clone, Copy, PartialEq)]
pub enum DnsDropReply {
    #[default]
    Silent,
    Nxdomain,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        Self::load()
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).unwrap_or_else(|e| format!("<failed to serialize: {}>", e))
    }

    pub fn load() -> Result<Self, ConfigError> {
        let args = Args::parse();
        std::env::set_current_dir(&args.work_dir).map_err(|e| {
            ConfigError::Message(format!(
                "Failed to set working directory '{}': {}",
                args.work_dir, e
            ))
        })?;

        let s = Config::builder()
            .add_source(File::with_name(&args.config))
            .add_source(Environment::with_prefix("rfor"))
            .build()?;

        /* 1. Setup the initial rules object. */
        let mut route = RouteTable::new();

        /* 2. Parse the outbounds section */
        parse_outbounds(&s, &mut route)?;

        /* 3. Populate the DIRECT/DROP rule. */
        ensure_default_outbounds(&mut route)?;

        /* 4. Parse the actual rules. */
        parse_route_rules(&s, &mut route)?;

        /* 5. Parse the Intercept Mode */
        let intercept_mode = parse_intercept_mode(&s)?;
        let bypass_cidrs = parse_bypass_cidrs(&s)?;

        /* 6. Parse the UDP enabling */
        let udp_enable = match &intercept_mode {
            InterceptMode::TPROXY { .. }
            | InterceptMode::IPFW { .. }
            | InterceptMode::PF { .. }
            | InterceptMode::UTUN { .. }
            | InterceptMode::MANUAL => {
                // The canonical key is `udp-enabled`; keep `udp-enable` as a
                // deprecated alias so existing configs keep working.
                match (s.get_bool("udp-enabled"), s.get_bool("udp-enable")) {
                    (Ok(enabled), _) => enabled,
                    (Err(_), Ok(enabled)) => {
                        warn!("config key `udp-enable` is deprecated, use `udp-enabled` instead");
                        enabled
                    }
                    (Err(_), Err(_)) => true,
                }
            }
            InterceptMode::REDIRECT { .. } => {
                warn!("UDP is not supported in REDIRECT mode, disabling it.");
                false
            }
        };

        let pprof = if let Some(p) = args.pprof {
            Some(p)
        } else {
            // Check config
            if let Ok(path) = s.get::<String>("pprof") {
                Some(path)
            } else if let Ok(true) = s.get_bool("pprof") {
                Some("flamegraph.svg".to_string())
            } else {
                None
            }
        };

        let settings = Settings {
            debug: s.get_bool("debug").unwrap_or(false),
            pprof,
            disable_ipv6: s.get_bool("disable-ipv6").unwrap_or(false),
            tproxy_listen: s.get::<String>("tproxy-listen").ok(),
            socks5_listen: s.get::<String>("socks5-listen").ok(),
            redirect_listen: s.get::<String>("redirect-listen").ok(),
            routetable: route,
            intercept_mode,
            bypass_cidrs,
            egress_interface: parse_egress_interface(&s),
            udp_enable,
            udp_timeout: s.get_int("udp-timeout").unwrap_or(60) as u64,
            udp_fullcone: s.get_bool("udp-fullcone").unwrap_or(false),
            udp_fullcone_max_sockets: s.get_int("udp-fullcone-max-sockets").unwrap_or(64) as usize,
            udp_fullcone_socket_timeout: s.get_int("udp-fullcone-socket-timeout").unwrap_or(30)
                as u64,
            udp_fullcone_rate_limit: s.get_int("udp-fullcone-rate-limit").unwrap_or(10) as u32,
            udp_max_sessions: s.get_int("udp-max-sessions").unwrap_or(1024) as usize,
            drop_reply: parse_drop_reply(&s)?,
        };

        // Validate settings
        validate_settings(&settings)?;

        Ok(settings)
    }
}

fn parse_outbounds(s: &Config, route: &mut RouteTable) -> Result<(), ConfigError> {
    let outbounds = s.get_array("outbounds").unwrap_or_default();

    for outbound_value in outbounds {
        let outbound = outbound_value
            .into_table()
            .map_err(|e| ConfigError::Message(format!("Failed to parse outbound: {}", e)))?;

        let name = parse_required_field(&outbound, "name")?;

        let url = outbound
            .get("url")
            .and_then(|v| v.clone().into_string().ok().and_then(|s| s.parse().ok()));

        let bind_range = parse_bind_range(&outbound)?;

        route.add_empty_rule(name, url, bind_range);
    }

    Ok(())
}

fn parse_required_field(
    outbound: &std::collections::HashMap<String, config::Value>,
    field: &str,
) -> Result<String, ConfigError> {
    outbound
        .get(field)
        .and_then(|v| v.clone().into_string().ok())
        .ok_or_else(|| ConfigError::Message(format!("Missing required field: {}", field)))
}

fn parse_bind_range(
    outbound: &std::collections::HashMap<String, config::Value>,
) -> Result<Option<iprange::IpRange<ipnet::Ipv6Net>>, ConfigError> {
    if let Some(items) = outbound.get("bind_range") {
        let items = items
            .clone()
            .into_array()
            .map_err(|e| ConfigError::Message(format!("bind_range must be an array: {}", e)))?;

        let mut bind_range = iprange::IpRange::<ipnet::Ipv6Net>::new();

        for item in items {
            let cidr_str = item.into_string().map_err(|e| {
                ConfigError::Message(format!("bind_range item must be a string: {}", e))
            })?;

            let cidr = cidr_str.parse().map_err(|e| {
                ConfigError::Message(format!("Invalid bind_range CIDR '{}': {}", cidr_str, e))
            })?;

            bind_range.add(cidr);
        }

        Ok(Some(bind_range))
    } else {
        Ok(None)
    }
}

fn cidr_to_ipv6net(cidr: &crate::protos::common::CIDR) -> Option<ipnet::Ipv6Net> {
    match cidr.ip.len() {
        4 => vec_to_array::<u8, 4>(cidr.ip.clone()).and_then(|arr| {
            ipnet::Ipv6Net::new(
                Ipv4Addr::from(arr).to_ipv6_mapped(),
                cidr.prefix as u8 + (128 - 32),
            )
            .ok()
        }),
        16 => vec_to_array::<u8, 16>(cidr.ip.clone())
            .and_then(|arr| ipnet::Ipv6Net::new(Ipv6Addr::from(arr), cidr.prefix as u8).ok()),
        _ => None,
    }
}

fn ensure_default_outbounds(route: &mut RouteTable) -> Result<(), ConfigError> {
    if route.get_outbound_by_name(DIRECT_OUTBOUND_NAME).is_none() {
        route.add_empty_rule(DIRECT_OUTBOUND_NAME.to_owned(), None, None);
    }

    if route.get_outbound_by_name(DROP_OUTBOUND_NAME).is_none() {
        let drop_url: url::Url = "drop://0.0.0.0"
            .parse()
            .map_err(|e| ConfigError::Message(format!("Failed to parse drop URL: {}", e)))?;
        route.add_empty_rule(DROP_OUTBOUND_NAME.to_owned(), Some(drop_url), None);
    }

    Ok(())
}

fn validate_settings(settings: &Settings) -> Result<(), ConfigError> {
    // At least one listener should be configured (or macOS utun interception active)
    if settings.tproxy_listen.is_none()
        && settings.socks5_listen.is_none()
        && settings.redirect_listen.is_none()
        && !matches!(settings.intercept_mode, InterceptMode::UTUN { .. })
    {
        return Err(ConfigError::Message(
            "At least one listener (tproxy-listen, socks5-listen, or redirect-listen) must be configured.".to_string()
        ));
    }

    if matches!(
        settings.intercept_mode,
        InterceptMode::UTUN {
            local_traffic: true,
            ..
        }
    ) {
        for cidr in settings
            .bypass_cidrs
            .v4
            .iter()
            .chain(settings.bypass_cidrs.v6.iter())
        {
            if let Ok(net) = cidr.parse::<IpNet>() {
                if net.prefix_len() < 2 {
                    return Err(ConfigError::Message(format!(
                        "bypass-cidrs entry '{}' with prefix length < 2 conflicts with macOS utun split-default routes",
                        cidr
                    )));
                }
            }
        }
    }

    Ok(())
}

fn sanitize_port_ranges(s: &Vec<config::Value>) -> Result<Vec<[u16; 2]>, ConfigError> {
    let mut ranges = s
        .iter()
        .map(|v| {
            let v = v
                .clone()
                .into_string()
                .map_err(|e| ConfigError::Message(format!("port must be a string: {}", e)))?;
            if !v.contains("-") {
                let v = v.parse::<u16>().map_err(|e| {
                    ConfigError::Message(format!("port must contain a number: {}", e))
                })?;
                return Ok([v, v]);
            }

            let (start, end) = v
                .split("-")
                .collect_tuple::<(&str, &str)>()
                .ok_or_else(|| ConfigError::Message("port range must be start-end".to_string()))?;
            let start = start
                .parse::<u16>()
                .map_err(|e| ConfigError::Message(format!("start must be a number: {}", e)))?;
            let end = end
                .parse::<u16>()
                .map_err(|e| ConfigError::Message(format!("end must be a number: {}", e)))?;
            return Ok([start, end]);
        })
        .collect::<Result<Vec<_>, _>>()?;

    // reduce the ranges
    ranges.sort();
    let mut i = 0;
    while i + 1 < ranges.len() {
        if ranges[i][1] >= ranges[i + 1][0] {
            ranges[i][1] = ranges[i][1].max(ranges[i + 1][1]);
            ranges.remove(i + 1);
        } else {
            i += 1;
        }
    }
    Ok(ranges)
}

fn port_range_to_string(ranges: &[[u16; 2]]) -> String {
    ranges
        .iter()
        .map(|r| {
            if r[0] == r[1] {
                r[0].to_string()
            } else {
                format!("{}:{}", r[0], r[1])
            }
        })
        .join(",")
}

fn parse_drop_reply(s: &Config) -> Result<DropReply, ConfigError> {
    let mut reply = DropReply::default();

    let table = match s.get_table("drop-reply") {
        Err(_) => return Ok(reply),
        Ok(t) => t,
    };

    if let Some(v) = table.get("dns") {
        let value = v
            .clone()
            .into_string()
            .map(|s| s.to_lowercase())
            .map_err(|e| ConfigError::Message(format!("Failed to parse drop-reply.dns: {}", e)))?;
        reply.dns = match value.as_str() {
            "silent" | "none" => DnsDropReply::Silent,
            "nxdomain" => DnsDropReply::Nxdomain,
            _ => {
                return Err(ConfigError::Message(format!(
                    "invalid drop-reply.dns '{}', expect silent|nxdomain",
                    value
                )))
            }
        };
    }

    Ok(reply)
}

fn parse_intercept_mode(s: &Config) -> Result<InterceptMode, ConfigError> {
    let table = match s.get_table("traffic-intercept") {
        Err(_) => return Ok(InterceptMode::MANUAL),
        Ok(t) => t,
    };

    let mode = table
        .get("mode")
        .ok_or_else(|| ConfigError::Message("mode field not found.".to_string()))?
        .clone()
        .into_string()
        .map(|s| s.to_lowercase())
        .map_err(|e| ConfigError::Message(format!("Failed to parse mode: {}", e)))?;

    match mode.as_str() {
        "manual" => return Ok(InterceptMode::MANUAL),
        "auto" | "tproxy" | "ipfw" | "pf" | "utun" | "tun" | "redirect" => {
            let capture_local_traffic = table
                .get("local-traffic")
                .and_then(|v| v.clone().into_bool().ok())
                .unwrap_or(false);

            let ports = match table.get("ports") {
                Some(v) => {
                    let arr = v.clone().into_array().map_err(|e| {
                        ConfigError::Message(format!("ports must be an array: {}", e))
                    })?;
                    let ranges = sanitize_port_ranges(&arr)?;
                    let ports_str = port_range_to_string(&ranges);
                    Some(ports_str)
                }
                None => None,
            };

            let proxy_mark =
                parse_optional_int_field(table.clone(), "proxy-mark", DEFAULT_IPTABLES_PROXY_MARK);
            let direct_mark = parse_optional_int_field(
                table.clone(),
                "direct-mark",
                DEFAULT_IPTABLES_DIRECT_MARK,
            );
            let proxy_chain = parse_optional_string_field(
                table.clone(),
                "tproxy-proxy-chain",
                DEFAULT_IPTABLES_PROXY_CHAIN_NAME,
            );
            let mark_chain = parse_optional_string_field(
                table.clone(),
                "tproxy-mark-chain",
                DEFAULT_IPTABLES_MARK_CHAIN_NAME,
            );
            let rule_table_index =
                parse_optional_int_field_u8(table.clone(), "rule-table", DEFAULT_IPRULE_TABLE);

            if mode == "redirect" {
                if cfg!(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos")) {
                    return Err(ConfigError::Message(
                        "redirect mode is not supported on this platform; use auto/tproxy or manual"
                            .to_string(),
                    ));
                }
                return Ok(InterceptMode::REDIRECT {
                    local_traffic: capture_local_traffic,
                    ports: ports.unwrap_or_default(),
                    direct_mark,
                    proxy_chain,
                });
            }

            if mode == "pf" && !cfg!(target_os = "openbsd") {
                return Err(ConfigError::Message(
                    "pf mode is only supported on OpenBSD; use auto/tproxy".to_string(),
                ));
            }

            if (mode == "utun" || mode == "tun") && !cfg!(target_os = "macos") {
                return Err(ConfigError::Message(
                    "utun/tun mode is only supported on macOS; use auto/tproxy".to_string(),
                ));
            }

            if mode == "ipfw" || cfg!(target_os = "freebsd") {
                if !cfg!(target_os = "freebsd") {
                    return Err(ConfigError::Message(
                        "ipfw mode is only supported on FreeBSD; use auto/tproxy"
                            .to_string(),
                    ));
                }
                let rule_base = parse_optional_int_field_u16(
                    table.clone(),
                    "ipfw-rule-base",
                    DEFAULT_IPFW_RULE_BASE,
                );
                return Ok(InterceptMode::IPFW {
                    local_traffic: capture_local_traffic,
                    ports: ports.unwrap_or_default(),
                    rule_base,
                    proxy_chain,
                });
            }

            if mode == "pf" || cfg!(target_os = "openbsd") {
                if !cfg!(target_os = "openbsd") {
                    return Err(ConfigError::Message(
                        "pf mode is only supported on OpenBSD; use auto/tproxy".to_string(),
                    ));
                }
                return Ok(InterceptMode::PF {
                    local_traffic: capture_local_traffic,
                    ports: ports.unwrap_or_default(),
                    proxy_chain,
                });
            }

            if mode == "utun" || mode == "tun" || cfg!(target_os = "macos") {
                if !cfg!(target_os = "macos") {
                    return Err(ConfigError::Message(
                        "utun/tun mode is only supported on macOS; use auto/tproxy".to_string(),
                    ));
                }
                let utun_name = table
                    .get("utun-name")
                    .and_then(|v| v.clone().into_string().ok())
                    .and_then(non_empty_trimmed);
                let egress_interface = table
                    .get("egress-interface")
                    .and_then(|v| v.clone().into_string().ok())
                    .and_then(non_empty_trimmed)
                    .or_else(|| parse_egress_interface(s));
                return Ok(InterceptMode::UTUN {
                    local_traffic: capture_local_traffic,
                    ports: ports.unwrap_or_default(),
                    utun_name,
                    egress_interface,
                    proxy_chain,
                });
            }

            Ok(InterceptMode::TPROXY {
                local_traffic: capture_local_traffic,
                ports: ports.unwrap_or_default(),
                proxy_mark,
                direct_mark,
                proxy_chain,
                rule_table_index,
                mark_chain,
            })
        }
        _ => Err(ConfigError::Message(
            "either `auto/tproxy`, `utun/tun`, `ipfw`, `pf`, `redirect` or `manual` is expected."
                .to_owned(),
        )),
    }
}

fn parse_optional_int_field(
    table: std::collections::HashMap<String, config::Value>,
    field: &str,
    default: u32,
) -> u32 {
    table
        .get(field)
        .and_then(|v| v.clone().into_int().ok())
        .unwrap_or(default as i64) as u32
}

fn parse_optional_int_field_u8(
    table: std::collections::HashMap<String, config::Value>,
    field: &str,
    default: u8,
) -> u8 {
    table
        .get(field)
        .and_then(|v| v.clone().into_int().ok())
        .unwrap_or(default as i64)
        .min(u8::MAX as i64) as u8
}

fn parse_optional_int_field_u16(
    table: std::collections::HashMap<String, config::Value>,
    field: &str,
    default: u16,
) -> u16 {
    table
        .get(field)
        .and_then(|v| v.clone().into_int().ok())
        .unwrap_or(default as i64)
        .clamp(0, u16::MAX as i64) as u16
}

fn parse_optional_string_field(
    table: std::collections::HashMap<String, config::Value>,
    field: &str,
    default: &str,
) -> String {
    table
        .get(field)
        .and_then(|v| v.clone().into_string().ok())
        .unwrap_or_else(|| default.to_string())
}

fn non_empty_trimmed(raw: String) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn parse_egress_interface(s: &Config) -> Option<String> {
    s.get::<String>("egress-interface")
        .ok()
        .and_then(non_empty_trimmed)
        .or_else(|| {
            s.get_table("traffic-intercept").ok().and_then(|table| {
                table
                    .get("egress-interface")
                    .and_then(|v| v.clone().into_string().ok())
                    .and_then(non_empty_trimmed)
            })
        })
}

fn parse_bypass_cidrs(s: &Config) -> Result<BypassCidrs, ConfigError> {
    let Ok(table) = s.get_table("traffic-intercept") else {
        return Ok(BypassCidrs::default());
    };
    let Some(raw_list) = table.get("bypass-cidrs") else {
        return Ok(BypassCidrs::default());
    };

    let items = raw_list
        .clone()
        .into_array()
        .map_err(|e| ConfigError::Message(format!("bypass-cidrs must be an array: {}", e)))?;

    let mut out = BypassCidrs::default();
    for item in items {
        let raw = item.into_string().map_err(|e| {
            ConfigError::Message(format!("bypass-cidrs item must be a string: {}", e))
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::Message(
                "bypass-cidrs item must not be empty".to_string(),
            ));
        }

        let net = match trimmed.parse::<IpNet>() {
            Ok(net) => net.trunc(),
            Err(net_err) => trimmed
                .parse::<std::net::IpAddr>()
                .map(IpNet::from)
                .map_err(|_| {
                    ConfigError::Message(format!(
                        "Invalid bypass-cidrs CIDR '{}': {}",
                        trimmed, net_err
                    ))
                })?,
        };

        if net.prefix_len() == 0 {
            return Err(ConfigError::Message(format!(
                "bypass-cidrs cannot contain default route '{}'",
                trimmed
            )));
        }

        match net {
            IpNet::V4(v4) => out.v4.push(v4.to_string()),
            IpNet::V6(v6) => out.v6.push(v6.to_string()),
        }
    }

    out.v4.sort();
    out.v4.dedup();
    out.v6.sort();
    out.v6.dedup();
    Ok(out)
}

fn parse_route_rules(s: &Config, route: &mut RouteTable) -> Result<(), ConfigError> {
    // Separate storage for different types of domain rules per outbound
    let num_outbounds = route.outbounds.len();
    let mut keyword_sets: Vec<HashSet<String>> = vec![HashSet::new(); num_outbounds];
    let mut suffix_sets: Vec<Vec<(FQDN, u8)>> = vec![Vec::new(); num_outbounds];
    let mut exact_sets: Vec<HashSet<String>> = vec![HashSet::new(); num_outbounds];

    for user_rule in s.get_array("rules").unwrap_or_default() {
        let rule = user_rule.into_string()?;
        let (keyword, param, outbound_name) = rule
            .split(",")
            .into_iter()
            .map(|v| v.trim())
            .collect_tuple::<_>()
            .ok_or_else(|| {
                ConfigError::Message(
                    "Rule must be in format: keyword,param,outbound_name".to_string(),
                )
            })?;

        let outbound_index = route
            .get_outbound_index_by_name(outbound_name)
            .ok_or_else(|| {
                ConfigError::Message(format!("Outbound '{}' not found", outbound_name))
            })?;

        let cond = &mut route.rules[outbound_index as usize];

        match keyword {
            "DEFAULT" => {
                route.set_default_route(outbound_index);
            }
            "IP-CIDR" => {
                let ip_net = param.parse::<IpNet>().map_err(|e| {
                    ConfigError::Message(format!("Wrong format for IP-CIDR '{}': {}", param, e))
                })?;
                let ip_v6 = ip_net.to_ipv6_net().map_err(|e| {
                    ConfigError::Message(format!(
                        "Failed to convert IP-CIDR '{}' to IPv6 network: {}",
                        param, e
                    ))
                })?;
                cond.dst_ip_table.insert(
                    ip_v6.addr(),
                    ip_v6.prefix_len() as u32,
                    ip_v6.prefix_len(),
                );
            }
            "GEOIP" => {
                let (filename, region) = param
                    .split(":")
                    .into_iter()
                    .map(|v| v.trim())
                    .collect_tuple::<_>()
                    .ok_or_else(|| {
                        ConfigError::Message(
                            "GEOIP rule must be in format: GEOIP,filename,region".to_string(),
                        )
                    })?;
                match filename {
                    name if name.ends_with(".mmdb") => {
                        let maxmind_reader =
                            maxminddb::Reader::open_readfile(filename).map_err(|e| {
                                ConfigError::Message(format!(
                                    "Failed to open file '{}': {}",
                                    filename, e
                                ))
                            })?;
                        route.ip_db = Some(maxmind_reader);
                        cond.maxmind_regions.push(region.to_string().to_lowercase());
                    }
                    name if name.ends_with(".dat") => {
                        let mut f = std::fs::File::open(filename).map_err(|e| {
                            ConfigError::Message(format!(
                                "Failed to open file '{}': {}",
                                filename, e
                            ))
                        })?;
                        let list: crate::protos::common::GeoIPList =
                            protobuf::Message::parse_from_reader(&mut f).map_err(|e| {
                                ConfigError::Message(format!(
                                    "Failed to parse GeoIPList '{}': {}",
                                    filename, e
                                ))
                            })?;
                        list.entry
                            .iter()
                            .filter(|&l| l.country_code.to_lowercase() == region.to_lowercase())
                            .for_each(|geoip| {
                                geoip.cidr.iter().for_each(|cidr| {
                                    if let Some(net) = cidr_to_ipv6net(cidr) {
                                        cond.dst_ip_table.insert(
                                            net.addr(),
                                            net.prefix_len() as u32,
                                            net.prefix_len(),
                                        );
                                    }
                                });
                            });
                    }
                    _ => {
                        return Err(ConfigError::Message(
                            "GEOIP filename must end with .mmdb or .dat".to_string(),
                        ))
                    }
                }
            }
            "GEOSITE" => {
                let (filename, code) = param
                    .split(":")
                    .into_iter()
                    .map(|v| v.trim())
                    .collect_tuple::<_>()
                    .ok_or_else(|| {
                        ConfigError::Message(
                            "GEOSITE rule must be in format: GEOSITE,filename,code".to_string(),
                        )
                    })?;

                let outbound_index =
                    route
                        .get_outbound_index_by_name(outbound_name)
                        .ok_or_else(|| {
                            ConfigError::Message(format!("Outbound '{}' not found", outbound_name))
                        })?;

                let mut f = std::fs::File::open(filename).map_err(|e| {
                    ConfigError::Message(format!("Failed to open file '{}': {}", filename, e))
                })?;
                let list: crate::protos::common::GeoSiteList =
                    protobuf::Message::parse_from_reader(&mut f).map_err(|e| {
                        ConfigError::Message(format!(
                            "Failed to parse geosite.dat '{}': {}",
                            filename, e
                        ))
                    })?;
                list.entry
                    .iter()
                    .filter(|&geosites| geosites.country_code.to_lowercase() == code.to_lowercase())
                    .map(|e| &e.domain)
                    .for_each(|ds| {
                        ds.iter().for_each(|d| {
                            let idx = outbound_index as usize;
                            match d.type_.enum_value() {
                                Ok(crate::protos::common::domain::Type::Plain) => {
                                    // Plain type -> keyword matching with AC
                                    keyword_sets[idx].insert(d.value.to_lowercase());
                                }
                                Ok(crate::protos::common::domain::Type::Regex) => {
                                    // Regex not supported, skip
                                }
                                Ok(crate::protos::common::domain::Type::RootDomain) => {
                                    // RootDomain -> suffix matching with Trie
                                    if let Ok(fqdn) = d.value.to_lowercase().parse::<FQDN>() {
                                        let score = d.value.len().min(255) as u8;
                                        suffix_sets[idx].push((fqdn, score));
                                    }
                                }
                                Ok(crate::protos::common::domain::Type::Full) => {
                                    // Full -> exact match
                                    exact_sets[idx].insert(d.value.to_lowercase());
                                }
                                Err(_) => { /* Unknown type, skip */ }
                            }
                        })
                    });
            }
            "DOMAIN" => {
                let outbound_index =
                    route
                        .get_outbound_index_by_name(outbound_name)
                        .ok_or_else(|| {
                            ConfigError::Message(format!("Outbound '{}' not found", outbound_name))
                        })?;
                // DOMAIN -> exact match
                exact_sets[outbound_index as usize].insert(param.to_lowercase());
            }
            "DOMAIN-SUFFIX" => {
                let outbound_index =
                    route
                        .get_outbound_index_by_name(outbound_name)
                        .ok_or_else(|| {
                            ConfigError::Message(format!("Outbound '{}' not found", outbound_name))
                        })?;
                // DOMAIN-SUFFIX -> suffix matching with Trie
                if let Ok(fqdn) = param.to_lowercase().parse::<FQDN>() {
                    let score = param.len().min(255) as u8;
                    suffix_sets[outbound_index as usize].push((fqdn, score));
                }
            }
            "DOMAIN-KEYWORD" => {
                let outbound_index =
                    route
                        .get_outbound_index_by_name(outbound_name)
                        .ok_or_else(|| {
                            ConfigError::Message(format!("Outbound '{}' not found", outbound_name))
                        })?;
                // DOMAIN-KEYWORD -> keyword matching with AC
                keyword_sets[outbound_index as usize].insert(param.to_lowercase());
            }
            e @ _ => {
                return Err(ConfigError::Message(format!(
                    "'{}' is not a valid rule keyword",
                    e
                )));
            }
        }
    }

    // Build the matchers for each outbound
    for i in 0..num_outbounds {
        let cond = route
            .rules
            .get_mut(i)
            .ok_or_else(|| ConfigError::Message(format!("Invalid rule index: {}", i)))?;

        // Build Aho-Corasick for keyword matching
        if !keyword_sets[i].is_empty() {
            cond.domain_keywords = Some(
                aho_corasick::AhoCorasick::new(keyword_sets[i].iter()).map_err(|e| {
                    ConfigError::Message(format!("Failed to build keyword matcher: {}", e))
                })?,
            );
        }

        // Build FqdnTrieMap for suffix matching
        for (fqdn, score) in suffix_sets[i].drain(..) {
            cond.domain_suffix_trie.insert(fqdn, score);
        }

        // Set exact domains
        cond.exact_domains = std::mem::take(&mut exact_sets[i]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::FileFormat;

    fn parse_config_yaml(yaml: &str) -> Config {
        Config::builder()
            .add_source(File::from_str(yaml, FileFormat::Yaml))
            .build()
            .unwrap()
    }

    #[test]
    fn sanitize_port_ranges_handles_empty_and_overlapping_ranges() {
        let empty = sanitize_port_ranges(&vec![]).unwrap();
        assert!(empty.is_empty());

        let vals = vec![
            config::Value::from("80"),
            config::Value::from("443"),
            config::Value::from("8080-8085"),
            config::Value::from("8082-8084"),
        ];
        let merged = sanitize_port_ranges(&vals).unwrap();
        assert_eq!(merged, vec![[80, 80], [443, 443], [8080, 8085]]);
        assert_eq!(port_range_to_string(&merged), "80,443,8080:8085");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_intercept_mode_parses_utun_and_rejects_unsupported() {
        for mode in ["auto", "tproxy", "utun", "tun"] {
            let cfg = parse_config_yaml(&format!(
                "traffic-intercept:\n  mode: {mode}\n  local-traffic: true\n  ports: [80, 443, \"8080-8082\"]\n  utun-name: utun9\n  egress-interface: en0\n  tproxy-proxy-chain: rfor-mac\n"
            ));
            match parse_intercept_mode(&cfg).unwrap() {
                InterceptMode::UTUN {
                    local_traffic,
                    ports,
                    utun_name,
                    egress_interface,
                    proxy_chain,
                } => {
                    assert!(local_traffic);
                    assert_eq!(ports, "80,443,8080:8082");
                    assert_eq!(utun_name.as_deref(), Some("utun9"));
                    assert_eq!(egress_interface.as_deref(), Some("en0"));
                    assert_eq!(proxy_chain, "rfor-mac");
                }
                _ => panic!("expected UTUN variant for mode {mode}"),
            }
        }

        for bad_mode in ["redirect", "ipfw", "pf"] {
            let cfg = parse_config_yaml(&format!("traffic-intercept:\n  mode: {bad_mode}\n"));
            assert!(
                parse_intercept_mode(&cfg).is_err(),
                "{bad_mode} should be rejected on macOS"
            );
        }

        let manual = parse_config_yaml("traffic-intercept:\n  mode: manual\n");
        assert!(matches!(
            parse_intercept_mode(&manual).unwrap(),
            InterceptMode::MANUAL
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_settings_allows_utun_without_tproxy_listen() {
        let settings = Settings {
            debug: false,
            pprof: None,
            disable_ipv6: false,
            tproxy_listen: None,
            socks5_listen: None,
            redirect_listen: None,
            routetable: RouteTable::new(),
            intercept_mode: InterceptMode::UTUN {
                local_traffic: true,
                ports: "80,443".to_string(),
                utun_name: None,
                egress_interface: None,
                proxy_chain: "rfor-proxy".to_string(),
            },
            bypass_cidrs: BypassCidrs::default(),
            egress_interface: None,
            udp_enable: true,
            udp_timeout: 60,
            udp_fullcone: false,
            udp_fullcone_max_sockets: 64,
            udp_fullcone_socket_timeout: 30,
            udp_fullcone_rate_limit: 10,
            udp_max_sessions: 1024,
            drop_reply: DropReply::default(),
        };
        assert!(validate_settings(&settings).is_ok());
    }

    #[test]
    fn parse_egress_interface_supports_top_level_and_manual_intercept() {
        let top_level = parse_config_yaml("egress-interface: \" en0 \"\ntraffic-intercept:\n  mode: manual\n");
        assert_eq!(parse_egress_interface(&top_level).as_deref(), Some("en0"));

        let nested = parse_config_yaml(
            "traffic-intercept:\n  mode: manual\n  egress-interface: \"en1\"\n",
        );
        assert_eq!(parse_egress_interface(&nested).as_deref(), Some("en1"));

        let blank = parse_config_yaml("egress-interface: \"   \"\ntraffic-intercept:\n  mode: manual\n");
        assert_eq!(parse_egress_interface(&blank), None);

        let missing = parse_config_yaml("traffic-intercept:\n  mode: manual\n");
        assert_eq!(parse_egress_interface(&missing), None);
    }

    #[test]
    fn parse_bypass_cidrs_supports_v4_v6_bare_ips_and_truncates() {
        let cfg = parse_config_yaml(
            "traffic-intercept:\n  mode: auto\n  bypass-cidrs:\n    - \" 30.221.100.46/19 \"\n    - \"29.29.29.29\"\n    - \"30.221.96.0/19\"\n    - \"2001:db8::1/64\"\n    - \"2001:db8:cafe::1\"\n    - \"2001:db8::/64\"\n",
        );
        let parsed = parse_bypass_cidrs(&cfg).unwrap();
        assert_eq!(
            parsed,
            BypassCidrs {
                v4: vec!["29.29.29.29/32".to_string(), "30.221.96.0/19".to_string()],
                v6: vec![
                    "2001:db8::/64".to_string(),
                    "2001:db8:cafe::1/128".to_string()
                ],
            }
        );

        let absent = parse_config_yaml("socks5-listen: 127.0.0.1:1080\n");
        assert_eq!(parse_bypass_cidrs(&absent).unwrap(), BypassCidrs::default());
    }

    #[test]
    fn parse_bypass_cidrs_rejects_invalid_and_default_routes() {
        for yaml in [
            "traffic-intercept:\n  mode: auto\n  bypass-cidrs: \"30.0.0.0/8\"\n",
            "traffic-intercept:\n  mode: auto\n  bypass-cidrs:\n    - \"   \"\n",
            "traffic-intercept:\n  mode: auto\n  bypass-cidrs:\n    - \"not-a-cidr\"\n",
            "traffic-intercept:\n  mode: auto\n  bypass-cidrs:\n    - \"0.0.0.0/0\"\n",
            "traffic-intercept:\n  mode: auto\n  bypass-cidrs:\n    - \"::/0\"\n",
        ] {
            let cfg = parse_config_yaml(yaml);
            assert!(
                parse_bypass_cidrs(&cfg).is_err(),
                "expected error for yaml:\n{yaml}"
            );
        }
    }

    #[test]
    fn validate_settings_rejects_slash_one_bypass_only_for_utun_local_traffic() {
        let make_settings = |local_traffic: bool, bypass_cidrs: BypassCidrs| Settings {
            debug: false,
            pprof: None,
            disable_ipv6: false,
            tproxy_listen: None,
            socks5_listen: None,
            redirect_listen: None,
            routetable: RouteTable::new(),
            intercept_mode: InterceptMode::UTUN {
                local_traffic,
                ports: "80,443".to_string(),
                utun_name: None,
                egress_interface: None,
                proxy_chain: "rfor-proxy".to_string(),
            },
            bypass_cidrs,
            egress_interface: None,
            udp_enable: true,
            udp_timeout: 60,
            udp_fullcone: false,
            udp_fullcone_max_sockets: 64,
            udp_fullcone_socket_timeout: 30,
            udp_fullcone_rate_limit: 10,
            udp_max_sessions: 1024,
            drop_reply: DropReply::default(),
        };

        assert!(validate_settings(&make_settings(
            true,
            BypassCidrs {
                v4: vec!["0.0.0.0/1".to_string()],
                v6: Vec::new(),
            }
        ))
        .is_err());

        assert!(validate_settings(&make_settings(
            true,
            BypassCidrs {
                v4: Vec::new(),
                v6: vec!["::/1".to_string()],
            }
        ))
        .is_err());

        assert!(validate_settings(&make_settings(
            false,
            BypassCidrs {
                v4: vec!["0.0.0.0/1".to_string()],
                v6: vec!["::/1".to_string()],
            }
        ))
        .is_ok());
    }
}
