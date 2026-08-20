use std::{collections::HashSet, sync::Arc, time::Duration};

use clap::Parser;
use fqdn::FQDN;
use itertools::Itertools;
use serde::Serialize;
use tracing::warn;

use config::{Config, ConfigError, Environment, File};
use ipnet::IpNet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::rules::{RouteOptions, RouteTable};
use crate::utils::{vec_to_array, ToV6Net};

const DIRECT_OUTBOUND_NAME: &str = "DIRECT";
const DROP_OUTBOUND_NAME: &str = "DROP";
const DEFAULT_IPTABLES_PROXY_MARK: u32 = 0xff42;
const DEFAULT_IPTABLES_DIRECT_MARK: u32 = 0xff43;
const DEFAULT_IPTABLES_PROXY_CHAIN_NAME: &str = "rfor-proxy";
const DEFAULT_IPTABLES_MARK_CHAIN_NAME: &str = "rfor-mark";
const DEFAULT_IPRULE_TABLE: u8 = 0x42;
const DEFAULT_TCP_SNIFF_TIMEOUT_SECS: f64 = 2.0;

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

#[derive(Serialize, PartialEq, Eq)]
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
    MANUAL,
}

#[derive(Serialize)]
pub struct Settings {
    pub debug: bool,
    pub pprof: Option<String>,
    pub disable_ipv6: bool,
    pub tproxy_listen: Option<String>,
    pub socks5_listen: Option<String>,
    pub redirect_listen: Option<String>,
    /// Maximum time to wait for a recognizable TCP Host/SNI, in seconds.
    pub tcp_sniff_timeout: f64,
    #[serde(skip)]
    pub routetable: Arc<RouteTable>,
    pub intercept_mode: InterceptMode,
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
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        Self::load()
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml_ng::to_string(self).unwrap_or_else(|e| format!("<failed to serialize: {}>", e))
    }

    pub fn route_snapshot(&self) -> (Arc<RouteTable>, RouteOptions) {
        let direct_mark = match &self.intercept_mode {
            InterceptMode::TPROXY { direct_mark, .. }
            | InterceptMode::REDIRECT { direct_mark, .. } => Some(*direct_mark),
            InterceptMode::MANUAL => None,
        };
        (
            Arc::clone(&self.routetable),
            RouteOptions {
                debug: self.debug,
                disable_ipv6: self.disable_ipv6,
                direct_mark,
            },
        )
    }

    pub fn tcp_sniff_timeout(&self) -> Duration {
        Duration::try_from_secs_f64(self.tcp_sniff_timeout)
            .expect("tcp-sniff-timeout is validated while loading settings")
    }

    pub(crate) fn restart_required_changes(&self, new: &Self) -> Vec<&'static str> {
        let mut changes = Vec::new();

        if self.disable_ipv6 != new.disable_ipv6 {
            changes.push("disable-ipv6");
        }
        if self.tproxy_listen != new.tproxy_listen {
            changes.push("tproxy-listen");
        }
        if self.socks5_listen != new.socks5_listen {
            changes.push("socks5-listen");
        }
        if self.redirect_listen != new.redirect_listen {
            changes.push("redirect-listen");
        }
        if self.intercept_mode != new.intercept_mode {
            changes.push("traffic-intercept");
        }
        if self.udp_enable != new.udp_enable {
            changes.push("udp-enabled");
        }
        if self.udp_max_sessions != new.udp_max_sessions {
            changes.push("udp-max-sessions");
        }

        changes
    }

    pub(crate) fn apply_reloadable(&mut self, new: Self) {
        self.debug = new.debug;
        self.pprof = new.pprof;
        self.routetable = new.routetable;
        self.tcp_sniff_timeout = new.tcp_sniff_timeout;
        self.udp_timeout = new.udp_timeout;
        self.udp_fullcone = new.udp_fullcone;
        self.udp_fullcone_max_sockets = new.udp_fullcone_max_sockets;
        self.udp_fullcone_socket_timeout = new.udp_fullcone_socket_timeout;
        self.udp_fullcone_rate_limit = new.udp_fullcone_rate_limit;
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

        /* 6. Parse the UDP enabling */
        let udp_enable = match &intercept_mode {
            InterceptMode::TPROXY { .. } | InterceptMode::MANUAL => {
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
            tcp_sniff_timeout: parse_tcp_sniff_timeout(&s)?,
            routetable: Arc::new(route),
            intercept_mode,
            udp_enable,
            udp_timeout: s.get_int("udp-timeout").unwrap_or(60) as u64,
            udp_fullcone: s.get_bool("udp-fullcone").unwrap_or(false),
            udp_fullcone_max_sockets: s.get_int("udp-fullcone-max-sockets").unwrap_or(64) as usize,
            udp_fullcone_socket_timeout: s.get_int("udp-fullcone-socket-timeout").unwrap_or(30)
                as u64,
            udp_fullcone_rate_limit: s.get_int("udp-fullcone-rate-limit").unwrap_or(10) as u32,
            udp_max_sessions: s.get_int("udp-max-sessions").unwrap_or(1024) as usize,
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
    // At least one listener should be configured
    if settings.tproxy_listen.is_none()
        && settings.socks5_listen.is_none()
        && settings.redirect_listen.is_none()
    {
        return Err(ConfigError::Message(
            "At least one listener (tproxy-listen, socks5-listen, or redirect-listen) must be configured.".to_string()
        ));
    }

    Ok(())
}

fn parse_tcp_sniff_timeout(config: &Config) -> Result<f64, ConfigError> {
    let seconds = match config.get_float("tcp-sniff-timeout") {
        Ok(seconds) => seconds,
        Err(ConfigError::NotFound(_)) => DEFAULT_TCP_SNIFF_TIMEOUT_SECS,
        Err(err) => return Err(err),
    };
    Duration::try_from_secs_f64(seconds).map_err(|_| {
        ConfigError::Message(
            "tcp-sniff-timeout must be a finite, non-negative number of seconds".to_string(),
        )
    })?;
    Ok(seconds)
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
    while i < ranges.len() - 1 {
        if ranges[i][1] >= ranges[i + 1][0] {
            ranges[i][1] = ranges[i + 1][1];
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
        "auto" | "tproxy" | "redirect" => {
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

            if mode.as_str() != "redirect" {
                Ok(InterceptMode::TPROXY {
                    local_traffic: capture_local_traffic,
                    ports: ports.unwrap_or_default(),
                    proxy_mark,
                    direct_mark,
                    proxy_chain,
                    rule_table_index,
                    mark_chain,
                })
            } else {
                Ok(InterceptMode::REDIRECT {
                    local_traffic: capture_local_traffic,
                    ports: ports.unwrap_or_default(),
                    direct_mark,
                    proxy_chain,
                })
            }
        }
        _ => Err(ConfigError::Message(
            "either `auto/tproxy`, `redirect` or `manual` is expected.".to_owned(),
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

    fn test_settings() -> Settings {
        Settings {
            debug: false,
            pprof: None,
            disable_ipv6: true,
            tproxy_listen: Some("0.0.0.0:50080".to_string()),
            socks5_listen: None,
            redirect_listen: None,
            tcp_sniff_timeout: DEFAULT_TCP_SNIFF_TIMEOUT_SECS,
            routetable: Arc::new(RouteTable::new()),
            intercept_mode: InterceptMode::TPROXY {
                local_traffic: true,
                ports: "80,443".to_string(),
                proxy_mark: DEFAULT_IPTABLES_PROXY_MARK,
                direct_mark: DEFAULT_IPTABLES_DIRECT_MARK,
                proxy_chain: DEFAULT_IPTABLES_PROXY_CHAIN_NAME.to_string(),
                mark_chain: DEFAULT_IPTABLES_MARK_CHAIN_NAME.to_string(),
                rule_table_index: DEFAULT_IPRULE_TABLE,
            },
            udp_enable: true,
            udp_timeout: 60,
            udp_fullcone: false,
            udp_fullcone_max_sockets: 64,
            udp_fullcone_socket_timeout: 30,
            udp_fullcone_rate_limit: 10,
            udp_max_sessions: 1024,
        }
    }

    #[test]
    fn restart_required_changes_reports_immutable_fields() {
        let current = test_settings();
        let mut new = test_settings();
        new.disable_ipv6 = false;
        new.tproxy_listen = Some("0.0.0.0:50081".to_string());
        new.socks5_listen = Some("0.0.0.0:1080".to_string());
        new.redirect_listen = Some("0.0.0.0:50082".to_string());
        new.udp_enable = false;
        new.udp_max_sessions = 2048;
        new.intercept_mode = InterceptMode::MANUAL;

        assert_eq!(
            current.restart_required_changes(&new),
            vec![
                "disable-ipv6",
                "tproxy-listen",
                "socks5-listen",
                "redirect-listen",
                "traffic-intercept",
                "udp-enabled",
                "udp-max-sessions",
            ]
        );
    }

    #[test]
    fn apply_reloadable_updates_only_whitelisted_fields() {
        let mut current = test_settings();
        let mut new = test_settings();
        new.debug = true;
        new.pprof = Some("profile.svg".to_string());
        new.tcp_sniff_timeout = 0.25;
        new.udp_timeout = 120;
        new.udp_fullcone = true;
        new.udp_fullcone_max_sockets = 128;
        new.udp_fullcone_socket_timeout = 45;
        new.udp_fullcone_rate_limit = 20;
        let new_routetable = Arc::clone(&new.routetable);

        current.apply_reloadable(new);

        assert!(current.debug);
        assert_eq!(current.pprof.as_deref(), Some("profile.svg"));
        assert_eq!(current.tcp_sniff_timeout, 0.25);
        assert!(Arc::ptr_eq(&current.routetable, &new_routetable));
        assert_eq!(current.udp_timeout, 120);
        assert!(current.udp_fullcone);
        assert_eq!(current.udp_fullcone_max_sockets, 128);
        assert_eq!(current.udp_fullcone_socket_timeout, 45);
        assert_eq!(current.udp_fullcone_rate_limit, 20);
        assert!(current.disable_ipv6);
        assert_eq!(current.tproxy_listen.as_deref(), Some("0.0.0.0:50080"));
        assert!(matches!(
            current.intercept_mode,
            InterceptMode::TPROXY { .. }
        ));
        assert!(current.udp_enable);
        assert_eq!(current.udp_max_sessions, 1024);
    }

    #[test]
    fn parses_fractional_tcp_sniff_timeout_and_rejects_invalid_values() {
        let defaults = Config::builder().build().unwrap();
        assert_eq!(
            parse_tcp_sniff_timeout(&defaults).unwrap(),
            DEFAULT_TCP_SNIFF_TIMEOUT_SECS
        );

        let fractional = Config::builder()
            .set_override("tcp-sniff-timeout", 0.25)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(parse_tcp_sniff_timeout(&fractional).unwrap(), 0.25);

        let wrong_type = Config::builder()
            .set_override("tcp-sniff-timeout", "invalid")
            .unwrap()
            .build()
            .unwrap();
        assert!(parse_tcp_sniff_timeout(&wrong_type).is_err());

        for invalid in [-0.1, f64::NAN, f64::INFINITY, f64::MAX] {
            let config = Config::builder()
                .set_override("tcp-sniff-timeout", invalid)
                .unwrap()
                .build()
                .unwrap();
            assert!(parse_tcp_sniff_timeout(&config).is_err());
        }
    }
}
