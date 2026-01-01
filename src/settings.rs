use std::collections::HashSet;

use clap::Parser;
use itertools::Itertools;
use tracing::warn;

use config::{Config, ConfigError, Environment, File};
use ipnet::IpNet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::rules::{RouteTable, RULE_DOMAIN_SUFFIX_TAG};
use crate::utils::{vec_to_array, ToV6Net};

const DIRECT_OUTBOUND_NAME: &str = "DIRECT";
const DROP_OUTBOUND_NAME: &str = "DROP";
const DEFAULT_IPTABLES_PROXY_MARK: u32 = 0xff42;
const DEFAULT_IPTABLES_DIRECT_MARK: u32 = 0xff43;
const DEFAULT_IPTABLES_PROXY_CHAIN_NAME: &str = "rfor-proxy";
const DEFAULT_IPTABLES_MARK_CHAIN_NAME: &str = "rfor-mark";
const DEFAULT_IPRULE_TABLE: u8 = 0x42;

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

pub struct Settings {
    pub debug: bool,
    pub pprof: Option<String>,
    pub disable_ipv6: bool,
    pub tproxy_listen: Option<String>,
    pub socks5_listen: Option<String>,
    pub redirect_listen: Option<String>,
    pub routetable: RouteTable,
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

    pub fn load() -> Result<Self, ConfigError> {
        let args = Args::parse();
        std::env::set_current_dir(&args.work_dir).map_err(|e| {
            ConfigError::Message(format!(
                "Failed to set working directory '{}': {}",
                args.work_dir, e
            ))
        })?;
        let args = Args::parse();
        std::env::set_current_dir(&args.work_dir)
            .map_err(|e| ConfigError::Message(format!("Failed to set working directory '{}': {}", args.work_dir, e)))?;

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
            InterceptMode::TPROXY { .. } | InterceptMode::MANUAL => s.get_bool("udp-enable").unwrap_or(true),
            InterceptMode::REDIRECT { .. } => {
                warn!("UDP is not supported in REDIRECT mode, disabling it.");
                false
            },
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
            udp_enable,
            udp_timeout: s.get_int("udp-timeout").unwrap_or(60) as u64,
            udp_fullcone: s.get_bool("udp-fullcone").unwrap_or(false),
            udp_fullcone_max_sockets: s.get_int("udp-fullcone-max-sockets").unwrap_or(64) as usize,
            udp_fullcone_socket_timeout: s.get_int("udp-fullcone-socket-timeout").unwrap_or(30) as u64,
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
        let outbound = outbound_value.into_table()
            .map_err(|e| ConfigError::Message(format!("Failed to parse outbound: {}", e)))?;

        let name = parse_required_field(&outbound, "name")?;

        let url = outbound.get("url").and_then(|v| {
            v.clone().into_string().ok().and_then(|s| {
                s.parse().ok()
            })
        });

        let bind_range = parse_bind_range(&outbound)?;

        route.add_empty_rule(name, url, bind_range);
    }

    Ok(())
}

fn parse_required_field(outbound: &std::collections::HashMap<String, config::Value>, field: &str) -> Result<String, ConfigError> {
    outbound.get(field)
        .and_then(|v| v.clone().into_string().ok())
        .ok_or_else(|| ConfigError::Message(format!("Missing required field: {}", field)))
}

fn parse_bind_range(outbound: &std::collections::HashMap<String, config::Value>) -> Result<Option<iprange::IpRange<ipnet::Ipv6Net>>, ConfigError> {
    if let Some(items) = outbound.get("bind_range") {
        let items = items.clone().into_array()
            .map_err(|e| ConfigError::Message(format!("bind_range must be an array: {}", e)))?;

        let mut bind_range = iprange::IpRange::<ipnet::Ipv6Net>::new();

        for item in items {
            let cidr_str = item.into_string()
                .map_err(|e| ConfigError::Message(format!("bind_range item must be a string: {}", e)))?;

            let cidr = cidr_str.parse()
                .map_err(|e| ConfigError::Message(format!("Invalid bind_range CIDR '{}': {}", cidr_str, e)))?;

            bind_range.add(cidr);
        }

        Ok(Some(bind_range))
    } else {
        Ok(None)
    }
}

fn cidr_to_ipv6net(cidr: &crate::protos::common::CIDR) -> Option<ipnet::Ipv6Net> {
    match cidr.ip.len() {
        4 => {
            vec_to_array::<u8, 4>(cidr.ip.clone()).and_then(|arr| {
                ipnet::Ipv6Net::new(
                    Ipv4Addr::from(arr).to_ipv6_mapped(),
                    cidr.prefix as u8 + (128 - 32),
                ).ok()
            })
        }
        16 => {
            vec_to_array::<u8, 16>(cidr.ip.clone()).and_then(|arr| {
                ipnet::Ipv6Net::new(
                    Ipv6Addr::from(arr),
                    cidr.prefix as u8,
                ).ok()
            })
        }
        _ => None,
    }
}

fn ensure_default_outbounds(route: &mut RouteTable) -> Result<(), ConfigError> {
    if route.get_outbound_by_name(DIRECT_OUTBOUND_NAME).is_none() {
        route.add_empty_rule(DIRECT_OUTBOUND_NAME.to_owned(), None, None);
    }

    if route.get_outbound_by_name(DROP_OUTBOUND_NAME).is_none() {
        let drop_url: url::Url = "drop://0.0.0.0".parse()
            .map_err(|e| ConfigError::Message(format!("Failed to parse drop URL: {}", e)))?;
        route.add_empty_rule(DROP_OUTBOUND_NAME.to_owned(), Some(drop_url), None);
    }

    Ok(())
}

fn validate_settings(settings: &Settings) -> Result<(), ConfigError> {
    // At least one listener should be configured
    if settings.tproxy_listen.is_none()
        && settings.socks5_listen.is_none()
        && settings.redirect_listen.is_none() {
        return Err(ConfigError::Message(
            "At least one listener (tproxy-listen, socks5-listen, or redirect-listen) must be configured.".to_string()
        ));
    }

    Ok(())
}

fn sanitize_port_ranges(s: &Vec<config::Value>) -> Result<Vec<[u16; 2]>, ConfigError> {
    let mut ranges = s.iter()
        .map(|v| {
            let v = v.clone().into_string()
                .map_err(|e| ConfigError::Message(format!("port must be a string: {}", e)))?;
            if !v.contains("-") {
                let v = v.parse::<u16>()
                    .map_err(|e| ConfigError::Message(format!("port must contain a number: {}", e)))?;
                return Ok([v, v]);
            }

            let (start, end) = v.split("-").collect_tuple::<(&str, &str)>()
                .ok_or_else(|| ConfigError::Message("port range must be start-end".to_string()))?;
            let start = start.parse::<u16>()
                .map_err(|e| ConfigError::Message(format!("start must be a number: {}", e)))?;
            let end = end.parse::<u16>()
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
    ranges.iter().map(|r| {
        if r[0] == r[1] {
            r[0].to_string()
        } else {
            format!("{}:{}", r[0], r[1])
        }
    }).join(",")
}

fn parse_intercept_mode(s: &Config) -> Result<InterceptMode, ConfigError> {
    let table = match s.get_table("traffic-intercept") {
        Err(_) => return Ok(InterceptMode::MANUAL),
        Ok(t) => t,
    };

    let mode = table.get("mode")
        .ok_or_else(|| ConfigError::Message("mode field not found.".to_string()))?
        .clone()
        .into_string()
        .map(|s| s.to_lowercase())
        .map_err(|e| ConfigError::Message(format!("Failed to parse mode: {}", e)))?;

    match mode.as_str() {
        "manual" => return Ok(InterceptMode::MANUAL),
        "auto" | "tproxy" | "redirect" => {
            let capture_local_traffic = table.get("local-traffic")
                .and_then(|v| v.clone().into_bool().ok())
                .unwrap_or(false);

            let ports = match table.get("ports") {
                Some(v) => {
                    let arr = v.clone().into_array()
                        .map_err(|e| ConfigError::Message(format!("ports must be an array: {}", e)))?;
                    let ranges = sanitize_port_ranges(&arr)?;
                    let ports_str = port_range_to_string(&ranges);
                    Some(ports_str)
                }
                None => None,
            };

            let proxy_mark = parse_optional_int_field(table.clone(), "proxy-mark", DEFAULT_IPTABLES_PROXY_MARK);
            let direct_mark = parse_optional_int_field(table.clone(), "direct-mark", DEFAULT_IPTABLES_DIRECT_MARK);
            let proxy_chain = parse_optional_string_field(table.clone(), "tproxy-proxy-chain", DEFAULT_IPTABLES_PROXY_CHAIN_NAME);
            let mark_chain = parse_optional_string_field(table.clone(), "tproxy-mark-chain", DEFAULT_IPTABLES_MARK_CHAIN_NAME);
            let rule_table_index = parse_optional_int_field_u8(table.clone(), "rule-table", DEFAULT_IPRULE_TABLE);

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

fn parse_optional_int_field(table: std::collections::HashMap<String, config::Value>, field: &str, default: u32) -> u32 {
    table.get(field)
        .and_then(|v| v.clone().into_int().ok())
        .unwrap_or(default as i64) as u32
}

fn parse_optional_int_field_u8(table: std::collections::HashMap<String, config::Value>, field: &str, default: u8) -> u8 {
    table.get(field)
        .and_then(|v| v.clone().into_int().ok())
        .unwrap_or(default as i64)
        .min(u8::MAX as i64) as u8
}

fn parse_optional_string_field(table: std::collections::HashMap<String, config::Value>, field: &str, default: &str) -> String {
    table.get(field)
        .and_then(|v| v.clone().into_string().ok())
        .unwrap_or_else(|| default.to_string())
}

fn parse_route_rules(s: &Config, route: &mut RouteTable) -> Result<(), ConfigError> {
    let mut domain_sets: Vec<HashSet<_>> = vec![HashSet::new(); route.outbounds.len()];

    for user_rule in s.get_array("rules").unwrap_or_default() {
        let rule = user_rule.into_string()?;
        let (keyword, param, outbound_name) = rule
            .split(",")
            .into_iter()
            .map(|v| v.trim())
            .collect_tuple::<_>()
            .ok_or_else(|| ConfigError::Message("Rule must be in format: keyword,param,outbound_name".to_string()))?;

        let outbound_index = route
            .get_outbound_index_by_name(outbound_name)
            .ok_or_else(|| ConfigError::Message(format!("Outbound '{}' not found", outbound_name)))?;

        let cond = &mut route.rules[outbound_index as usize];

        match keyword {
            "DEFAULT" => {
                route.set_default_route(outbound_index);
            }
            "IP-CIDR" => {
                let ip_net = param
                    .parse::<IpNet>()
                    .map_err(|e| ConfigError::Message(format!("Wrong format for IP-CIDR '{}': {}", param, e)))?;
                let ip_v6 = ip_net.to_ipv6_net()
                    .map_err(|e| ConfigError::Message(format!("Failed to convert IP-CIDR '{}' to IPv6 network: {}", param, e)))?;
                cond.dst_ip_table.insert(ip_v6.addr(), ip_v6.prefix_len() as u32, ip_v6.prefix_len());
            }
            "GEOIP" => {
                let (filename, region) = param
                    .split(":")
                    .into_iter()
                    .map(|v| v.trim())
                    .collect_tuple::<_>()
                    .ok_or_else(|| ConfigError::Message("GEOIP rule must be in format: GEOIP,filename,region".to_string()))?;
                match filename {
                    name if name.ends_with(".mmdb") => {
                        let maxmind_reader = maxminddb::Reader::open_readfile(filename)
                            .map_err(|e| ConfigError::Message(format!("Failed to open file '{}': {}", filename, e)))?;
                        route.ip_db = Some(maxmind_reader);
                        cond.maxmind_regions.push(region.to_string().to_lowercase());
                    }
                    name if name.ends_with(".dat") => {
                        let mut f = std::fs::File::open(filename)
                            .map_err(|e| ConfigError::Message(format!("Failed to open file '{}': {}", filename, e)))?;
                        let list: crate::protos::common::GeoIPList =
                            protobuf::Message::parse_from_reader(&mut f)
                                .map_err(|e| ConfigError::Message(format!("Failed to parse GeoIPList '{}': {}", filename, e)))?;
                         list.entry
                             .iter()
                             .filter(|&l| l.country_code.to_lowercase() == region.to_lowercase())
                             .for_each(|geoip| {
                                 geoip.cidr.iter().for_each(|cidr| {
                                     if let Some(net) = cidr_to_ipv6net(cidr) {
                                         cond.dst_ip_table.insert(net.addr(), net.prefix_len() as u32, net.prefix_len());
                                     }
                                 });
                             });
                    }
                    _ => {
                        return Err(ConfigError::Message(
                            "GEOIP filename must end with .mmdb or .dat".to_string()
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
                    .ok_or_else(|| ConfigError::Message("GEOSITE rule must be in format: GEOSITE,filename,code".to_string()))?;
 
                let outbound_index = route.get_outbound_index_by_name(outbound_name)
                    .ok_or_else(|| ConfigError::Message(format!("Outbound '{}' not found", outbound_name)))?;
                let domains = &mut domain_sets[outbound_index as usize];
 
                let mut f = std::fs::File::open(filename)
                    .map_err(|e| ConfigError::Message(format!("Failed to open file '{}': {}", filename, e)))?;
                let list: crate::protos::common::GeoSiteList =
                    protobuf::Message::parse_from_reader(&mut f)
                        .map_err(|e| ConfigError::Message(format!("Failed to parse geosite.dat '{}': {}", filename, e)))?;
                list.entry
                    .iter()
                    .filter(|&geosites| geosites.country_code.to_lowercase() == code.to_lowercase())
                    .map(|e| &e.domain)
                    .for_each(|ds| {
                        ds.iter().for_each(|d| {
                            match d.type_.enum_value() {
                                Ok(crate::protos::common::domain::Type::Plain) => {
                                    domains.insert(d.value.to_owned());
                                }
                                Ok(crate::protos::common::domain::Type::Regex) => { /* Not supported. */
                                }
                                Ok(crate::protos::common::domain::Type::RootDomain) => {
                                    domains.insert(format!(".{}{}", d.value, RULE_DOMAIN_SUFFIX_TAG));
                                }
                                Ok(crate::protos::common::domain::Type::Full) => {
                                    domains.insert(format!("^{}$", d.value));
                                }
                                Err(_) => { /* Unknown type, skip */ }
                            }
                        })
                    });
            }
            tag @ ("DOMAIN" | "DOMAIN-SUFFIX") => {
                let outbound_index = route
                    .get_outbound_index_by_name(outbound_name)
                    .ok_or_else(|| ConfigError::Message(format!("Outbound '{}' not found", outbound_name)))?;
                let domains = &mut domain_sets[outbound_index as usize];
                match tag {
                    "DOMAIN" => {
                        domains.insert(param.to_string());
                    }
                    "DOMAIN-SUFFIX" => {
                        domains.insert(param.to_string() + RULE_DOMAIN_SUFFIX_TAG);
                    }
                    _ => {}
                }
            }
            e @ _ => {
                return Err(ConfigError::Message(format!("'{}' is not a valid rule keyword", e)));
            }
        }
    }

    for (i, v) in domain_sets.iter().enumerate() {
        let cond = route.rules.get_mut(i)
            .ok_or_else(|| ConfigError::Message(format!("Invalid rule index: {}", i)))?;
        cond.domains = Some(aho_corasick::AhoCorasick::new(v.iter())
            .map_err(|e| ConfigError::Message(format!("Failed to build domain matcher: {}", e)))?);
    }

    Ok(())
}