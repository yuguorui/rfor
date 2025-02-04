use std::collections::HashSet;

use clap::Parser;
use itertools::Itertools;

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
#[clap(author, version, about, long_about = None)]
struct Args {
    /// config file filepath
    #[clap(short, long, default_value = "config.yaml")]
    config: String,

    /// working directory
    #[clap(short, long, default_value = ".")]
    work_dir: String,
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
    pub disable_ipv6: bool,
    pub tproxy_listen: Option<String>,
    pub socks5_listen: Option<String>,
    pub redirect_listen: Option<String>,
    pub routetable: RouteTable,
    pub intercept_mode: InterceptMode,
    pub udp_enable: bool,
    pub udp_timeout: u64,
    pub udp_fullcone: bool,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let args = Args::parse();
        std::env::set_current_dir(args.work_dir).unwrap();

        let mut s = Config::new();
        s.merge(File::with_name(&args.config))?;
        s.merge(Environment::with_prefix("rfor"))?;

        /* 1. Setup the initial rules object. */
        let mut route = RouteTable::new();

        /* 2. Parse the outbounds section */
        for outbound_value in s.get_array("outbounds").unwrap_or_default() {
            let outbound = outbound_value.into_table()?;

            let name = outbound
                .get("name")
                .expect("Not found the name of outbound.")
                .clone()
                .into_str()?;
            let url = outbound.get("url").and_then(|v| {
                Some(
                    v.clone()
                        .into_str()
                        .expect("Expect string in the url field.")
                        .parse()
                        .expect("Expect a valid url."),
                )
            });

            let mut bind_range = iprange::IpRange::<ipnet::Ipv6Net>::new();

            if let Some(items) = outbound.get("bind_range") {
                for item in items.to_owned().into_array()? {
                    bind_range.add(
                        item.into_str()?
                            .parse()
                            .expect("Wrong format for bind_range."),
                    );
                }
            }

            route.add_empty_rule(name, url, Some(bind_range));
        }

        /* 3. Populate the DIRECT/DROP rule. */
        if route.get_outbound_by_name(DIRECT_OUTBOUND_NAME).is_none() {
            route.add_empty_rule(DIRECT_OUTBOUND_NAME.to_owned(), None, None);
        }

        if route.get_outbound_by_name(DROP_OUTBOUND_NAME).is_none() {
            route.add_empty_rule(
                DROP_OUTBOUND_NAME.to_owned(),
                Some("drop://0.0.0.0".parse().unwrap()),
                None,
            );
        }

        /* 4. Parse the actual rules. */
        parse_route_rules(&mut s, &mut route)?;

        /* 5. Parse the Intercept Mode */
        let intercept_mode = parse_intercept_mode(&mut s)?;

        /* 6. Parse the UDP enabling */
        let udp_enable = match &intercept_mode {
            InterceptMode::TPROXY { .. } | InterceptMode::MANUAL => s.get_bool("udp-enable").unwrap_or(true),
            InterceptMode::REDIRECT { .. } => {
                println!("UDP is not supported in REDIRECT mode, disabling it.");
                false
            },
        };

        let settings = Settings {
            debug: s.get_bool("debug").unwrap_or(false),
            disable_ipv6: s.get_bool("disable-ipv6").unwrap_or(false),
            tproxy_listen: s.get::<String>("tproxy-listen").ok(),
            socks5_listen: s.get::<String>("socks5-listen").ok(),
            redirect_listen: s.get::<String>("redirect-listen").ok(),
            routetable: route,
            intercept_mode,
            udp_enable,
            udp_timeout: s.get_int("udp-timeout").unwrap_or(60) as u64,
            udp_fullcone: s.get_bool("udp-fullcone").unwrap_or(false),
        };

        Ok(settings)
    }
}

fn santize_port_ranges(s: &Vec<config::Value>) -> Vec<[u16; 2]> {
    let mut ranges = s.iter()
        .map(|v| {
            let v = v.clone().into_str().expect("port must be a string");
            if !v.contains("-") {
                let v = v.parse::<u16>().expect("port must contain a number");
                return [v, v];
            }

            let (start, end) = v.split("-").collect_tuple::<_>().expect("port range must be start-end");
            let start = start.parse::<u16>().expect("start must be a number");
            let end = end.parse::<u16>().expect("end must be a number");
            return [start, end];
        })
        .collect::<Vec<_>>();

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
    return ranges;
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

fn parse_intercept_mode(s: &mut Config) -> Result<InterceptMode, ConfigError> {
    match s.get_table("traffic-intercept") {
        Err(_) => return Ok(InterceptMode::MANUAL),
        Ok(table) => {
            let mode = table
                .get("mode")
                .expect("mode field not found.")
                .clone()
                .into_str()?
                .to_lowercase();
            match mode.as_str() {
                "manual" => return Ok(InterceptMode::MANUAL),
                "auto" | "tproxy" | "redirect" => {
                    let capture_local_traffic = table
                        .get("local-traffic")
                        .and_then(|v| {
                            Some(
                                v.clone()
                                    .into_bool()
                                    .expect("local-traffic field needs a bool value"),
                            )
                        })
                        .unwrap_or(false);

                    let ports = table.get("ports").and_then(|v| {
                        let ranges = santize_port_ranges(
                            &v.clone().into_array().expect("ports field need an array"),
                        );

                        let ports_str = port_range_to_string(&ranges);
                        Some(ports_str)
                    });

                    let proxy_mark = table
                        .get("proxy-mark")
                        .and_then(|v| {
                            Some(
                                v.to_owned()
                                    .into_int()
                                    .expect("tproxy-mark field need an int")
                                    as u32,
                            )
                        })
                        .unwrap_or(DEFAULT_IPTABLES_PROXY_MARK);

                    let direct_mark = table
                        .get("direct-mark")
                        .and_then(|v| {
                            Some(
                                v.to_owned()
                                    .into_int()
                                    .expect("direct-xmark field need an int")
                                    as u32,
                            )
                        })
                        .unwrap_or(DEFAULT_IPTABLES_DIRECT_MARK);

                    let proxy_chain = table
                        .get("tproxy-proxy-chain")
                        .and_then(|v| {
                            Some(
                                v.to_owned()
                                    .into_str()
                                    .expect("tproxy-proxy-chain field need an str"),
                            )
                        })
                        .unwrap_or(DEFAULT_IPTABLES_PROXY_CHAIN_NAME.to_owned());

                    let mark_chain = table
                        .get("tproxy-mark-chain")
                        .and_then(|v| {
                            Some(
                                v.to_owned()
                                    .into_str()
                                    .expect("tproxy-mark-chain field need an str"),
                            )
                        })
                        .unwrap_or(DEFAULT_IPTABLES_MARK_CHAIN_NAME.to_owned());

                    let rule_table_index = table
                        .get("rule-table")
                        .and_then(|v| {
                            Some(
                                v.to_owned()
                                    .into_int()
                                    .expect("rule-table field need an int")
                                    as u8,
                            )
                        })
                        .unwrap_or(DEFAULT_IPRULE_TABLE);

                    if mode.as_str() != "redirect" {
                        return Ok(InterceptMode::TPROXY {
                            local_traffic: capture_local_traffic,
                            ports: ports.unwrap_or_default(),
                            proxy_mark,
                            direct_mark,
                            proxy_chain,
                            rule_table_index,
                            mark_chain,
                        });
                    } else {
                        return Ok(InterceptMode::REDIRECT {
                            local_traffic: capture_local_traffic,
                            ports: ports.unwrap_or_default(),
                            direct_mark,
                            proxy_chain,
                        });
                    }
                }
                _ => Err(ConfigError::Message(
                    "either `auto/tproxy`, `redirect` or `manual` is expected.".to_owned(),
                )),
            }
        }
    }
}

fn parse_route_rules(s: &mut Config, route: &mut RouteTable) -> Result<(), ConfigError> {
    let mut domain_sets: Vec<HashSet<_>> = vec![HashSet::new(); route.outbounds.len()];

    for user_rule in s.get_array("rules").unwrap_or_default() {
        let rule = user_rule.into_str()?;
        let (keyword, param, outbound_name) = rule
            .split(",")
            .into_iter()
            .map(|v| v.trim())
            .collect_tuple::<_>()
            .expect("Expect a (keyword, param, outbound_name) tuple.");

        let outbound_index = route
            .get_outbound_index_by_name(outbound_name)
            .expect(format!("Outbound {} is not found.", outbound_name).as_str());

        let cond = &mut route.rules[outbound_index as usize];

        match keyword {
            "DEFAULT" => {
                route.set_default_route(outbound_index);
            }
            "IP-CIDR" => {
                cond.dst_ip_range.add(
                    param
                        .parse::<IpNet>()
                        .expect("Wrong format for IP-CIDR.")
                        .to_ipv6_net()
                        .unwrap(),
                );
            }
            "GEOIP" => {
                let (filename, region) = param
                    .split(":")
                    .into_iter()
                    .map(|v| v.trim())
                    .collect_tuple::<_>()
                    .expect("Expect a (filename, region) tuple.");
                match filename {
                    name if name.ends_with(".mmdb") => {
                        let maxmind_reader = maxminddb::Reader::open_readfile(filename)
                            .map_err(|e| ConfigError::Message(format!("Failed to open file '{}' with error: {}", filename, e)))?;
                        route.ip_db = Some(maxmind_reader);
                        cond.maxmind_regions.push(region.to_string().to_lowercase());
                    }
                    name if name.ends_with(".dat") => {
                        let mut f = std::fs::File::open(filename)
                            .expect(format!("file {} not found", filename).as_str());
                        let mut b = protobuf::CodedInputStream::new(&mut f);
                        let list: crate::protos::common::GeoIPList =
                            protobuf::Message::parse_from(&mut b)
                                .expect(format!("failed to parse GeoIPList {}", filename).as_str());
                        list.entry
                            .iter()
                            .filter(|&l| l.country_code.to_lowercase() == region.to_lowercase())
                            .for_each(|geoip| {
                                geoip.cidr.iter().for_each(|cidr| {
                                    match cidr.ip.len() {
                                        4 => {
                                            cond.dst_ip_range.add(
                                                ipnet::Ipv6Net::new(
                                                    Ipv4Addr::from(
                                                        vec_to_array(cidr.ip.to_owned()).unwrap(),
                                                    )
                                                    .to_ipv6_mapped(),
                                                    cidr.prefix.try_into().unwrap(),
                                                )
                                                .unwrap(),
                                            );
                                        }
                                        16 => {
                                            cond.dst_ip_range.add(
                                                ipnet::Ipv6Net::new(
                                                    Ipv6Addr::from(
                                                        vec_to_array(cidr.ip.to_owned()).unwrap(),
                                                    ),
                                                    cidr.prefix.try_into().unwrap(),
                                                )
                                                .unwrap(),
                                            );
                                        }
                                        _ => {}
                                    };
                                });
                            });
                    }
                    _ => {
                        return Err(ConfigError::Message(format!(
                            "GEOIP filename must end with .mmdb or .dat"
                        )))
                    }
                }
            }
            "GEOSITE" => {
                let (filename, code) = param
                    .split(":")
                    .into_iter()
                    .map(|v| v.trim())
                    .collect_tuple::<_>()
                    .expect("Expect a (filename, code) tuple.");

                let domains = &mut domain_sets[route
                    .get_outbound_index_by_name(outbound_name)
                    .expect(format!("outbound {} not found", outbound_name).as_str())
                    as usize];

                let mut f = std::fs::File::open(filename)
                    .expect(format!("file {} not found", filename).as_str());
                let mut b = protobuf::CodedInputStream::new(&mut f);
                let list: crate::protos::common::GeoSiteList =
                    protobuf::Message::parse_from(&mut b).expect("Failed to parse geosite.dat");
                list.entry
                    .iter()
                    .filter(|&geosites| geosites.country_code.to_lowercase() == code.to_lowercase())
                    .map(|e| &e.domain)
                    .map(|ds| {
                        ds.iter().for_each(|d| {
                            match d.field_type {
                                crate::protos::common::Domain_Type::Plain => {
                                    domains.insert(d.value.to_owned());
                                }
                                crate::protos::common::Domain_Type::Regex => { /* Not supported. */
                                }
                                crate::protos::common::Domain_Type::RootDomain => {
                                    domains.insert(format!(".{}{}", d.value, RULE_DOMAIN_SUFFIX_TAG));
                                }
                                crate::protos::common::Domain_Type::Full => {
                                    domains.insert(format!("^{}$", d.value));
                                }
                            }
                        })
                    })
                    .for_each(drop);
            }
            tag @ ("DOMAIN" | "DOMAIN-SUFFIX") => {
                let domains = &mut domain_sets[route
                    .get_outbound_index_by_name(outbound_name)
                    .expect(format!("outbound {} not found", outbound_name).as_str())
                    as usize];
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
                panic!("{} is not a valid rule keyword.", e);
            }
        }
    }

    for (i, v) in domain_sets.iter().enumerate() {
        let cond = route.rules.get_mut(i).unwrap();
        cond.domains = Some(aho_corasick::AhoCorasick::new(v.iter()).unwrap());
    }

    Ok(())
}