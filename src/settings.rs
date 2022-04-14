use std::collections::{HashMap, HashSet};

use clap::Parser;
use itertools::Itertools;

use config::{Config, ConfigError, Environment, File};
use ipnet::IpNet;

use crate::rules::{Outbound, RouteRule, RouteTable, Condition, RULE_DOMAIN_SUFFIX_TAG};

use crate::utils::{BoomHashSet, ToV6Net};

const DIRECT_OUTBOUND_NAME: &str = "DIRECT";
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
    AUTO {
        local_traffic: bool,
        ports: Vec<u16>,
        proxy_mark: u32,
        direct_mark: u32,
        proxy_chain: String,
        mark_chain: String,
        rule_table_index: u8,
    },
    MANUAL,
}

pub struct Settings {
    pub debug: bool,
    pub tproxy_listen: Option<String>,
    pub socks5_listen: Option<String>,
    pub outbounds: RouteTable,
    pub intercept_mode: InterceptMode,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let args = Args::parse();
        std::env::set_current_dir(args.work_dir).unwrap();

        let mut s = Config::new();
        s.merge(File::with_name(&args.config))?;
        s.merge(Environment::with_prefix("rfor"))?;

        /* 1. Setup the initial rules object. */
        let mut route = RouteTable {
            default: Outbound {
                name: "direct-implicitly".to_owned(),
                url: None,
                bind_range: None,
            },
            outbound_dict: HashMap::new(),
            ip_db: None,
        };

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

            route.add(name, url, Some(bind_range));
        }

        /* 3. Populate the DIRECT rule. */
        if route.outbound_dict.get(DIRECT_OUTBOUND_NAME).is_none() {
            route.outbound_dict.insert(
                DIRECT_OUTBOUND_NAME.to_string(),
                RouteRule(
                    Outbound {
                        name: DIRECT_OUTBOUND_NAME.to_owned(), 
                        url: None, 
                        bind_range: None},
                    None,
                ),
            );
        }

        /* 3. Parse the actual rules. */
        parse_forwarder_rules(&mut s, &mut route)?;

        /* 4. Parse the Intercept Mode */
        let intercept_mode = parse_intercept_mode(&mut s)?;

        let settings = Settings {
            debug: s.get_bool("debug").unwrap_or(false),
            tproxy_listen: s.get::<String>("tproxy-listen").ok(),
            socks5_listen: s.get::<String>("socks5-listen").ok(),
            outbounds: route,
            intercept_mode,
        };

        Ok(settings)
    }
}

fn parse_intercept_mode(s: &mut Config) -> Result<InterceptMode, ConfigError> {
    match s.get_table("traffic-intercept") {
        Err(_) => return Ok(InterceptMode::MANUAL),
        Ok(table) => {
            let mode = table
                .get("mode")
                .expect("mode field not found.")
                .clone()
                .into_str()?;
            match mode.as_str() {
                "manual" => return Ok(InterceptMode::MANUAL),
                "auto" => {
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

                    let ports: Vec<u16> = table
                        .get("ports")
                        .and_then(|v| {
                            Some(v.clone().into_array().expect("ports field need a vector"))
                        })
                        .unwrap_or(vec![])
                        .into_iter()
                        .map(|v| v.into_int().expect("ports field need a vector of ints") as u16)
                        .collect();

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
                                    .expect("rule-table field need an int") as u8
                            )
                        })
                        .unwrap_or(DEFAULT_IPRULE_TABLE);

                    return Ok(InterceptMode::AUTO {
                        local_traffic: capture_local_traffic,
                        ports,
                        proxy_mark,
                        direct_mark,
                        proxy_chain,
                        rule_table_index,
                        mark_chain,
                    });
                }
                _ => Err(ConfigError::Message(
                    "either `auto` or `manual` is expected.".to_owned(),
                )),
            }
        }
    }
}

fn parse_forwarder_rules(s: &mut Config, route: &mut RouteTable) -> Result<(), ConfigError> {
    let mut domain_dict: HashMap<String, HashSet<_>> = HashMap::new();
    for rule in s.get_array("rules").unwrap_or_default() {
        let rule = rule.into_str()?;
        let (keyword, param, outbound_name) = rule
            .split(",")
            .into_iter()
            .map(|v| v.trim())
            .collect_tuple::<_>()
            .expect("Expect a (keyword, param, outbound_name) tuple.");

        let o_rule = route
            .outbound_dict
            .get_mut(outbound_name)
            .expect(format!("Outbound {} is not found.", outbound_name).as_str());

        if o_rule.1.is_none() {
            o_rule.1 = Some(Condition::default());
        }
        let rules = o_rule.1.as_mut().unwrap();

        match keyword {
            "DEFAULT" => {
                route.default = o_rule.0.clone();
            }
            "IP-CIDR" => {
                rules.dst_ip_range.add(
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
                let maxmind_reader = maxminddb::Reader::open_readfile(filename).unwrap();
                route.ip_db = Some(maxmind_reader);
                rules.maxmind_regions.push(region.to_string());
            }
            tag @ ("DOMAIN" | "DOMAIN-SUFFIX") => {
                let domains = domain_dict
                    .entry(outbound_name.to_owned())
                    .or_insert(HashSet::new());
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

    for (k, v) in domain_dict.iter() {
        let o_rule = route.outbound_dict.get_mut(k).unwrap();
        o_rule.1.as_mut().unwrap().domains =
            Some(BoomHashSet::new(v.to_owned().into_iter().collect_vec()));
    }

    Ok(())
}
