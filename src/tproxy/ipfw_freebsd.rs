//! FreeBSD transparent interception using ipfw ``fwd``.
//!
//! ``ipfw fwd <local-address>,<port>`` is the FreeBSD equivalent of Linux
//! TPROXY for locally delivered packets: the packet header is left untouched and
//! the local socket is bound to the original destination address. Combined with
//! ``IP_BINDANY`` on the listener, this lets rfor accept the original connection
//! and preserve the destination for TCP. UDP uses ``IP_ORIGDSTADDR`` for the
//! original destination and ``IP_BINDANY`` for replies from that address.

use anyhow::{anyhow, Context, Result};
use std::process::{Command, Output};

const RESERVED_V4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
];

const RESERVED_V6: &[&str] = &[
    "::1/128",
    "100::/64",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "::ffff:0:0/96",
    "::ffff:0:0:0/96",
];

fn ipfw(args: &[String]) -> Result<Output> {
    Command::new("ipfw")
        .args(args)
        .output()
        .context("failed to execute ipfw; is the ipfw kernel module available?")
}

fn run_ok(args: Vec<String>) -> Result<()> {
    let output = ipfw(&args)?;
    if !output.status.success() {
        return Err(anyhow!(
            "ipfw {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn sanitize(value: &str) -> String {
    let value: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect();
    if value.is_empty() {
        "rfor".to_owned()
    } else {
        value
    }
}

fn table_name(chain: &str, port: u16) -> String {
    format!("rfor_{}_{}", port, sanitize(chain))
}

fn marker(chain: &str) -> String {
    format!("rfor:{}", sanitize(chain))
}

fn local_addresses() -> Result<Vec<String>> {
    use nix::sys::socket::{AddressFamily, SockaddrLike};

    let mut addresses = Vec::new();
    for interface in nix::ifaddrs::getifaddrs()? {
        let Some(address) = interface.address else {
            continue;
        };
        match address.family() {
            Some(AddressFamily::Inet) => {
                if let Some(addr) = address.as_sockaddr_in() {
                    addresses.push(format!("{}/32", addr.ip()));
                }
            }
            Some(AddressFamily::Inet6) => {
                if let Some(addr) = address.as_sockaddr_in6() {
                    addresses.push(format!("{}/128", addr.ip()));
                }
            }
            _ => {}
        }
    }
    Ok(addresses)
}

fn cleanup_rules(marker: &str) -> Result<()> {
    let output = ipfw(&["list".to_owned()])?;
    if !output.status.success() {
        return Err(anyhow!(
            "ipfw list failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((_, comment)) = line.split_once("//") else {
            continue;
        };
        if comment.trim() != marker {
            continue;
        }
        let Some(number) = line.split_whitespace().next() else {
            continue;
        };
        // Ignore malformed output rather than risking deletion of an unrelated rule.
        if number.parse::<u16>().is_err() {
            continue;
        }
        let _ = ipfw(&["delete".to_owned(), number.to_owned()]);
    }
    Ok(())
}

/// Install the FreeBSD ipfw rules and address table for one rfor instance.
pub async fn setup(
    tproxy_port: u16,
    ports: &str,
    local_traffic: bool,
    rule_base: u16,
    chain: &str,
    enable_ipv6: bool,
    udp_enable: bool,
) -> Result<()> {
    if ports.trim().is_empty() {
        return Err(anyhow!(
            "traffic-intercept.ports must not be empty in ipfw mode"
        ));
    }
    if rule_base < 100 || rule_base > 65_500 {
        return Err(anyhow!(
            "ipfw-rule-base must be between 100 and 65500, got {rule_base}"
        ));
    }
    if crate::utils::geteuid() != 0 {
        return Err(anyhow!("must be root to configure ipfw"));
    }

    let marker = marker(chain);
    let table = table_name(chain, tproxy_port);

    // Recover from a previous crash before installing the new rules.
    cleanup_rules(&marker)?;
    let _ = ipfw(&["table".to_owned(), table.clone(), "destroy".to_owned()]);
    run_ok(vec!["table".to_owned(), table.clone(), "create".to_owned()])?;

    let setup_result = (|| -> Result<()> {
        let local = local_addresses()?;
        let mut addresses_v4: Vec<String> = RESERVED_V4.iter().map(|s| (*s).to_owned()).collect();
        addresses_v4.extend(
            local
                .iter()
                .filter(|address| !address.contains(':'))
                .cloned(),
        );
        addresses_v4.sort();
        addresses_v4.dedup();

        for address in addresses_v4 {
            run_ok(vec![
                "table".to_owned(),
                table.clone(),
                "add".to_owned(),
                address,
            ])?;
        }

        if enable_ipv6 {
            let mut addresses_v6: Vec<String> =
                RESERVED_V6.iter().map(|s| (*s).to_owned()).collect();
            addresses_v6.extend(
                local
                    .iter()
                    .filter(|address| address.contains(':'))
                    .cloned(),
            );
            addresses_v6.sort();
            addresses_v6.dedup();
            for address in addresses_v6 {
                run_ok(vec![
                    "table".to_owned(),
                    table.clone(),
                    "add".to_owned(),
                    address,
                ])?;
            }
        }

        // ipfw uses '-' for port ranges; rfor's config uses the Linux-style ':'
        // notation shared with the other interception modes.
        let ipfw_ports = ports.replace(':', "-");
        let mut rule = rule_base;
        let mut add_rule = |body: String| -> Result<()> {
            if rule > 65_534 {
                return Err(anyhow!(
                    "ipfw rule range exhausted at rule {rule}; lower ipfw-rule-base"
                ));
            }
            // ipfw expects every rule token as a separate argv entry. A
            // single whitespace-containing body is interpreted as one invalid
            // action, so split on whitespace just like the shell would.
            let mut args = vec!["add".to_owned(), rule.to_string()];
            args.extend(body.split_whitespace().map(str::to_owned));
            args.extend(["//".to_owned(), marker.clone()]);
            run_ok(args)?;
            rule += 1;
            Ok(())
        };

        for (protocol, is_udp) in [("tcp", false), ("udp", true)] {
            if is_udp && !udp_enable {
                continue;
            }

            add_rule(format!(
                "fwd 127.0.0.1,{tproxy_port} {protocol} from any to not table({table}) {ipfw_ports} ipversion 4 in"
            ))?;

            if local_traffic {
                // rfor marks its own sockets with SO_USER_COOKIE; sockarg lets
                // the output rule exclude those connections without relying on
                // a dedicated uid or a second routing table.
                add_rule(format!(
                    "fwd 127.0.0.1,{tproxy_port} {protocol} from any to not table({table}) {ipfw_ports} ipversion 4 not sockarg out"
                ))?;
            }

            if enable_ipv6 {
                add_rule(format!(
                    "fwd ::1,{tproxy_port} {protocol} from any to not table({table}) {ipfw_ports} ipversion 6 in"
                ))?;
                if local_traffic {
                    add_rule(format!(
                        "fwd ::1,{tproxy_port} {protocol} from any to not table({table}) {ipfw_ports} ipversion 6 not sockarg out"
                    ))?;
                }
            }
        }

        Ok(())
    })();

    if let Err(error) = setup_result {
        let _ = cleanup_rules(&marker);
        let _ = ipfw(&["table".to_owned(), table, "destroy".to_owned()]);
        return Err(error);
    }

    Ok(())
}

pub async fn cleanup(chain: &str, tproxy_port: u16) -> Result<()> {
    if crate::utils::geteuid() != 0 {
        return Ok(());
    }
    cleanup_rules(&marker(chain))?;
    let table = table_name(chain, tproxy_port);
    let _ = ipfw(&["table".to_owned(), table, "destroy".to_owned()]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_linux_port_ranges_for_ipfw() {
        assert_eq!("80,443,8080:8082".replace(':', "-"), "80,443,8080-8082");
    }

    #[test]
    fn table_names_are_bounded_and_identifier_safe() {
        assert_eq!(table_name("rfor-proxy", 15080), "rfor_15080_rforproxy");
        assert!(table_name(&"x".repeat(200), 65535).len() <= 32);
    }

    #[test]
    fn marker_is_identifier_safe() {
        assert_eq!(marker("rfor-proxy"), "rfor:rforproxy");
    }
}
