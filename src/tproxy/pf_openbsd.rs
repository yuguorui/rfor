//! OpenBSD transparent interception using PF divert-to.
//!
//! OpenBSD's PF divert-to action delivers a packet to a local TCP or UDP
//! socket without rewriting its headers. A TCP listener therefore gets the
//! original destination from getsockname(2); a UDP listener gets the original
//! destination through IP_RECVDSTADDR/IP_RECVDSTPORT (IPv4) or
//! IPV6_PKTINFO/IPV6_RECVDSTPORT (IPv6). This is the mechanism used by
//! relayd's "forward to destination" mode and avoids the privileged
//! DIOCNATLOOK API required by older rdr-to based proxies.
//!
//! PF rules are installed in a per-instance anchor. The main ruleset must
//! contain an anchor "rfor/*" reference; the anchor cannot be attached to an
//! already-running ruleset safely from userland.
//!
//! This first OpenBSD backend is forwarded-traffic only. Local output capture
//! needs a loopback detour and a reliable socket marker; neither path has been
//! live-tested yet, so local-traffic: true is rejected at startup.

use anyhow::{anyhow, Context, Result};
use std::fmt::Write as _;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Output, Stdio};

use ipnet::{Ipv4Net, Ipv6Net};

const ANCHOR_PARENT: &str = "rfor";

const RESERVED_V4: &[&str] = &[
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

const RESERVED_V6: &[&str] = &[
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

fn anchor_name(chain: &str, port: u16) -> String {
    format!("{ANCHOR_PARENT}/{}_{}", port, sanitize(chain))
}

fn validate_ports(ports: &str) -> Result<()> {
    if ports.trim().is_empty() {
        return Err(anyhow!(
            "traffic-intercept.ports must not be empty in OpenBSD pf mode"
        ));
    }
    if !ports
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, ',' | ':'))
    {
        return Err(anyhow!(
            "invalid traffic-intercept.ports value for pf: {ports}"
        ));
    }
    Ok(())
}

fn ensure_forwarded_only(local_traffic: bool) -> Result<()> {
    if local_traffic {
        return Err(anyhow!(
            "OpenBSD local-traffic interception is not supported in this version; set traffic-intercept.local-traffic: false"
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

fn table(entries: impl IntoIterator<Item = String>) -> String {
    let entries: Vec<String> = entries.into_iter().collect();
    format!("{{ {} }}", entries.join(", "))
}

/// Split configured bind_range IPv6 networks into PF-usable IPv4 and IPv6
/// source tables. IPv4 clients are represented internally as IPv4-mapped IPv6,
/// so map those prefixes back before handing them to an inet rule.
fn source_tables(ranges: &[Ipv6Net]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for range in ranges {
        let prefix = range.prefix_len();
        let octets = range.network().octets();
        let is_mapped =
            octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff;
        if prefix >= 96 && is_mapped {
            let addr = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
            if let Ok(net) = Ipv4Net::new(addr, prefix - 96) {
                v4.push(net.to_string());
            }
        } else if !range.network().is_unspecified() {
            v6.push(range.to_string());
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    (v4, v6)
}

fn render_rules(
    tproxy_port: u16,
    ports: &str,
    disable_ipv6: bool,
    udp_enable: bool,
    local_v4: &[String],
    local_v6: &[String],
    source_v4: &[String],
    source_v6: &[String],
) -> Result<String> {
    validate_ports(ports)?;

    let mut v4: Vec<String> = RESERVED_V4.iter().map(|s| (*s).to_owned()).collect();
    v4.extend(local_v4.iter().cloned());
    v4.sort();
    v4.dedup();

    let mut v6: Vec<String> = RESERVED_V6.iter().map(|s| (*s).to_owned()).collect();
    v6.extend(local_v6.iter().cloned());
    v6.sort();
    v6.dedup();

    let mut rules = String::new();
    writeln!(rules, "# rfor OpenBSD PF anchor")?;
    writeln!(rules, "table <rfor_np4> {}", table(v4))?;
    if !disable_ipv6 {
        writeln!(rules, "table <rfor_np6> {}", table(v6))?;
    }
    if !source_v4.is_empty() {
        writeln!(rules, "table <rfor_src4> {}", table(source_v4.to_vec()))?;
    }
    if !disable_ipv6 && !source_v6.is_empty() {
        writeln!(rules, "table <rfor_src6> {}", table(source_v6.to_vec()))?;
    }

    let port_set = format!("{{ {ports} }}");
    let families = if disable_ipv6 {
        vec![("inet", "127.0.0.1", "<rfor_np4>")]
    } else {
        vec![
            ("inet", "127.0.0.1", "<rfor_np4>"),
            ("inet6", "::1", "<rfor_np6>"),
        ]
    };

    // Only configured bind_range sources and intercepted ports get
    // divert-reply rules. Non-intercepted ports must keep normal forwarding;
    // otherwise a broad bind_range would capture unrelated direct flows such
    // as PT peer traffic. There is no catch-all non-local source rule: a
    // packet with an unrelated spoofed source must not be admitted here.
    if !source_v4.is_empty() {
        writeln!(
            rules,
            "pass out quick inet proto tcp from <rfor_src4> to any port {port_set} divert-reply"
        )?;
        if udp_enable {
            writeln!(
                rules,
                "pass out quick inet proto udp from <rfor_src4> to any port {port_set} divert-reply"
            )?;
        }
    }
    if !disable_ipv6 && !source_v6.is_empty() {
        writeln!(
            rules,
            "pass out quick inet6 proto tcp from <rfor_src6> to any port {port_set} divert-reply"
        )?;
        if udp_enable {
            writeln!(
                rules,
                "pass out quick inet6 proto udp from <rfor_src6> to any port {port_set} divert-reply"
            )?;
        }
    }

    for (family, listener, no_proxy) in &families {
        writeln!(
            rules,
            "pass in quick {family} proto tcp from any to ! {no_proxy} port {port_set} divert-to {listener} port {tproxy_port}"
        )?;
        if udp_enable {
            writeln!(
                rules,
                "pass in quick {family} proto udp from any to ! {no_proxy} port {port_set} divert-to {listener} port {tproxy_port}"
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
        .context("failed to execute pfctl; is pf enabled?")?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to open pfctl stdin"))?
            .write_all(input.as_bytes())
            .context("failed to write pf rules to pfctl")?;
    }
    child.wait_with_output().context("failed to wait for pfctl")
}

fn command_error(args: &[&str], output: &Output) -> anyhow::Error {
    anyhow!(
        "pfctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn ensure_anchor_reference(anchor: &str) -> Result<()> {
    let output = pfctl(&["-sr"], None)?;
    if !output.status.success() {
        return Err(command_error(&["-sr"], &output));
    }

    let exact = format!("anchor \"{anchor}\"");
    let wildcard = format!("anchor \"{ANCHOR_PARENT}/*\"");
    let referenced = String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
        normalized.starts_with(&exact) || normalized.starts_with(&wildcard)
    });
    if !referenced {
        return Err(anyhow!(
            "pf is not evaluating the rfor anchor; add 'anchor \"rfor/*\"' to /etc/pf.conf after the block rules and reload pf"
        ));
    }
    Ok(())
}

fn flush_anchor(anchor: &str) -> Result<()> {
    let output = pfctl(&["-a", anchor, "-F", "all"], None)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(&["-a", anchor, "-F", "all"], &output))
    }
}

fn load_anchor(anchor: &str, rules: &str) -> Result<()> {
    let output = pfctl(&["-a", anchor, "-f", "-"], Some(rules))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(&["-a", anchor, "-f", "-"], &output))
    }
}

/// Install the OpenBSD PF divert rules and scoped source-preservation table.
pub async fn setup(
    tproxy_port: u16,
    ports: &str,
    local_traffic: bool,
    chain: &str,
    disable_ipv6: bool,
    udp_enable: bool,
    bind_ranges: &[Ipv6Net],
) -> Result<()> {
    ensure_forwarded_only(local_traffic)?;
    if crate::utils::geteuid() != 0 {
        return Err(anyhow!("must be root to configure pf"));
    }

    let (local_v4, local_v6) = local_addresses()?;
    let (source_v4, source_v6) = source_tables(bind_ranges);
    let rules = render_rules(
        tproxy_port,
        ports,
        disable_ipv6,
        udp_enable,
        &local_v4,
        &local_v6,
        &source_v4,
        &source_v6,
    )?;
    let anchor = anchor_name(chain, tproxy_port);

    ensure_anchor_reference(&anchor)?;
    let _ = flush_anchor(&anchor);
    if let Err(error) = load_anchor(&anchor, &rules) {
        let _ = flush_anchor(&anchor);
        return Err(error);
    }

    let output = pfctl(&["-a", &anchor, "-sr"], None)?;
    if !output.status.success() {
        let _ = flush_anchor(&anchor);
        return Err(command_error(&["-a", &anchor, "-sr"], &output));
    }
    if String::from_utf8_lossy(&output.stdout).trim().is_empty() {
        let _ = flush_anchor(&anchor);
        return Err(anyhow!("pf loaded no rules into anchor {anchor}"));
    }

    Ok(())
}

pub async fn cleanup(chain: &str, tproxy_port: u16) -> Result<()> {
    if crate::utils::geteuid() != 0 {
        return Ok(());
    }
    let _ = flush_anchor(&anchor_name(chain, tproxy_port));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rules(
        disable_ipv6: bool,
        udp_enable: bool,
        source_v4: &[String],
        source_v6: &[String],
    ) -> String {
        render_rules(
            15080,
            "80,443,8080:8082",
            disable_ipv6,
            udp_enable,
            &["192.0.2.10/32".to_owned()],
            &["2001:db8::1/128".to_owned()],
            source_v4,
            source_v6,
        )
        .unwrap()
    }

    #[test]
    fn anchor_names_are_bounded_and_safe() {
        assert_eq!(anchor_name("rfor-proxy", 15080), "rfor/15080_rforproxy");
        assert!(anchor_name(&"x".repeat(200), 65535).len() < 64);
    }

    #[test]
    fn local_traffic_is_rejected() {
        assert!(ensure_forwarded_only(true).is_err());
        assert!(ensure_forwarded_only(false).is_ok());
    }

    #[test]
    fn mapped_bind_ranges_become_ipv4_source_rules() {
        let ranges = vec![
            "::ffff:192.0.2.0/120".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let (v4, v6) = source_tables(&ranges);
        assert_eq!(v4, vec!["192.0.2.0/24"]);
        assert_eq!(v6, vec!["2001:db8::/32"]);
    }

    #[test]
    fn rules_scope_divert_reply_to_configured_sources() {
        let rules = test_rules(
            false,
            true,
            &["192.0.2.0/24".to_owned()],
            &["2001:db8::/32".to_owned()],
        );
        assert!(rules.contains("table <rfor_src4> { 192.0.2.0/24 }"));
        assert!(rules.contains("table <rfor_src6> { 2001:db8::/32 }"));
        assert!(rules.contains(
            "from <rfor_src4> to any port { 80,443,8080:8082 } divert-reply"
        ));
        assert!(rules.contains(
            "from <rfor_src6> to any port { 80,443,8080:8082 } divert-reply"
        ));
        assert!(!rules.contains("from <rfor_src4> to any divert-reply"));
        assert!(!rules.contains("from <rfor_src6> to any divert-reply"));
        assert!(!rules.contains("from ! <rfor_np4> to any divert-reply"));
        assert!(!rules.contains("route-to"));
    }

    #[test]
    fn rules_include_both_families_and_protocols() {
        let rules = test_rules(false, true, &[], &[]);
        assert!(rules.contains("table <rfor_np4>"));
        assert!(rules.contains("table <rfor_np6>"));
        assert!(rules.contains("divert-to 127.0.0.1 port 15080"));
        assert!(rules.contains("divert-to ::1 port 15080"));
    }

    #[test]
    fn disabled_families_and_udp_are_omitted() {
        let rules = test_rules(true, false, &["192.0.2.0/24".to_owned()], &[]);
        assert!(!rules.contains("inet6"));
        assert!(!rules.contains("proto udp"));
        assert!(!rules.contains("table <rfor_np6>"));
    }

    #[test]
    fn ports_are_validated_before_reaching_pfctl() {
        assert!(validate_ports("80,443,8080:8082").is_ok());
        assert!(validate_ports("80 }\npass all").is_err());
        assert!(validate_ports("").is_err());
    }
}
