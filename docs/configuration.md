# Configuration Reference

`rfor` reads a YAML configuration file (`config.yaml` by default). For platform-specific firewall, `utun`, and `bypass-cidrs` details, see the [Platform Guides](platforms.md).

## CLI Options

```text
USAGE:
    rfor [OPTIONS]

OPTIONS:
    -c, --config <CONFIG>        config file filepath [default: config.yaml]
    -w, --work-dir <WORK_DIR>    working directory [default: .]
        --pprof [<PPROF>]        enable pprof [defaults to flamegraph.svg when passed without a path]
    -h, --help                   Print help information
    -V, --version                Print version information
```

At least one listener (`tproxy-listen`, `socks5-listen`, or `redirect-listen`) must be configured, except on macOS when `traffic-intercept` enables the `utun` backend.

## Full YAML Reference

```yaml
debug: false
disable-ipv6: false

tproxy-listen: '[::]:50080'
socks5-listen: '[::]:50081'
# redirect-listen: '[::]:50082'

# Global UDP relay settings
udp-enabled: true
udp-timeout: 60
udp-max-sessions: 1024
# udp-fullcone: false
# udp-fullcone-max-sockets: 64
# udp-fullcone-socket-timeout: 30
# udp-fullcone-rate-limit: 10

# Optional response for DNS queries hitting a DROP outbound
# drop-reply:
#   dns: silent                  # silent (default) | nxdomain

# Optional CPU flamegraph output on exit (Linux & macOS x86_64/aarch64 only)
# pprof: flamegraph.svg

# Optional default egress interface for macOS `mode: manual` instances
# egress-interface: en0

traffic-intercept:
  mode: auto                     # auto | tproxy | redirect | ipfw | pf | utun | manual
  local-traffic: false
  ports: [80, 443, 8080]
  # bypass-cidrs:
  #   - "30.0.0.0/8"
  #   - "2001:db8:cafe::/48"

outbounds:
  - name: PROXY
    url: socks5://127.0.0.1:1080
  - name: DIRECT
    bind_range:
      - 2000::/3                 # preserve client source IP when source matches CIDR

rules:
  - DEFAULT,,DIRECT
  - DOMAIN,www.google.com,PROXY
  - DOMAIN-SUFFIX,google.com,PROXY
  - IP-CIDR,1.1.1.1/32,PROXY
  - GEOIP,Country.mmdb:JP,DIRECT
  - GEOSITE,geosite.dat:category-ads,DROP
```

## Listeners

| Key | Description |
| --- | --- |
| `tproxy-listen` | Transparent proxy bind address (Linux TPROXY, FreeBSD ipfw, OpenBSD PF divert). Optional on macOS `utun` mode. |
| `socks5-listen` | SOCKS5 server bind address (supports TCP CONNECT and UDP ASSOCIATE). |
| `redirect-listen` | Linux `REDIRECT` (`SO_ORIGINAL_DST`) listener address. |
| `disable-ipv6` | Disable IPv6 interception/socket handling where applicable (default: `false`). |

## Traffic Interception

`traffic-intercept` controls automatic firewall/routing setup and teardown on startup and shutdown. If omitted, `rfor` defaults to `mode: manual`.

| Key | Default | Description |
| --- | --- | --- |
| `mode` | `manual` | `auto` / `tproxy` (selects native OS backend), `redirect` (Linux), `ipfw` (FreeBSD), `pf` (OpenBSD), `utun` / `tun` (macOS), or `manual`. |
| `local-traffic` | `false` | Also intercept connections originating from the host itself (unsupported on OpenBSD). |
| `ports` | `[]` | Ports or `"start-end"` ranges to intercept (for example `[53, 80, 443, "8000-8080"]`). |
| `bypass-cidrs` | `[]` | Extra IPv4/IPv6 CIDRs or bare IPs excluded from interception across all auto backends, additive to built-in private/reserved ranges. `/0` is always rejected; `/1` is rejected in macOS `local-traffic: true` mode. |

Platform-specific `traffic-intercept` options (`proxy-mark`, `direct-mark`, `tproxy-proxy-chain`, `tproxy-mark-chain`, `rule-table`, `ipfw-rule-base`, `utun-name`, `egress-interface`) are documented in the [Platform Guides](platforms.md).

## Outbounds

Two built-in outbounds, **`DIRECT`** and **`DROP`** (`drop://0.0.0.0`), are always registered automatically even if not listed in `outbounds`.

| Field | Description |
| --- | --- |
| `name` | Unique outbound name referenced by `rules`. |
| `url` | Omit for direct egress; `socks5://[user:pass@]host:port` (or `socks://`) for SOCKS5 upstream; `drop://0.0.0.0` to reject connections. |
| `bind_range` | Optional list of CIDRs (for example `2000::/3`, `::ffff:192.0.2.0/24`). When a client's source IP matches, `rfor` binds the upstream socket to preserve the source IP (Linux TPROXY, FreeBSD, OpenBSD only; unsupported on Linux `redirect` and macOS `utun`). |

## Routing Rules

> [!NOTE]
> Rules are **declarative and aggregated** into tries/hash tables for speed (`<= 15µs` with 70k rules) — they are **not** evaluated top-to-bottom. If two outbounds define the same rule, the winner is undefined.

Each entry follows `KEYWORD,PARAM,OUTBOUND`:

| Rule | Example | Notes |
| --- | --- | --- |
| `DEFAULT` | `DEFAULT,,DIRECT` | Fallback outbound when no domain or IP rule matches. |
| `DOMAIN` | `DOMAIN,www.google.com,PROXY` | Exact domain match (highest priority). |
| `DOMAIN-SUFFIX` | `DOMAIN-SUFFIX,google.com,PROXY` | Longest-matching domain suffix trie. |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD,google,PROXY` | Substring domain matcher (Aho-Corasick). |
| `IP-CIDR` | `IP-CIDR,1.1.1.1/32,PROXY` | IPv4/IPv6 CIDR lookup (longest prefix wins). |
| `GEOIP` | `GEOIP,Country.mmdb:JP,DIRECT` | Matches country/region from [GeoIP `.dat`](https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat) or [MMDB `.mmdb`](https://raw.githubusercontent.com/alecthw/mmdb_china_ip_list/release/Country.mmdb). |
| `GEOSITE` | `GEOSITE,geosite.dat:cn,DIRECT` | Loads domain categories from [GeoSite `.dat`](https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat) (`Plain`, `RootDomain`, `Full`; regex entries are skipped). |

Precedence order:
1. Domain matches (`DOMAIN` exact > longest `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD`)
2. IP matches (longest prefix `IP-CIDR` / `GEOIP .dat` > `GEOIP .mmdb`)
3. `DEFAULT`

## Protocol Sniffing & DNS Drop Reply

- Transparent connections sniff HTTP `Host`, TLS SNI, QUIC Initial SNI, and DNS queries (port 53 TCP/UDP).
- Intercepted DNS queries are routed using the queried domain name while still forwarded to the original destination DNS server IP. Include port `53` in `traffic-intercept.ports` (and `udp-enabled: true` for UDP DNS) to enable domain rules for DNS traffic.
- When a DNS query routes to a `drop://` outbound and `drop-reply.dns: nxdomain` is set, `rfor` returns an immediate `NXDOMAIN` response instead of `silent` (default) so clients do not stall waiting for DNS timeouts.

## UDP Relay

| Key | Default | Description |
| --- | --- | --- |
| `udp-enabled` | `true` | Enable UDP transparent proxy (`udp-enable` is still accepted as a deprecated alias). Forced off in Linux `redirect` mode. |
| `udp-timeout` | `60` | Idle timeout in seconds for generic UDP sessions (sniffed DNS flows expire after `10` seconds). |
| `udp-max-sessions` | `1024` | Maximum concurrent intercepted UDP relay sessions (`0` = unlimited). |
| `udp-fullcone` | `false` | Allow full-cone UDP replies from arbitrary peers (unsupported together with `bind_range` on OpenBSD). |
| `udp-fullcone-max-sockets` | `64` | Maximum tracked peers per full-cone session (`0` = unlimited). |
| `udp-fullcone-socket-timeout` | `30` | Idle timeout in seconds per full-cone peer entry. |
| `udp-fullcone-rate-limit` | `10` | Maximum new full-cone peer entries per second per session (`0` = unlimited). |

## Hot Reload & Profiling

- **Config Reload (`SIGHUP`)**: Send `SIGHUP` (e.g. `kill -HUP <pid>`) to reload configuration and toggle `pprof` without restarting.
- **Profiling (`pprof`)**: Supported on Linux and macOS (`x86_64` and `aarch64`); unavailable on FreeBSD, OpenBSD, and other Linux architectures (`armv7`, `riscv64`).

## Bundled Examples

- [conf/config-cn.yaml](../conf/config-cn.yaml) — Split China/foreign traffic with GeoSite rules and `auto` interception.
- [conf/config-redirect.yaml](../conf/config-redirect.yaml) — Linux `redirect` mode example.
