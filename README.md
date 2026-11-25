# rfor - Rust traffic FORwarder

### A simple but fast traffic forwarder with routing.
Do one thing and do it well.

## Features

- Built on Tokio with Rust, low CPU/memory overhead
  - Zero-copy support with `splice` syscall on Linux
- Standard SOCKS5 proxy protocol support (TCP & UDP)
- Fast routing decision (`<= 15us` with 70k rules)
  - TLS / QUIC SNI sniffing
  - DNS query sniffing (route intercepted DNS requests by queried domain, with optional `NXDOMAIN` on `DROP`)
  - [GeoIP](https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat) / [GeoSite](https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat) / [MMDB](https://raw.githubusercontent.com/alecthw/mmdb_china_ip_list/release/Country.mmdb) support
- Auto configuration and cleanup for transparent proxy on Linux, macOS, FreeBSD, and OpenBSD (No more manual firewall state 🥳)
- Optional source IP preserving when connecting directly (`bind_range`)
- Native IPv6 support
- UDP transparent proxy
- Performance profiling with pprof/flamegraph 📊
- SIGHUP configuration reload without restart 🔄

## Platform Support

| Platform | Auto Backend | Local Traffic | Forwarded Traffic | Source IP (`bind_range`) | Guide |
| --- | --- | --- | --- | --- | --- |
| **Linux** | TPROXY / REDIRECT | Yes | Yes | TPROXY only | [Linux](docs/platforms.md#linux) |
| **macOS** | `utun` + netstack | Yes | Yes | No | [macOS](docs/platforms.md#macos) |
| **FreeBSD** | `ipfw` | Yes | Yes | Yes | [FreeBSD](docs/platforms.md#freebsd) |
| **OpenBSD** | PF `divert-to` | No | Yes | Yes | [OpenBSD](docs/platforms.md#openbsd) |

## Install

Download prebuilt binaries (static Linux musl and signed/notarized macOS builds, bundled with GeoIP/GeoSite data and sample configs) from [GitHub Releases](https://github.com/yuguorui/rfor/releases).

Or build it from source (see [Building from Source](docs/platforms.md#building-from-source) for static musl, FreeBSD/OpenBSD, and macOS `protobuf` notes):

```bash
# Build it!
cargo build --release
```

## Quick Start

Create a minimal `config.yaml`:

```yaml
tproxy-listen: '[::]:50080'
socks5-listen: '[::]:50081'
udp-enabled: true

traffic-intercept:
  mode: auto              # auto | manual (see platform guides for backend aliases)
  local-traffic: true     # set to false for gateway/forwarded-only (required on OpenBSD)
  ports: [80, 443, 53]    # ports you are interested in

outbounds:
  - name: PROXY
    url: socks5://127.0.0.1:1080
  - name: DIRECT

# Note: all rules are aggregated for matching speed — matching is declarative,
# not sequential. When multiple identical rules exist, priority is undefined.
rules:
  - DEFAULT,,DIRECT
  - DOMAIN-SUFFIX,google.com,PROXY
  - IP-CIDR,1.1.1.1/32,PROXY
  - GEOSITE,geosite.dat:category-ads,DROP
```

Run it (transparent interception requires `root`; on macOS, raise the default FD limit first with `ulimit -n 65536`):

```bash
sudo rfor -c config.yaml
```

Send `SIGHUP` to reload config without restarting. Ready-to-use examples are included in [conf/config-cn.yaml](conf/config-cn.yaml) and [conf/config-redirect.yaml](conf/config-redirect.yaml).

## Documentation

- [Configuration Reference](docs/configuration.md) — CLI options, full YAML keys, rule precedence, DNS sniffing & `drop-reply`, UDP tuning, `SIGHUP`, and `pprof`.
- [Platform Guides](docs/platforms.md) — Linux, macOS, FreeBSD, and OpenBSD setup, `bypass-cidrs`, known issues, and building from source.
- Test harnesses: [Linux](tests/integration/README.md) · [macOS](tests/macos/README.md) · [FreeBSD](tests/freebsd/README.md) · [OpenBSD](tests/openbsd/README.md)
