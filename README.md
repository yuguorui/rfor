rfor - Rust traffic FORwarder
======

### A simple but fast traffic forwarder with routing.
Do one thing and do it well.

Features
------
- Build on Tokio with Rust, low CPU/memory overhead
    - Zero copy support with splice syscall.
- Standard SOCKS5 proxy protocols support
- Fast routing decision ( <= 15us with 70k rules )
    - TLS/QUIC SNI sniffing
    - DNS query sniffing (route intercepted DNS requests by the queried domain)
    - [GeoIP](https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat)/[GeoSite](https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat)/[MMDB](https://raw.githubusercontent.com/alecthw/mmdb_china_ip_list/release/Country.mmdb) support
- Auto configuration and cleanup for transparent proxy with Linux TPROXY/iptables and FreeBSD ipfw (No more manual firewall state🥳)
- Optional source IP preserving when connects directly
- Native IPv6 support
- UDP transparent proxy
- Performance profiling with pprof/flamegraph 📊
- SIGHUP configuration reload without restart 🔄

Build
-----
```bash
# Install rust with:
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build it!
$ cargo build --release

# Or build static rfor!
# rustup target add x86_64-unknown-linux-musl
# RUSTFLAGS='-C target-feature=+crt-static' cargo build --target x86_64-unknown-linux-musl
```

On FreeBSD, install a system protobuf compiler and Rust, then build natively:

```bash
pkg install rust protobuf
cargo build --release
```

`pprof`/flamegraph is not available on FreeBSD because the current `pprof`
crate does not compile for that target. All other features, including the
SOCKS5 server and transparent proxy, are available.

Usage
-----
```yaml
debug: false
# disable-ipv6: false
tproxy-listen: '[::]:50080'
socks5-listen: '[::]:50081'

udp-enabled: true
# udp-timeout: 60

# drop-reply:                  # how to answer requests rejected by a drop:// outbound
#   dns: nxdomain              # silent (default) | nxdomain

traffic-intercept:
  mode: auto                # auto(tproxy)/redirect/manual, set to "manual" when you want set iptables by hand.
  local-traffic: true       # set to true to allow intercept local traffic
  ports: [80,443,8080]      # ports you are interested
#   proxy-mark: 0xff42
#   direct-mark: 0xff43
#   tproxy-proxy-chain: rfor-proxy
#   tproxy-mark-chain: rfor-mark
#   rule-table: 0x42

outbounds:
  - name: PROXY
    url: socks5://127.0.0.1:1080

  - name: DIRECT
    bind_range:
      - 2000::/3        # connect with original source IP when src ip match this range.

# It is worth noting that all rules are aggregated in order to improve the speed of rule matching. 
# So the matching of rules is not sequential, but declarative. When multiple identical rules exist, 
# the matching priority is undefined.
rules:
  - DEFAULT,,DIRECT
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN,www.google.com,PROXY
  - IP-CIDR,1.1.1.1/32,PROXY
  - GEOIP,Country.mmdb:JP,DIRECT
  - GEOSITE,geosite.dat:category-ads,DROP
```

### FreeBSD transparent proxy

On FreeBSD, `traffic-intercept.mode: auto` (and the alias `tproxy`) selects the
ipfw backend. `mode: redirect` is intentionally rejected; use `auto`/`tproxy`
or manage the rules yourself with `mode: manual`. The `ipfw` kernel module must
already be loaded, for example with `firewall_enable="YES"` in `/etc/rc.conf`
or `kldload ipfw`.

```yaml
traffic-intercept:
  mode: auto
  local-traffic: false
  ports: [80, 443]
  ipfw-rule-base: 64000
  tproxy-proxy-chain: rfor-proxy
```

The backend installs commented ipfw rules tagged `// rfor:<tproxy-proxy-chain>`
and removes them on shutdown. `ipfw-rule-base` must cover eight consecutive rule
numbers for IPv4/IPv6 TCP/UDP and the optional local-output rules. Keep this
range reserved. rfor does not change the ipfw default policy; make sure the
generated rules are reached before any terminal `allow`/`deny` rule.

A FreeBSD listener configured as `[::]:<port>` creates separate IPv4 and IPv6
sockets, because `ipfw fwd` delivers to the native listener address. An IPv4-only
listener (`0.0.0.0:<port>`) does not install IPv6 rules.

`local-traffic: true` marks rfor's own sockets with `SO_USER_COOKIE` and uses
`not sockarg` in the output rules, preventing upstream connections from looping
back into the proxy. IPv4-mapped IPv6 destinations are normalized to the native
socket family before transparent binds, TCP connects, and UDP sends.

DNS requests (UDP/TCP port 53) intercepted by tproxy/redirect are sniffed for
the queried domain, so the domain rules above also apply to DNS traffic itself.
The query is still forwarded to the original DNS server; only the routing
decision uses the sniffed domain. To route DNS requests, make sure port 53 is
included in `traffic-intercept.ports` (and `udp-enabled: true` for UDP DNS).
When a DNS query matches a `drop://` outbound and `drop-reply.dns: nxdomain` is
set, rfor answers with an NXDOMAIN response (impersonating the original DNS
server) instead of silently dropping the packet, so clients fail fast without
waiting for the DNS timeout.

You can run it with:
```shell
$ ./target/x86_64-unknown-linux-musl/debug/rfor -h
rfor 0.1.0
A simple and fast traffic forwarder with routing

USAGE:
    rfor [OPTIONS]

OPTIONS:
    -c, --config <CONFIG>        config file filepath [default: config.yaml]
    -h, --help                   Print help information
    -V, --version                Print version information
    -w, --work-dir <WORK_DIR>    working directory [default: .]
```

# Known Issues
- On FreeBSD, the ipfw backend requires the `ipfw` module to be loaded and root
  privileges. It does not add a default `allow` rule; that remains the
  administrator's policy.
- `br_netfilter` has some known issues [link](http://patchwork.ozlabs.org/project/netfilter-devel/patch/1518715545-2188-1-git-send-email-gregory.vanderschueren@tessares.net/) with tproxy, which may lead to network timeout in Docker.
   You can mitigate this problem with:

      echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables
      echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-ip6tables


  And you may also switch to mode `redirect`, but the source IP preserving feature will not work anymore.
