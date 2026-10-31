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
- Auto configuration and cleanup for transparent proxy with Linux TPROXY/iptables, FreeBSD ipfw, and OpenBSD PF divert-to (No more manual firewall state🥳)
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

On FreeBSD or OpenBSD, install a system protobuf compiler and Rust, then build
natively:

```bash
pkg install rust protobuf
cargo build --release
```

`pprof`/flamegraph is not available on FreeBSD or OpenBSD because the current
`pprof` crate does not compile for those targets. All other features, including
the SOCKS5 server and the forwarded-transparent path, are available.

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

### OpenBSD transparent proxy (forwarded traffic only)

On OpenBSD, `traffic-intercept.mode: auto` (and `tproxy`) selects the PF
backend; `mode: pf` is also accepted. `redirect` and `ipfw` are rejected.
The first version intentionally supports forwarded traffic only:
`local-traffic: true` is rejected at startup because the loopback route-to/TOS
marker path has not been live-tested and is not safe to ship as an implicit
feature yet.
Forwarded TCP/UDP over IPv4 and IPv6 has been live-tested on OpenBSD 7.9.
Source preservation through `bind_range` is live-tested for IPv4 and IPv6
TCP/UDP when the return path is routed back through the OpenBSD gateway.

PF cannot attach a new anchor to a running ruleset safely from userland. Add
this one-time hook to `/etc/pf.conf` (after the block rules that should still
govern rfor's traffic), then reload PF:

```pf
anchor "rfor/*"
```

```yaml
traffic-intercept:
  mode: auto
  local-traffic: false
  ports: [80, 443, 53]
  tproxy-proxy-chain: rfor-proxy
```

rfor loads rules into the anchor `rfor/<tproxy-port>_<chain>` and flushes that
anchor on shutdown. A graceful stop therefore falls back to the main ruleset
(no interception); if rfor dies without cleanup, the anchor keeps diverting
traffic to a missing listener and the affected flows are dropped until rfor
restarts. It binds TCP and UDP divert targets on `127.0.0.1` and `::1`
(unless `disable-ipv6` is true); the address in `tproxy-listen` is used for
its port only because PF `divert-to` addresses the loopback socket
explicitly.

Source preservation is opt-in through an outbound `bind_range`. rfor converts
IPv4-mapped IPv6 ranges to IPv4 PF tables and installs `divert-reply` rules
only for those configured source ranges; there is no catch-all
non-local-source `divert-reply` rule. A `bind_range` of `::ffff:0:0/96` is
intentionally broad and should be avoided on an exposed gateway.

On OpenBSD, UDP source preservation keeps the original source address but
lets the kernel choose a fresh source port and connects the upstream socket
to the resolved target. PF `divert-reply` only delivers replies to a
connected socket, and reusing the client's source port would collide with the
divert-to 5-tuple. The target's return path must pass through the OpenBSD
gateway; a target on the client's own L2 segment can bypass the proxy. For
the same reason, `udp-fullcone` together with `bind_range` is not supported
on OpenBSD: the connected socket only accepts replies from the resolved
target.

The rules rely on `divert-to` preserving the original destination without a
privileged DIOCNATLOOK. TCP recovers it with `getsockname(2)`; UDP uses
`IP_RECVDSTADDR`/`IP_RECVDSTPORT` or `IPV6_PKTINFO`/`IPV6_RECVDSTPORT`.
The automated OpenBSD test recipe is in `tests/openbsd/README.md`.

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
- On OpenBSD, the PF backend requires root, an enabled PF, and the one-time
  `anchor "rfor/*"` hook. Only forwarded traffic is supported in this version;
  `local-traffic: true` is rejected. The PF/relayd `divert-to` mechanism and
  the scoped `divert-reply` rules are source-verified but not yet live-tested
  in this repository's test VM.
- `br_netfilter` has some known issues [link](http://patchwork.ozlabs.org/project/netfilter-devel/patch/1518715545-2188-1-git-send-email-gregory.vanderschueren@tessares.net/) with tproxy, which may lead to network timeout in Docker.
   You can mitigate this problem with:

      echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables
      echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-ip6tables


  And you may also switch to mode `redirect`, but the source IP preserving feature will not work anymore.
