rfor - Rust traffic FORwarder
======

### A simple but fast traffic forwarder with routing.
Do one thing and do it well.

Features
------
- Build on Tokio with Rust, low CPU/memory overhead
    - Zero copy support
- Standard SOCKS5 proxy protocols support
- Fast routing decision ( <= 15us with 70k rules )
    - TLS SNI sniffing
    - GeoIP/GeoSite/MMDB support
- Auto configuration and cleanup for transparent proxy with iptables and tproxy (No more mess with iptables)
- Optional source IP preserving when connects directly
- Native IPv6 support

Build
-----
```bash
# Install rust with:
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build it!
$ cargo build --release

# Or build static rfor!
# RUSTFLAGS='-C target-feature=+crt-static' cargo build --target x86_64-unknown-linux-musl
```

Usage
-----
```yaml
debug: false
tproxy-listen: '[::]:50080'
socks5-listen: '[::]:50081'

traffic-intercept:
  mode: auto            # set to "manual" when you want set iptables by hand.
  local-traffic: false  # set to true to allow intercept local traffic
  ports: [80,443,8080]  # ports you are interested
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

```

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

# TODO
- [ ] UDP relay

# Known Issues
- `br_netfilter` has some known issues [link](http://patchwork.ozlabs.org/project/netfilter-devel/patch/1518715545-2188-1-git-send-email-gregory.vanderschueren@tessares.net/) with tproxy, which may lead to network timeout in Docker.
   You can mitigate this problem with:
```shell
echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables
echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-ip6tables
```
