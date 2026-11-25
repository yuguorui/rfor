# Platform Guides

`rfor` manages transparent proxy firewall/routing rules automatically on startup and cleans them up on exit. All `auto` interception backends also support additive IPv4/IPv6 exclusions via [`traffic-intercept.bypass-cidrs`](configuration.md#traffic-interception).

---

## Linux

`traffic-intercept.mode: auto` (or `tproxy`) configures kernel `iptables`/`ip6tables` + policy routing (`ip rule` / `ip route`) using `TPROXY`. Use `mode: redirect` if you cannot use `TPROXY` (for example in some container setups), or `mode: manual` to manage `iptables` yourself.

### Linux Options

```yaml
traffic-intercept:
  mode: auto                 # auto (tproxy) | redirect | manual
  local-traffic: true
  ports: [80, 443, 8080]
  # bypass-cidrs:
  #   - "30.0.0.0/8"
  #   - "2001:db8:cafe::/48"
  # proxy-mark: 0xff42
  # direct-mark: 0xff43
  # tproxy-proxy-chain: rfor-proxy
  # tproxy-mark-chain: rfor-mark
  # rule-table: 0x42
```

- `DIRECT` source IP preservation (`bind_range`) is supported in `tproxy` mode, not in `redirect` mode.
- `mode: redirect` only supports TCP (`udp-enabled` is automatically disabled).

### Known Issue: `br_netfilter` in Docker

Linux `br_netfilter` has [a known issue with TPROXY](http://patchwork.ozlabs.org/project/netfilter-devel/patch/1518715545-2188-1-git-send-email-gregory.vanderschueren@tessares.net/) that can cause network timeouts in Docker containers. Mitigate it on the host with:

```bash
echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables
echo "0" | sudo tee /proc/sys/net/bridge/bridge-nf-call-ip6tables
```

Alternatively, switch to `traffic-intercept.mode: redirect` (without `bind_range` source IP preservation).

Automated Linux integration suite: [tests/integration/README.md](../tests/integration/README.md).

---

## macOS

On macOS, `traffic-intercept.mode: auto` (aliases `tproxy`, `utun`, `tun`) creates a native `utun` interface backed by userspace `smoltcp`. `redirect`, `ipfw`, and `pf` modes are rejected at startup; use `auto`/`utun` or `manual`. Requires `root`. Source IP preservation (`bind_range`) is not supported on macOS `utun`.

```yaml
traffic-intercept:
  mode: auto
  local-traffic: true
  ports: [80, 443, 53]
  # utun-name: utun9          # optional; auto-assigned when omitted
  # egress-interface: en0     # optional; auto-detected from default route
  # bypass-cidrs:             # optional extra IPv4/IPv6 CIDRs (e.g. corporate non-RFC1918 ranges)
  #   - "30.0.0.0/8"
  #   - "2001:db8:cafe::/48"
```

- `tproxy-listen` is not required when using the `utun` backend.
- **ICMP / `ping` handling**: `DIRECT` ICMP/ICMPv6 Echo Requests are forwarded over non-blocking `SOCK_DGRAM` ICMP sockets bound to the physical egress interface so real Echo Replies return through `utun`. Requests matching a proxy outbound receive ICMP Protocol Unreachable (IPv4 Type 3 Code 2) or Parameter Problem / Unrecognized Next Header (IPv6 Type 4 Code 1) immediately without leaking direct packets; requests matching `DROP` receive Administratively Prohibited (IPv4 Type 3 Code 13 / IPv6 Type 1 Code 1). Non-Echo ICMP packets, fragments, and multicast/broadcast traffic are dropped silently.
- **Non-intercepted ports & `bypass-cidrs`**: Traffic on ports outside `traffic-intercept.ports` (or UDP when `udp-enabled: false`) is forwarded directly over the egress interface without evaluating `rules`. Custom `bypass-cidrs` entries skip `/0` (always rejected) and `/1` in `local-traffic: true` mode (to avoid colliding with split-default routes), as well as any subnet already covered by a kernel on-link route.
- **`local-traffic: true` (host-local + forwarded)**:
  - Creates a `utun` device, detects the default egress interface (`route -n get default`), installs private/interface-scoped bypass routes plus split-default routes (`0.0.0.0/1`, `128.0.0.0/1`, and `::/1`, `8000::/1` when IPv6 egress exists), and binds outbound sockets via `IP_BOUND_IF`/`IPV6_BOUND_IF` (skipping loopback upstreams).
  - No `/etc/pf.conf` edits are required. Graceful shutdown removes installed routes and closing the `utun` descriptor tears down the interface so crashes fail open.
  - If you run a second local `rfor` instance on the same host (such as a `mode: manual` loopback SOCKS5 upstream), set top-level `egress-interface: <iface>` on it so its outbound sockets bind with `IP_BOUND_IF`/`IPV6_BOUND_IF` and avoid looping back into `utun`.
- **`local-traffic: false` (forwarded traffic only)**:
  - Brings up `utun` without modifying host routes, acquires a PF reference token (`pfctl -E` / `pfctl -X` on exit), and loads `route-to (<utunX> ...)` rules into anchor `rfor/<chain>`. Host-local traffic is untouched.
  - Add the one-time anchor hook to `/etc/pf.conf` and enable IP forwarding before starting `rfor`:

    ```pf
    anchor "rfor/*"
    ```

    ```bash
    sudo sysctl net.inet.ip.forwarding=1
    ```

- **File descriptor limit (`Too many open files`)**: macOS defaults to `ulimit -n` = `256` per process, which is easily exhausted under concurrent TCP + QUIC/UDP sessions. Raise it before launching `rfor`:

  ```bash
  ulimit -n 65536 && sudo rfor -c config.yaml
  ```

Automated macOS VM test suite via `tart`: [tests/macos/README.md](../tests/macos/README.md).

---

## FreeBSD

On FreeBSD, `traffic-intercept.mode: auto` (and `tproxy` / `ipfw`) selects the `ipfw` backend. `mode: redirect` is rejected; use `auto`/`tproxy` or `mode: manual`. Requires `root` and the `ipfw` kernel module already loaded (for example `firewall_enable="YES"` in `/etc/rc.conf` or `kldload ipfw`).

```yaml
traffic-intercept:
  mode: auto
  local-traffic: false
  ports: [80, 443]
  ipfw-rule-base: 64000
  tproxy-proxy-chain: rfor-proxy
```

- Installs commented `ipfw` rules tagged `// rfor:<tproxy-proxy-chain>` and removes them on shutdown.
- `ipfw-rule-base` must reserve **eight consecutive rule numbers** for IPv4/IPv6 TCP/UDP and optional local-output rules. `rfor` does not alter the default `ipfw` policy — ensure `ipfw-rule-base` is reached before any terminal `allow`/`deny` rule.
- A listener configured as `[::]:<port>` creates separate IPv4 and IPv6 sockets because `ipfw fwd` delivers to the native listener address. An IPv4-only listener (`0.0.0.0:<port>`) does not install IPv6 rules.
- `local-traffic: true` marks `rfor`'s own sockets with `SO_USER_COOKIE` and uses `not sockarg` in output rules to prevent forwarding loops. IPv4-mapped IPv6 destinations are normalized to the native socket family before transparent binds, TCP connects, and UDP sends.

Automated FreeBSD VM test suite: [tests/freebsd/README.md](../tests/freebsd/README.md).

---

## OpenBSD

On OpenBSD, `traffic-intercept.mode: auto` (and `tproxy` / `pf`) selects the PF `divert-to` backend. `redirect` and `ipfw` are rejected. **Forwarded traffic only**: `local-traffic: true` is rejected at startup (PF `divert-to` only tags inbound packets; use an explicit proxy such as `http_proxy` for host-local commands). Requires `root` and PF enabled.

Live-tested for IPv4 and IPv6 TCP/UDP (including `bind_range` source preservation when the return path traverses the OpenBSD gateway) on OpenBSD 7.9 and 8.0 (8.0 after syspatch 001-005).

Add this one-time hook to `/etc/pf.conf` (after block rules that should still govern `rfor`'s traffic), then reload PF:

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

- **Anchor lifecycle**: Rules load into `rfor/<tproxy-port>_<chain>` and flush on shutdown. If `rfor` dies ungracefully without cleanup, the anchor continues diverting matched traffic to a missing listener until `rfor` restarts or the anchor is flushed.
- **Divert listeners**: Binds TCP and UDP divert targets on `127.0.0.1` and `::1` (unless `disable-ipv6: true`); `tproxy-listen` is used only for its port number.
- **Source preservation (`bind_range`)**: Converts IPv4-mapped IPv6 ranges to IPv4 PF tables and installs `divert-reply` rules only for those configured source ranges and intercepted ports. Avoid overly broad ranges like `::ffff:0:0/96` on exposed gateways.
- **UDP source preservation**: Keeps the client's source address while letting the kernel allocate a fresh source port and connecting the upstream socket to the resolved target (avoiding `divert-to`/`divert-reply` 5-tuple collisions). The return path must pass through the OpenBSD gateway, and `udp-fullcone` together with `bind_range` is unsupported.
- **IPv4/IPv6 socket families**: SOCKS5 UDP upstreams and UDP ASSOCIATE relays bind `0.0.0.0:0` for IPv4 and `[::]:0` for IPv6 (because OpenBSD IPv6 sockets are IPv6-only by default).
- **Original destination recovery**: Recovers destinations without `DIOCNATLOOK` via `getsockname(2)` (TCP) and `IP_RECVDSTADDR`/`IP_RECVDSTPORT` or `IPV6_PKTINFO`/`IPV6_RECVDSTPORT` (UDP).

Automated OpenBSD VM test suite: [tests/openbsd/README.md](../tests/openbsd/README.md).

---

## Building from Source

```bash
# Install Rust with:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build it!
cargo build --release

# Or build static rfor!
# rustup target add x86_64-unknown-linux-musl
# RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-musl
```

- **FreeBSD / OpenBSD**:
  ```bash
  pkg install rust protobuf
  cargo build --release
  ```
- **macOS** (install `protobuf` or rely on the vendored `protoc`):
  ```bash
  brew install protobuf
  cargo build --release
  ```

`pprof`/flamegraph profiling is supported on Linux and macOS (`x86_64` and `aarch64`), and is disabled on FreeBSD, OpenBSD, and other Linux architectures (`armv7`, `riscv64`).
