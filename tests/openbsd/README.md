# OpenBSD forwarded-traffic live test

Status: **executed on 2026-10-31** against OpenBSD 7.9/amd64, first under
QEMU TCG, then under PVE/KVM with routed client and target namespaces. The
same PVE/KVM VM was later upgraded to 8.0. This test covers forwarded
traffic only; `local-traffic: true` is intentionally rejected by rfor.

## OpenBSD 8.0 upgrade

The PVE/KVM VM was upgraded from 7.9 to 8.0 with `sysupgrade -R 8.0`
(release sets from cdn.openbsd.org) and syspatch 001-005. rfor was rebuilt
with an 8.0 sysroot; v2ray and gost were rebuilt for openbsd/amd64. PF
anchor installation, forwarded IPv4 TCP, forwarded UDP DNS, and the proxy
paths were re-verified on 8.0. The full ULA/GUA source-preservation matrix
was re-run on 8.0; see below.

## Tested topology

- proxy VM: OpenBSD 7.9/amd64, two virtio NICs.
  - `vio0`: QEMU user network, address `198.18.1.15`, host gateway
    `198.18.1.2`.
  - `vio1`: QEMU socket network, `10.55.0.1/24` and `fd00:55::1/64`.
- client VM: FreeBSD 15.1/arm64, `vtnet0` on the socket network,
  `10.55.0.2/24` and `fd00:55::2/64`, default routes via the proxy.
- host origin services:
  - IPv4 TCP `198.18.1.2:18080`, IPv4 UDP `198.18.1.2:19000`;
  - IPv6 TCP `[fec0::2]:18080`, IPv6 UDP `[fec0::2]:19000`.

On the proxy:

```sh
ifconfig vio1 inet 10.55.0.1/24
ifconfig vio1 inet6 fd00:55::1/64
sysctl net.inet.ip.forwarding=1
sysctl net.inet6.ip6.forwarding=1
printf 'anchor "rfor/*"\n' >> /etc/pf.conf
pfctl -f /etc/pf.conf
```

The rfor binary was cross-built on macOS with:

```sh
RUSTC_BOOTSTRAP=1 CC_x86_64_unknown_openbsd=clang \
CFLAGS_x86_64_unknown_openbsd='--sysroot=/tmp/openbsd-sysroot' \
cargo zigbuild -Z build-std=std,panic_abort \
  --target x86_64-unknown-openbsd --release
```

Test config:

```yaml
debug: true
tproxy-listen: 127.0.0.1:15080
udp-enabled: true
traffic-intercept:
  mode: auto
  local-traffic: false
  ports: ["18080", "19000"]
  tproxy-proxy-chain: rfor-test
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
```

## Results

Passed:

1. Startup loaded anchor `rfor/15080_rfortest` with IPv4 and IPv6
   `divert-to` rules for TCP and UDP.
2. IPv4 TCP from the client to `198.18.1.2:18080` returned the origin body;
   rfor logged `TPROXY:10.55.0.2 -> 198.18.1.2:18080`.
3. IPv4 UDP to `198.18.1.2:19000` echoed `udp:ob-udp`.
4. IPv6 TCP to `[fec0::2]:18080` returned `openbsd-ipv6-ok`; rfor logged
   `TPROXY:[fd00:55::2] -> [fec0::2]:18080`.
5. IPv6 UDP to `[fec0::2]:19000` echoed `udp6:ob-udp6`.
6. `local-traffic: true` exited with status 1 before loading any anchor rules.
7. SIGTERM removed all rules from the PF anchor.

## PVE/KVM source-preservation follow-up

The QEMU TCG run left `bind_range` source preservation unverified because the
slirp return path did not reach the divert-reply socket. A second run on the
same OpenBSD 7.9/amd64 image under PVE/KVM (`cpu: host`) used routed client
and target namespaces so every reply returned through the OpenBSD VM:

- proxy VM: `vio0` `192.168.51.254/24`, `vio1` `203.0.113.1/24` and
  `2001:db8:99::1/64`.
- client namespace: `192.168.51.240/24`, IPv4 default via
  `192.168.51.254`, IPv6 default via the proxy link-local.
- target namespace: `203.0.113.2/24` and `2001:db8:99::2/64`, default via
  the proxy.
- target services: HTTP on `203.0.113.2:80` / `[2001:db8:99::2]:80`, UDP
  echo on `203.0.113.2:443` / `[2001:db8:99::2]:443`.

With `bind_range` set to the client's IPv4 and IPv6 addresses:

1. IPv4 TCP: origin saw peer `192.168.51.240`.
2. IPv4 UDP: echo returned; origin saw peer `192.168.51.240`.
3. IPv6 TCP: origin saw peer `2408:...:85b1`.
4. IPv6 UDP: echo returned; origin saw peer `2408:...:85b1`.
5. SOCKS5 TCP: HTTP and HTTPS through a SOCKS5 upstream succeeded; rfor
   logged `Outbound(PROXY)`.
6. SOCKS5 UDP: a DNS query to `8.8.8.8:53` returned a response through both
   the `7905` (US) and `7904` (JP) upstreams; rfor logged the DGRAM flow as
   `Outbound(PROXY)`.
7. Graceful SIGTERM flushed the anchor and traffic bypassed the proxy;
   SIGKILL left the anchor loaded and the same HTTP request failed closed
   until the next restart.
8. SOCKS5 UDP associate: a stock SOCKS5 client sent a DNS query through
   rfor's `socks5-listen` and received the response; the relay was bound to
   `0.0.0.0:<port>` for the IPv4 control connection.

Four OpenBSD UDP fixes were required:

- Unmap the internal IPv4-mapped IPv6 source before binding an AF_INET
  socket; otherwise `bind(2)` returns `EAFNOSUPPORT`.
- Connect the `bind_range` upstream UDP socket to the resolved target.
  PF `divert-reply` only delivers replies to a connected socket. Keep the
  source address, let the kernel choose a fresh source port to avoid the
  divert-to 5-tuple collision, and fall back to `send(2)` when `sendto(2)`
  returns `EISCONN`.
- Bind the SOCKS5 datagram relay socket in the SOCKS server's address
  family. OpenBSD IPv6 sockets are IPv6-only by default, so `[::]:0` could
  not send to an IPv4 relay such as `127.0.0.1:7905`.
- Bind the SOCKS5 server's UDP associate relay in the client's address
  family. An IPv4 control connection must get a `0.0.0.0:0` relay; a
  `[::]:0` relay is IPv6-only on OpenBSD and silently drops IPv4 datagrams.

Not validated:

- `udp-fullcone` together with `bind_range`; the connected socket restricts
  replies to the resolved target.
- Multiple simultaneous destinations from one client UDP socket.
- A target whose return path bypasses the OpenBSD gateway (for example a
  target on the client's L2 segment); source preservation requires the
  gateway to see the reply.

### OpenBSD 8.0 re-run

The matrix was repeated on the same VM after the 8.0 upgrade, with `vio1`
moved to an isolated bridge so the production WAN L2 was not touched:

- proxy: `vio0` `192.168.51.254/24` plus the test ULA `fd00:99::1/64`;
  `vio1` `203.0.113.1/24` and `2001:db8:99::1/64`.
- client namespace: `192.168.51.240/24` and `fd00:99::240/64`, IPv4 and
  IPv6 defaults via the proxy.
- target namespace: `203.0.113.2/24` and `2001:db8:99::2/64`, HTTP on port
  80 and UDP echo on port 443.
- rfor: `bind_range` `::ffff:192.168.51.240/128` and
  `fd00:99::240/128`, `DEFAULT,,DIRECT`.

All four flows passed:

1. IPv4 TCP: origin saw peer `192.168.51.240`.
2. IPv4 UDP: echo returned; origin saw peer `192.168.51.240`.
3. IPv6 TCP: origin saw peer `fd00:99::240`.
4. IPv6 UDP: echo returned; origin saw peer `fd00:99::240`.

rfor logged `Outbound(DIRECT)` for all four flows. The test anchor was
`rfor/15080_rfortest`; forwarding and the test addresses were removed
afterwards.

## Resolver upstream through rfor SOCKS5

`traffic-intercept.local-traffic: false` means PF `divert-to` never sees
traffic originated by the router itself. unbound's own upstream queries
therefore bypass the transparent path and cannot use the rfor rule table or
its default outbound directly. proxychains is not a fix: it hooks TCP
`connect(2)` only, while unbound's default forwarder transport is UDP; on
OpenBSD unbound is also chrooted and pledged, so LD_PRELOAD injection is not
dependable.

The tested layout inserts a local UDP-to-SOCKS5 adapter:

    unbound -> 127.0.0.1:5353 (v2ray dokodemo-door, tcp,udp)
            -> 127.0.0.1:1080 (rfor socks5-listen)
            -> rfor rules / DEFAULT -> PROXY

unbound needs `do-not-query-localhost: no` and:

    forward-zone:
      name: "."
      forward-addr: 127.0.0.1@5353
      forward-first: no

Live results on OpenBSD 8.0:

1. UDP and TCP DNS through the adapter returned answers; `tcpdump -i lo0
   'tcp port 1080'` showed the SOCKS5 control connection for each query.
2. `cloudflare.com A +dnssec` returned `flags: qr rd ra ad`, so unbound
   still validates DNSSEC through the forwarder.
3. `home.ygo-note.com` and `openbsd-router.lan` returned the split-horizon
   `192.168.51.1` records.

## Explicit negative checks

- `local-traffic: true`: exit code 1 with
  `OpenBSD local-traffic interception is not supported in this version`.
- Removing the `anchor "rfor/*"` hook must fail before loading rules; this is
  enforced by `ensure_anchor_reference()`.
