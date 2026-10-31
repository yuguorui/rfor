# OpenBSD forwarded-traffic live test

Status: **executed on 2026-10-31** against OpenBSD 7.9/amd64, first under
QEMU TCG, then under PVE/KVM with routed client and target namespaces. This
test covers forwarded traffic only; `local-traffic: true` is intentionally
rejected by rfor.

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
6. Graceful SIGTERM flushed the anchor and traffic bypassed the proxy;
   SIGKILL left the anchor loaded and the same HTTP request failed closed
   until the next restart.

Two fixes were required for UDP source preservation:

- Unmap the internal IPv4-mapped IPv6 source before binding an AF_INET
  socket; otherwise `bind(2)` returns `EAFNOSUPPORT`.
- Connect the `bind_range` upstream UDP socket to the resolved target.
  PF `divert-reply` only delivers replies to a connected socket. Keep the
  source address, let the kernel choose a fresh source port to avoid the
  divert-to 5-tuple collision, and fall back to `send(2)` when `sendto(2)`
  returns `EISCONN`.

Not validated:

- `udp-fullcone` together with `bind_range`; the connected socket restricts
  replies to the resolved target.
- Multiple simultaneous destinations from one client UDP socket.
- A target whose return path bypasses the OpenBSD gateway (for example a
  target on the client's L2 segment); source preservation requires the
  gateway to see the reply.

## Explicit negative checks

- `local-traffic: true`: exit code 1 with
  `OpenBSD local-traffic interception is not supported in this version`.
- Removing the `anchor "rfor/*"` hook must fail before loading rules; this is
  enforced by `ensure_anchor_reference()`.
