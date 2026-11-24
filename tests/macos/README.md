# macOS integration tests

This directory contains the native macOS `utun` end-to-end test scripts and
the automated Cirrus Labs `tart` VM runner.

## Modes verified

1. **Local transparent proxy (`local-traffic: true`)** via `tests/macos/local-traffic.sh`:
   - Automatic `utun` interface creation, egress detection, private/scoped bypass
     routes, and split-default routes (`0.0.0.0/1`, `128.0.0.0/1`).
   - Sequential and concurrent HTTPS requests (`TPROXY:` -> `Outbound(DIRECT)`).
   - HTTP `Host` and TLS SNI routing to a loopback SOCKS5 upstream (`Outbound(PROXY)`),
     verifying `IP_BOUND_IF` skips loopback.
   - Sequential and concurrent UDP DNS queries (`TPROXY:` `DGRAM` -> `Outbound(DIRECT)`),
     DNS routing to SOCKS5 UDP ASSOCIATE (`Outbound(PROXY)`), and `drop-reply.dns: nxdomain`.
   - QUIC v1 and v2 Initial SNI sniffing (`[quic-v1]` and `[quic-v2]`).
   - Direct bypass for non-intercepted ports.
   - Clean `SIGTERM` teardown (zero leaked `utun` interfaces or routes) and
     5-cycle restart soak.

2. **Forwarded-only transparent proxy (`local-traffic: false`)** via `tests/macos/forwarded-traffic.sh`:
   - Two-VM topology (`rfor-macos-gw` + `rfor-macos-client`) linked by a point-to-point
     Layer-3 `utun` tunnel (`10.200.0.1 <-> 10.200.0.2` via `tests/macos/utun-wire.py`)
     to bypass Apple `vmnet` guest-to-guest isolation while exercising real kernel
     IP forwarding and PF `route-to`.
   - Gateway enables `net.inet.ip.forwarding=1`, configures `anchor "rfor/*"` in
     `/etc/pf.conf`, and starts `rfor` with `mode: utun` and `local-traffic: false`.
   - Verifies gateway host-local traffic is untouched while client-forwarded TCP,
     HTTP Host, UDP DNS, NXDOMAIN drop, and QUIC SNI traffic route through
     gateway's `utun` and `Outbound(DIRECT|PROXY|DROP)`.
   - Verifies `SIGTERM` flushes the PF anchor, releases the `pfctl -E` token, and
     tears down `utun`.

## Automated `tart` runner

```sh
./tests/macos/tart/run.sh
```

Or via `make macos-test` or Cargo:

```sh
cargo test --release --test macos_local_traffic -- --ignored --nocapture
```

The first run caches a template VM named `rfor-macos-base` (default image
`ghcr.io/cirruslabs/macos-sequoia-base:latest`, overridable with
`RFOR_MACOS_IMAGE`), installs the test SSH key and dependencies, and subsequent
runs clone disposable APFS COW VMs for isolated testing.
