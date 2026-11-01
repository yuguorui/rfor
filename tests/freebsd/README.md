# FreeBSD live integration test

This directory records the manual QEMU integration setup used for the FreeBSD
`ipfw fwd` backend. It is not run by the Linux Docker test.

## Tested environment

- FreeBSD 15.1-RELEASE, arm64, QEMU/HVF on Apple silicon.
- Gateway VM: QEMU user network on `198.18.1.0/24` plus a QEMU socket LAN on
  `198.18.0.0/24`.
- Client VM: `198.18.0.2/24`, default route through `198.18.0.1`.
- TCP origin: host service at `198.18.1.10:18080`, exported into the VM with
  QEMU `guestfwd=...-cmd:nc ...`.
- UDP echo origin: host UDP service at `198.18.1.2:19000`.
- IPv6 TCP/UDP origin: a VNET jail at `2001:db8::10`, with the gateway on a
  bridge at `2001:db8::1`; the client used `fd00:51::2` on the LAN.

## Build

On the FreeBSD VM:

```sh
pkg install rust protobuf
cargo build --release
cargo test --release
```

## Gateway setup

For the QEMU test only, the gateway used ipfw NAT and a terminal allow rule:

```sh
kldload ipfw_nat
ipfw nat 1 config if vtnet0
ipfw add 65000 nat 1 ip from 198.18.0.0/24 to any out xmit vtnet0
ipfw add 65001 nat 1 ip from any to 198.18.1.15 in recv vtnet0
ipfw add 65534 allow ip from any to any
```

Start rfor with `rfor-freebsd.yaml` from this directory. The IPv4/IPv6 firewall rules
are installed under rule base 62000 and removed on SIGTERM.

## Automated local-traffic benchmark

On a disposable FreeBSD VM with a working uplink:

    pkg install curl bind-tools
    cargo build --release
    RFOR_ALLOW_IPFW_TEST=1 ./tests/freebsd/local-traffic.sh

Load ipfw from the VM console first and keep a terminal allow rule; a
freshly loaded ipfw defaults to deny, which would drop the SSH session
before the test can install its own rule:

    kldload ipfw
    ipfw add 65530 allow ip from any to any

The test adds its own terminal rule at 65534 with a marker and removes it
on exit, leaving the preload rule alone. It installs rfor rules under
rule base 62000 with the rfor:rfortest marker, runs five sequential TCP
requests, a four-request
concurrent TCP burst, and ten UDP DNS queries. It prints
min/avg/p50/max latency in milliseconds and verifies that SIGTERM removes
the rules and the rfor_15080_rfortest table. It does not change the
default route, but it does modify the firewall; run it only on a
disposable VM. The shared tests/common/request-bench.sh helper must be
present in the checkout (or copied to /tmp/request-bench.sh).

## Checks performed

- IPv4 TCP through DIRECT and SOCKS5, with domain SNI/Host routing.
- IPv4 UDP request/response relay.
- IPv6 TCP and UDP through a VNET-jail daytime/echo service.
- Gateway-local TCP and UDP interception with `local-traffic: true`.
- Rule/table cleanup after SIGTERM.
- FreeBSD release unit tests: 39 passed.

Example client checks from the LAN VM:

```sh
fetch -q -o - http://198.18.1.10:18080/test
fetch -q -o - http://proxy.test:18080/test
printf hello-udp | nc -u -w 3 198.18.1.2 19000
nc -6 -w 3 2001:db8::10 13
printf x | nc -6 -u -w 3 2001:db8::10 13
```

`ipfw nat`, the QEMU `guestfwd` command, and the VNET jail are test scaffolding,
not requirements of the rfor backend.
