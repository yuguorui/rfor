# Docker integration test

Run the complete integration test from the repository root:

```sh
make integration-test
```

The test builds rfor in Docker and creates an isolated `198.18.0.0/24`
network with three containers:

- an HTTP and server-first TCP origin;
- a SOCKS5 upstream with a controlled handshake delay;
- a privileged test container that installs real iptables and policy routes.

Both TPROXY and REDIRECT modes are exercised. Each phase verifies transparent
HTTP forwarding, fragmented and server-first TCP forwarding, absence of
periodic rule reconstruction, and complete rule cleanup after SIGTERM. The
TPROXY phase additionally routes a QUIC Initial packet crafted by an
independent RFC 9001 implementation (quic_sni.py, python-cryptography) and
checks that its SNI drives the domain rule. Runtime traffic stays inside the
Docker network.

## Soak test

Run the sustained local-traffic soak test with:

    ./tests/integration/run-soak.sh

or:

    make soak-test

The default runs two cycles. Each cycle sends TCP and UDP traffic for 30
seconds, then waits 75 seconds for UDP sessions to expire. The test
samples rfor RSS, thread count, file descriptors, and UDP sockets during
load and after idle; it fails on linear RSS/fd/UDP-socket growth between
cycles or request errors.

Environment knobs include SOAK_SECONDS, SOAK_IDLE_SECONDS, SOAK_CYCLES,
SOAK_TCP_WORKERS, SOAK_UDP_WORKERS, SOAK_UDP_RECYCLE,
SOAK_UDP_SLEEP_MS, SOAK_MAX_RSS_DELTA_KB, and SOAK_MAX_ERRORS.

A stronger profile used for the leak check:

    SOAK_CYCLES=3 SOAK_SECONDS=30 SOAK_UDP_WORKERS=4     SOAK_UDP_SLEEP_MS=2 SOAK_UDP_RECYCLE=200     SOAK_MAX_RSS_DELTA_KB=200000 SOAK_MAX_ERRORS=5     ./tests/integration/run-soak.sh

At that load the test sent 128,172 UDP and 4,640 TCP requests with no
errors; fd and UDP-socket counts returned to baseline after idle, and RSS
settled at roughly 39 MiB with no linear growth across cycles.

