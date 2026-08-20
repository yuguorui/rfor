# Docker integration test

Run the complete integration test from the repository root:

```sh
make integration-test
```

The test builds rfor in Docker and creates an isolated dual-stack network
(`198.18.0.0/24` and `2001:db8:198:18::/64`) with four containers:

- HTTP, TLS 1.2/TLS 1.3 HTTPS, corrupted-TLS, and server-first TCP origins;
- a dual-stack UDP echo origin;
- a SOCKS5 upstream with a controlled handshake delay;
- a privileged test container that installs real iptables and policy routes.

Both TPROXY and REDIRECT modes are exercised over IPv4 and IPv6. Each phase
verifies transparent HTTP forwarding, timed and fragmented TLS ClientHello
forwarding, corrupted TLS fallback, server-first forwarding, concurrent
connections during SIGHUP reloads, IPv4/IPv6 policy rules, absence of periodic
rule reconstruction, and complete rule cleanup after SIGTERM. The TPROXY phase
also verifies ordinary UDP echo and session reuse over both address families.
Runtime traffic stays inside the Docker network.
