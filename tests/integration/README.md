# Docker integration test

Run the complete integration test from the repository root:

```sh
make integration-test
```

The test builds rfor in Docker and creates an isolated `198.18.0.0/24`
network with three containers:

- HTTP, TLS 1.2/TLS 1.3 HTTPS, corrupted-TLS, and server-first TCP origins;
- a SOCKS5 upstream with a controlled handshake delay;
- a privileged test container that installs real iptables and policy routes.

Both TPROXY and REDIRECT modes are exercised. Each phase verifies transparent
HTTP forwarding, timed and fragmented TLS ClientHello forwarding, corrupted
TLS fallback, server-first forwarding, concurrent connections during SIGHUP
reloads, absence of periodic rule reconstruction, and complete rule cleanup
after SIGTERM. Runtime traffic stays inside the Docker network.
