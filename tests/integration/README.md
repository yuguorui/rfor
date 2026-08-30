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

