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
HTTP forwarding, server-first forwarding, concurrent connections during
SIGHUP reloads, absence of periodic rule reconstruction, and complete rule
cleanup after SIGTERM. Runtime traffic stays inside the Docker network.

