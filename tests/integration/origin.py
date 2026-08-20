#!/usr/bin/env python3

import http.server
import hashlib
import signal
import socket
import ssl
import socketserver
import subprocess
import threading
import urllib.parse


HTTP_BODY = b"rfor-integration-ok\n"
HTTPS_BODY = b"rfor-tls-integration-ok\n"
SERVER_FIRST_BODY = b"server-first-ok\n"
CORRUPTED_TLS_PROBE = b"\x16\x04\x00\x00\x04BAD!"
CORRUPTED_TLS_BODY = b"corrupted-tls-forwarded-ok\n"
SERVER_HALF_CLOSE_BODY = b"server-half-close-ok\n"
SERVER_HALF_CLOSE_TOKENS = set()
SERVER_HALF_CLOSE_LOCK = threading.Lock()


class DualStackServerMixin:
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class ReusableThreadingTCPServer(DualStackServerMixin, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DualStackThreadingHTTPServer(
    DualStackServerMixin, http.server.ThreadingHTTPServer
):
    pass


class HttpHandler(http.server.BaseHTTPRequestHandler):
    response_body = HTTP_BODY

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/server-half-close-status":
            token = urllib.parse.parse_qs(parsed.query).get("token", [""])[0]
            with SERVER_HALF_CLOSE_LOCK:
                received = token in SERVER_HALF_CLOSE_TOKENS
            body = b"server-half-close-read-ok\n" if received else b"pending\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, format, *args):
        return


class ServerFirstHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(SERVER_FIRST_BODY)


class CorruptedTlsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        received = bytearray()
        while len(received) < len(CORRUPTED_TLS_PROBE):
            chunk = self.request.recv(len(CORRUPTED_TLS_PROBE) - len(received))
            if not chunk:
                return
            received.extend(chunk)
        if bytes(received) == CORRUPTED_TLS_PROBE:
            self.request.sendall(CORRUPTED_TLS_BODY)


class ClientHalfCloseHandler(socketserver.BaseRequestHandler):
    def handle(self):
        received = bytearray()
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                break
            received.extend(chunk)
        digest = hashlib.sha256(received).hexdigest()
        self.request.sendall(
            f"client-half-close-ok:{len(received)}:{digest}\n".encode()
        )


class ServerHalfCloseHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request = bytearray()
        while b"\r\n\r\n" not in request:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            request.extend(chunk)

        self.request.sendall(SERVER_HALF_CLOSE_BODY)
        self.request.shutdown(socket.SHUT_WR)

        token = bytearray()
        while b"\n" not in token:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            token.extend(chunk)
        with SERVER_HALF_CLOSE_LOCK:
            SERVER_HALF_CLOSE_TOKENS.add(token.split(b"\n", 1)[0].decode())


class HttpsHandler(HttpHandler):
    response_body = HTTPS_BODY


def create_tls_context():
    cert_path = "/tmp/rfor-integration-cert.pem"
    key_path = "/tmp/rfor-integration-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=split.test",
            "-addext",
            "subjectAltName=DNS:split.test",
            "-keyout",
            key_path,
            "-out",
            cert_path,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert_path, key_path)
    return context


def main():
    http_server = DualStackThreadingHTTPServer(("::", 18080), HttpHandler)
    https_server = DualStackThreadingHTTPServer(("::", 18443), HttpsHandler)
    https_server.socket = create_tls_context().wrap_socket(https_server.socket, server_side=True)
    tcp_server = ReusableThreadingTCPServer(("::", 18081), ServerFirstHandler)
    corrupted_tls_server = ReusableThreadingTCPServer(("::", 18444), CorruptedTlsHandler)
    client_half_close_server = ReusableThreadingTCPServer(
        ("::", 18083), ClientHalfCloseHandler
    )
    server_half_close_server = ReusableThreadingTCPServer(
        ("::", 18084), ServerHalfCloseHandler
    )
    stopped = threading.Event()

    for server in (
        http_server,
        https_server,
        tcp_server,
        corrupted_tls_server,
        client_half_close_server,
        server_half_close_server,
    ):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def stop(_signum, _frame):
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    stopped.wait()

    http_server.shutdown()
    https_server.shutdown()
    tcp_server.shutdown()
    corrupted_tls_server.shutdown()
    client_half_close_server.shutdown()
    server_half_close_server.shutdown()


if __name__ == "__main__":
    main()
