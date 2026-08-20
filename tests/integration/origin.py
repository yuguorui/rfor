#!/usr/bin/env python3

import http.server
import signal
import ssl
import socketserver
import subprocess
import threading


HTTP_BODY = b"rfor-integration-ok\n"
HTTPS_BODY = b"rfor-tls-integration-ok\n"
SERVER_FIRST_BODY = b"server-first-ok\n"
CORRUPTED_TLS_PROBE = b"\x16\x04\x00\x00\x04BAD!"
CORRUPTED_TLS_BODY = b"corrupted-tls-forwarded-ok\n"


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HttpHandler(http.server.BaseHTTPRequestHandler):
    response_body = HTTP_BODY

    def do_GET(self):
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
    http_server = http.server.ThreadingHTTPServer(("0.0.0.0", 18080), HttpHandler)
    https_server = http.server.ThreadingHTTPServer(("0.0.0.0", 18443), HttpsHandler)
    https_server.socket = create_tls_context().wrap_socket(https_server.socket, server_side=True)
    tcp_server = ReusableThreadingTCPServer(("0.0.0.0", 18081), ServerFirstHandler)
    corrupted_tls_server = ReusableThreadingTCPServer(
        ("0.0.0.0", 18444), CorruptedTlsHandler
    )
    stopped = threading.Event()

    for server in (http_server, https_server, tcp_server, corrupted_tls_server):
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


if __name__ == "__main__":
    main()
