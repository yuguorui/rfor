#!/usr/bin/env python3

import http.server
import signal
import socketserver
import threading


HTTP_BODY = b"rfor-integration-ok\n"
SERVER_FIRST_BODY = b"server-first-ok\n"


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(HTTP_BODY)))
        self.end_headers()
        self.wfile.write(HTTP_BODY)

    def log_message(self, format, *args):
        return


class ServerFirstHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(SERVER_FIRST_BODY)


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def main():
    http_server = http.server.ThreadingHTTPServer(("0.0.0.0", 18080), HttpHandler)
    tcp_server = ReusableThreadingTCPServer(("0.0.0.0", 18081), ServerFirstHandler)
    udp_server = socketserver.ThreadingUDPServer(("198.18.0.11", 19000), UdpEchoHandler)
    udp_server.allow_reuse_address = True
    udp_server.daemon_threads = True
    stopped = threading.Event()

    for server in (http_server, tcp_server, udp_server):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def stop(_signum, _frame):
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    stopped.wait()

    http_server.shutdown()
    tcp_server.shutdown()
    udp_server.shutdown()


if __name__ == "__main__":
    main()

