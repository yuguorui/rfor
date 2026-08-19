#!/usr/bin/env python3

import argparse
import selectors
import socket
import socketserver
import struct
import time


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        try:
            version, method_count = recv_exact(client, 2)
        except ConnectionError:
            return
        if version != 5:
            return
        recv_exact(client, method_count)
        client.sendall(b"\x05\x00")

        version, command, _reserved, address_type = recv_exact(client, 4)
        if version != 5 or command != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        if address_type == 1:
            host = socket.inet_ntop(socket.AF_INET, recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = struct.unpack("!H", recv_exact(client, 2))[0]

        time.sleep(self.server.delay_seconds)
        try:
            upstream = socket.create_connection((host, port), timeout=5)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        with upstream:
            bound_host, bound_port = upstream.getsockname()[:2]
            try:
                packed_host = socket.inet_pton(socket.AF_INET, bound_host)
                reply = b"\x05\x00\x00\x01" + packed_host
            except OSError:
                packed_host = socket.inet_pton(socket.AF_INET6, bound_host)
                reply = b"\x05\x00\x00\x04" + packed_host
            client.sendall(reply + struct.pack("!H", bound_port))
            relay(client, upstream)


def relay(left, right):
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    while True:
        for key, _events in selector.select(timeout=10):
            data = key.fileobj.recv(65536)
            if not data:
                return
            key.data.sendall(data)


class SocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--delay-ms", type=int, default=75)
    args = parser.parse_args()

    with SocksServer((args.listen, args.port), SocksHandler) as server:
        server.delay_seconds = args.delay_ms / 1000
        server.serve_forever()


if __name__ == "__main__":
    main()
