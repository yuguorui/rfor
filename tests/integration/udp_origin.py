#!/usr/bin/env python3

import argparse
import socket


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="::")
    parser.add_argument("--port", type=int, default=18082)
    args = parser.parse_args()

    family = socket.AF_INET6 if ":" in args.listen else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((args.listen, args.port))
        while True:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)


if __name__ == "__main__":
    main()
