#!/usr/bin/env python3
"""Generate sustained local TCP and UDP traffic for the soak test."""

import argparse
import http.client
import json
import socket
import threading
import time


def tcp_worker(host, port, deadline, results):
    ok = 0
    errors = 0
    samples = []
    while time.monotonic() < deadline:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request("GET", "/test")
            response = conn.getresponse()
            body = response.read()
            if response.status == 200 and body == b"rfor-integration-ok\n":
                ok += 1
            else:
                errors += 1
        except Exception as exc:
            errors += 1
            if len(samples) < 5:
                samples.append(repr(exc))
        finally:
            conn.close()
    results.append((ok, errors, samples))


def udp_worker(host, port, deadline, recycle, sleep_seconds, results):
    ok = 0
    errors = 0
    samples = []
    count = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    while time.monotonic() < deadline:
        try:
            sock.sendto(b"ping", (host, port))
            data, _ = sock.recvfrom(64)
            if data == b"ping":
                ok += 1
            else:
                errors += 1
        except Exception as exc:
            errors += 1
            if len(samples) < 5:
                samples.append(repr(exc))
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
        count += 1
        if recycle > 0 and count % recycle == 0:
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
        if sleep_seconds:
            time.sleep(sleep_seconds)
    sock.close()
    results.append((ok, errors, samples))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--tcp-host", default="198.18.0.10")
    parser.add_argument("--tcp-port", type=int, default=18080)
    parser.add_argument("--udp-host", default="198.18.0.11")
    parser.add_argument("--udp-port", type=int, default=19000)
    parser.add_argument("--tcp-workers", type=int, default=4)
    parser.add_argument("--udp-workers", type=int, default=4)
    parser.add_argument("--udp-recycle", type=int, default=100)
    parser.add_argument("--udp-sleep-ms", type=float, default=5.0)
    args = parser.parse_args()

    deadline = time.monotonic() + args.seconds
    tcp_results = []
    udp_results = []
    threads = []
    for _ in range(args.tcp_workers):
        threads.append(
            threading.Thread(
                target=tcp_worker,
                args=(args.tcp_host, args.tcp_port, deadline, tcp_results),
                daemon=True,
            )
        )
    for _ in range(args.udp_workers):
        threads.append(
            threading.Thread(
                target=udp_worker,
                args=(
                    args.udp_host,
                    args.udp_port,
                    deadline,
                    args.udp_recycle,
                    args.udp_sleep_ms / 1000.0,
                    udp_results,
                ),
                daemon=True,
            )
        )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    tcp_ok = sum(item[0] for item in tcp_results)
    tcp_errors = sum(item[1] for item in tcp_results)
    udp_ok = sum(item[0] for item in udp_results)
    udp_errors = sum(item[1] for item in udp_results)
    tcp_samples = [sample for item in tcp_results for sample in item[2]][:10]
    udp_samples = [sample for item in udp_results for sample in item[2]][:10]
    print(
        json.dumps(
            {
                "seconds": args.seconds,
                "tcp_ok": tcp_ok,
                "tcp_errors": tcp_errors,
                "udp_ok": udp_ok,
                "udp_errors": udp_errors,
                "tcp_error_samples": tcp_samples,
                "udp_error_samples": udp_samples,
            }
        )
    )


if __name__ == "__main__":
    main()
