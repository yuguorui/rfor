#!/usr/bin/env bash

set -Eeuo pipefail

readonly ORIGIN_IPV4=198.18.0.10
readonly ORIGIN_IPV6=2001:db8:198:18::10
readonly UDP_ORIGIN_IPV4=198.18.0.11
readonly UDP_ORIGIN_IPV6=2001:db8:198:18::11
readonly EXPECTED_HTTP_BODY=rfor-integration-ok
readonly EXPECTED_HTTPS_BODY=rfor-tls-integration-ok
readonly EXPECTED_CORRUPTED_TLS_BODY=corrupted-tls-forwarded-ok
readonly EXPECTED_SERVER_FIRST_BODY=server-first-ok
readonly SERVER_FIRST_TIMEOUT_SECONDS=8
readonly WORK_DIR=/tmp/rfor-integration

RFOR_PID=
RFOR_LOG=
RFOR_MODE=

log() {
    printf '[integration] %s\n' "$*"
}

fail() {
    printf '[integration] ERROR: %s\n' "$*" >&2
    if [[ -n ${RFOR_LOG:-} && -f $RFOR_LOG ]]; then
        printf '%s\n' '--- rfor log ---' >&2
        tail -200 "$RFOR_LOG" >&2
    fi
    exit 1
}

cleanup() {
    if [[ -n ${RFOR_PID:-} ]] && kill -0 "$RFOR_PID" 2>/dev/null; then
        kill -KILL "$RFOR_PID" 2>/dev/null || true
        wait "$RFOR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

wait_for_log() {
    local pattern=$1
    for _attempt in $(seq 1 100); do
        if grep --fixed-strings --quiet -- "$pattern" "$RFOR_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$RFOR_PID" 2>/dev/null; then
            fail "rfor exited before logging: ${pattern}"
        fi
        sleep 0.05
    done
    fail "timed out waiting for log: ${pattern}"
}

wait_for_log_after() {
    local pattern=$1
    local first_line=$2
    for _attempt in $(seq 1 100); do
        if tail -n "+${first_line}" "$RFOR_LOG" 2>/dev/null |
            grep --fixed-strings --quiet -- "$pattern"; then
            return 0
        fi
        if ! kill -0 "$RFOR_PID" 2>/dev/null; then
            fail "rfor exited before logging: ${pattern}"
        fi
        sleep 0.05
    done
    fail "timed out waiting for new log: ${pattern}"
}

format_target() {
    local host=$1
    local port=$2
    if [[ $host == *:* ]]; then
        printf '[%s]:%s' "$host" "$port"
    else
        printf '%s:%s' "$host" "$port"
    fi
}

format_route_target() {
    local host=$1
    local port=$2
    if [[ $RFOR_MODE == TPROXY && $host != *:* ]]; then
        printf '[::ffff:%s]:%s' "$host" "$port"
    else
        format_target "$host" "$port"
    fi
}

http_url() {
    printf 'http://%s/test' "$(format_target "$1" 18080)"
}

assert_http_forwarding() {
    local host=$1
    local body
    body=$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "$(http_url "$host")") ||
        fail "HTTP forwarding failed"
    [[ $body == "$EXPECTED_HTTP_BODY" ]] || fail "unexpected HTTP response: ${body}"
}

assert_timed_http_forwarding() {
    local host=$1
    local direct_count
    local fallback_target
    local first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    python3 - "$host" "$EXPECTED_HTTP_BODY" <<'PY' || fail "timed HTTP forwarding failed"
import socket
import sys
import time

host = sys.argv[1]
expected = sys.argv[2].encode()
request = b"GET /test HTTP/1.1\r\nHost: split.test\r\nConnection: close\r\n\r\n"

cases = [
    (0, [(request, 0)]),
    (0.2, [(request, 0)]),
    (0, [
        (b"GE", 0.05),
        (b"T /test HTTP/1.1\r\nHost: split", 0.1),
        (b".test\r\nConnection: close\r\n\r\n", 0),
    ]),
    (1.0, [(request, 0)]),
]

for initial_delay, fragments in cases:
    with socket.create_connection((host, 18080), timeout=2) as sock:
        sock.settimeout(10)
        time.sleep(initial_delay)
        for fragment, delay_after in fragments:
            sock.sendall(fragment)
            time.sleep(delay_after)
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        body = bytes(response).split(b"\r\n\r\n", 1)[-1].strip()
        if body != expected:
            raise RuntimeError(f"unexpected response body: {body!r}")
PY
    wait_for_log_after '-> split.test:18080 -> Outbound(DIRECT)' "$first_line"
    fallback_target=$(format_route_target "$host" 18080)
    wait_for_log_after "-> ${fallback_target} -> Outbound(PROXY)" "$first_line"
    direct_count=$(tail -n "+${first_line}" "$RFOR_LOG" 2>/dev/null |
        grep --fixed-strings --count -- '-> split.test:18080 -> Outbound(DIRECT)' || true)
    [[ $direct_count -eq 3 ]] ||
        fail "expected three domain-routed timed requests, observed ${direct_count}"
}

assert_timed_tls_forwarding() {
    local host=$1
    local direct_count
    local first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    python3 - "$host" "$EXPECTED_HTTPS_BODY" <<'PY' || fail "timed TLS forwarding failed"
import socket
import ssl
import sys
import time

host = sys.argv[1]
expected = sys.argv[2].encode()
request = b"GET /test HTTP/1.1\r\nHost: split.test\r\nConnection: close\r\n\r\n"


def flush_outgoing(raw_sock, outgoing, fragment_client_hello):
    first_flight = True
    while True:
        encrypted = outgoing.read()
        if not encrypted:
            return
        if fragment_client_hello and first_flight:
            offsets = [1, 5, 23, len(encrypted)]
            start = 0
            for end in offsets:
                raw_sock.sendall(encrypted[start:end])
                start = end
                if end != len(encrypted):
                    time.sleep(0.05)
        else:
            raw_sock.sendall(encrypted)
        first_flight = False


def tls_request(tls_version, expected_version, initial_delay, fragment_client_hello):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = tls_version
    context.maximum_version = tls_version
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname="split.test")

    with socket.create_connection((host, 18443), timeout=2) as raw_sock:
        raw_sock.settimeout(10)
        time.sleep(initial_delay)
        first_flight = fragment_client_hello

        while True:
            try:
                tls.do_handshake()
                flush_outgoing(raw_sock, outgoing, first_flight)
                break
            except ssl.SSLWantReadError:
                flush_outgoing(raw_sock, outgoing, first_flight)
                first_flight = False
                encrypted = raw_sock.recv(16384)
                if not encrypted:
                    raise RuntimeError("TLS peer closed during handshake")
                incoming.write(encrypted)
            except ssl.SSLWantWriteError:
                flush_outgoing(raw_sock, outgoing, first_flight)
                first_flight = False

        if tls.version() != expected_version:
            raise RuntimeError(f"negotiated {tls.version()}, expected {expected_version}")
        tls.write(request)
        flush_outgoing(raw_sock, outgoing, False)
        response = bytearray()
        while expected not in response:
            try:
                decrypted = tls.read(4096)
                if not decrypted:
                    break
                response.extend(decrypted)
            except ssl.SSLWantReadError:
                encrypted = raw_sock.recv(16384)
                if not encrypted:
                    break
                incoming.write(encrypted)
        body = bytes(response).split(b"\r\n\r\n", 1)[-1].strip()
        if body != expected:
            raise RuntimeError(f"unexpected TLS response body: {body!r}")


versions = [
    (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
    (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
]
timings = [(0, False), (0.2, False), (0, True)]
for tls_version, expected_version in versions:
    for timing in timings:
        tls_request(tls_version, expected_version, *timing)
PY
    wait_for_log_after '-> split.test:18443 -> Outbound(DIRECT)' "$first_line"
    direct_count=$(tail -n "+${first_line}" "$RFOR_LOG" 2>/dev/null |
        grep --fixed-strings --count -- '-> split.test:18443 -> Outbound(DIRECT)' || true)
    [[ $direct_count -eq 6 ]] ||
        fail "expected six domain-routed TLS requests, observed ${direct_count}"
}

assert_corrupted_tls_fallback() {
    local host=$1
    local body
    local fallback_target
    local first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    body=$(python3 - "$host" <<'PY'
import socket
import sys
import time

payload = b"\x16\x04\x00\x00\x04BAD!"
with socket.create_connection((sys.argv[1], 18444), timeout=2) as sock:
    sock.settimeout(2)
    sock.sendall(payload[:1])
    time.sleep(0.05)
    sock.sendall(payload[1:])
    print(sock.recv(128).decode().strip())
PY
    ) || fail "corrupted TLS did not fall back within two seconds"
    [[ $body == "$EXPECTED_CORRUPTED_TLS_BODY" ]] ||
        fail "unexpected corrupted TLS response: ${body}"
    fallback_target=$(format_route_target "$host" 18444)
    wait_for_log_after "-> ${fallback_target} -> Outbound(PROXY)" "$first_line"
}

assert_server_first_forwarding() {
    local host=$1
    local body
    body=$(python3 - "$host" "$SERVER_FIRST_TIMEOUT_SECONDS" <<'PY'
import socket
import sys

timeout = float(sys.argv[2])
with socket.create_connection((sys.argv[1], 18081), timeout=timeout) as sock:
    sock.settimeout(timeout)
    print(sock.recv(128).decode().strip())
PY
    ) || fail "server-first forwarding exceeded ${SERVER_FIRST_TIMEOUT_SECONDS} seconds"
    [[ $body == "$EXPECTED_SERVER_FIRST_BODY" ]] ||
        fail "unexpected server-first response: ${body}"
}

assert_family_forwarding() {
    local host=$1
    assert_http_forwarding "$host"
    assert_timed_http_forwarding "$host"
    assert_timed_tls_forwarding "$host"
    assert_corrupted_tls_fallback "$host"
    assert_server_first_forwarding "$host"
}

assert_udp_forwarding() {
    local host=$1
    local first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    local route_target
    local session_count

    python3 - "$host" <<'PY' || fail "UDP forwarding failed for ${host}"
import socket
import sys

host = sys.argv[1]
family = socket.AF_INET6 if ":" in host else socket.AF_INET
messages = [
    b"udp-single-packet",
    bytes(range(64)),
    bytes((index * 31) % 256 for index in range(511)),
    bytes((index * 17) % 256 for index in range(1400)),
    bytes((index * 7) % 256 for index in range(4096)),
]

with socket.socket(family, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.connect((host, 18082))
    for message in messages:
        sock.send(message)
        echoed = sock.recv(65535)
        if echoed != message:
            raise RuntimeError(
                f"UDP echo mismatch: sent {len(message)} bytes, received {len(echoed)}"
            )
PY

    route_target=$(format_route_target "$host" 18082)
    wait_for_log_after "DGRAM -> ${route_target} -> Outbound(DIRECT)" "$first_line"
    session_count=$(tail -n "+${first_line}" "$RFOR_LOG" 2>/dev/null |
        grep --fixed-strings --count -- 'udp relay: create tunnel' || true)
    [[ $session_count -eq 1 ]] ||
        fail "expected one reused UDP session for ${host}, observed ${session_count}"
}

stress_reload() {
    local mode=$1
    local request_count=32
    local -a request_pids=()
    local request_id
    local request_host
    local request_url
    local failed=0

    log "${mode}: starting ${request_count} concurrent requests with SIGHUP reloads"
    for request_id in $(seq 1 "$request_count"); do
        if (( request_id % 2 == 0 )); then
            request_host=$ORIGIN_IPV6
        else
            request_host=$ORIGIN_IPV4
        fi
        request_url="$(http_url "$request_host")?request=${request_id}"
        curl --noproxy '*' --fail --silent --show-error --max-time 10 \
            "$request_url" \
            --output "$WORK_DIR/${mode}-${request_id}.out" &
        request_pids+=("$!")
    done

    for _reload in $(seq 1 12); do
        kill -HUP "$RFOR_PID"
        sleep 0.02
    done

    for request_id in "${!request_pids[@]}"; do
        if ! wait "${request_pids[$request_id]}"; then
            failed=1
            continue
        fi
        if [[ $(<"$WORK_DIR/${mode}-$((request_id + 1)).out") != "$EXPECTED_HTTP_BODY" ]]; then
            failed=1
        fi
    done

    [[ $failed == 0 ]] || fail "${mode}: one or more concurrent requests failed"
    wait_for_log "Settings reloaded successfully."
    assert_http_forwarding "$ORIGIN_IPV4"
    assert_http_forwarding "$ORIGIN_IPV6"
}

assert_route_reload() {
    local config_file=$1
    local backup_file="$WORK_DIR/$(basename "$config_file").route-backup"
    local first_line
    local host

    cp "$config_file" "$backup_file"
    sed -i 's/^  - DEFAULT,,PROXY$/  - DEFAULT,,DROP/' "$config_file"
    first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    kill -HUP "$RFOR_PID"
    wait_for_log_after 'Settings reloaded successfully.' "$first_line"
    for host in "$ORIGIN_IPV4" "$ORIGIN_IPV6"; do
        if curl --noproxy '*' --fail --silent --max-time 2 "$(http_url "$host")" >/dev/null; then
            fail "route reload did not activate the DROP outbound for ${host}"
        fi
    done

    cp "$backup_file" "$config_file"
    first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    kill -HUP "$RFOR_PID"
    wait_for_log_after 'Settings reloaded successfully.' "$first_line"
    assert_http_forwarding "$ORIGIN_IPV4"
    assert_http_forwarding "$ORIGIN_IPV6"
}

assert_immutable_reload_rejected() {
    local config_file=$1
    local backup_file="$WORK_DIR/$(basename "$config_file").backup"

    cp "$config_file" "$backup_file"
    sed -i 's/^disable-ipv6: false$/disable-ipv6: true/' "$config_file"
    sed -i 's/^  - DEFAULT,,PROXY$/  - DEFAULT,,DROP/' "$config_file"
    kill -HUP "$RFOR_PID"
    wait_for_log 'Settings reload rejected; restart required for changes to: disable-ipv6'
    cp "$backup_file" "$config_file"

    assert_http_forwarding "$ORIGIN_IPV4"
    assert_http_forwarding "$ORIGIN_IPV6"
}

stop_rfor() {
    local mode=$1
    kill -TERM "$RFOR_PID"
    for _attempt in $(seq 1 100); do
        if ! kill -0 "$RFOR_PID" 2>/dev/null; then
            wait "$RFOR_PID" 2>/dev/null || true
            RFOR_PID=
            return 0
        fi
        sleep 0.05
    done
    fail "${mode}: rfor did not exit after SIGTERM"
}

assert_tproxy_rules() {
    iptables --wait 5 --table mangle --check OUTPUT --jump rfor-it-mark ||
        fail "TPROXY OUTPUT jump is missing"
    ip6tables --wait 5 --table mangle --check OUTPUT --jump rfor-it-mark ||
        fail "TPROXY IPv6 OUTPUT jump is missing"
    iptables --wait 5 --table mangle --list-rules rfor-it-proxy >/dev/null ||
        fail "TPROXY proxy chain is missing"
    ip6tables --wait 5 --table mangle --list-rules rfor-it-proxy >/dev/null ||
        fail "TPROXY IPv6 proxy chain is missing"
    iptables --wait 5 --table mangle --list-rules rfor-it-mark >/dev/null ||
        fail "TPROXY mark chain is missing"
    ip6tables --wait 5 --table mangle --list-rules rfor-it-mark >/dev/null ||
        fail "TPROXY IPv6 mark chain is missing"
    iptables --wait 5 --table mangle --check rfor-it-proxy \
        --protocol udp --match multiport --dports '18080:18082,18443:18444' \
        --jump TPROXY --tproxy-mark 0xff42 --on-port 15080 ||
        fail "TPROXY UDP rule is missing"
    ip6tables --wait 5 --table mangle --check rfor-it-proxy \
        --protocol udp --match multiport --dports '18080:18082,18443:18444' \
        --jump TPROXY --tproxy-mark 0xff42 --on-port 15080 ||
        fail "TPROXY IPv6 UDP rule is missing"
    for _attempt in $(seq 1 100); do
        if ip rule show | grep --quiet 'fwmark 0xff42 lookup 66' &&
            ip route show table 66 | grep --quiet 'local default dev lo' &&
            ip -6 rule show | grep --quiet 'fwmark 0xff42 lookup 66' &&
            ip -6 route show table 66 | grep --quiet 'local default dev lo'; then
            return
        fi
        sleep 0.05
    done
    fail "TPROXY policy rule or local route is missing"
}

assert_tproxy_cleanup() {
    if iptables --wait 5 --table mangle --list-rules rfor-it-proxy >/dev/null 2>&1; then
        fail "TPROXY proxy chain remained after shutdown"
    fi
    if iptables --wait 5 --table mangle --list-rules rfor-it-mark >/dev/null 2>&1; then
        fail "TPROXY mark chain remained after shutdown"
    fi
    if ip6tables --wait 5 --table mangle --list-rules rfor-it-proxy >/dev/null 2>&1; then
        fail "TPROXY IPv6 proxy chain remained after shutdown"
    fi
    if ip6tables --wait 5 --table mangle --list-rules rfor-it-mark >/dev/null 2>&1; then
        fail "TPROXY IPv6 mark chain remained after shutdown"
    fi
    if ip rule show | grep --quiet 'fwmark 0xff42 lookup 66'; then
        fail "TPROXY policy rule remained after shutdown"
    fi
    if ip route show table 66 | grep --quiet .; then
        fail "TPROXY route table remained after shutdown"
    fi
    if ip -6 rule show | grep --quiet 'fwmark 0xff42 lookup 66'; then
        fail "TPROXY IPv6 policy rule remained after shutdown"
    fi
    if ip -6 route show table 66 | grep --quiet .; then
        fail "TPROXY IPv6 route table remained after shutdown"
    fi
}

assert_redirect_rules() {
    iptables --wait 5 --table nat --check OUTPUT --jump rfor-it-redirect ||
        fail "REDIRECT OUTPUT jump is missing"
    ip6tables --wait 5 --table nat --check OUTPUT --jump rfor-it-redirect ||
        fail "REDIRECT IPv6 OUTPUT jump is missing"
    iptables --wait 5 --table nat --list-rules rfor-it-redirect >/dev/null ||
        fail "REDIRECT chain is missing"
    ip6tables --wait 5 --table nat --list-rules rfor-it-redirect >/dev/null ||
        fail "REDIRECT IPv6 chain is missing"
}

assert_redirect_cleanup() {
    if iptables --wait 5 --table nat --list-rules rfor-it-redirect >/dev/null 2>&1; then
        fail "REDIRECT chain remained after shutdown"
    fi
    if ip6tables --wait 5 --table nat --list-rules rfor-it-redirect >/dev/null 2>&1; then
        fail "REDIRECT IPv6 chain remained after shutdown"
    fi
}

assert_not_reconciled() {
    local mode=$1
    local table=$2
    local chain=$3

    iptables --wait 5 --table "$table" --delete OUTPUT --jump "$chain"
    log "${mode}: waiting past the former reconciliation interval"
    sleep 11
    if iptables --wait 5 --table "$table" --check OUTPUT --jump "$chain" 2>/dev/null; then
        fail "${mode}: deleted OUTPUT jump was automatically rebuilt"
    fi
}

run_tproxy_test() {
    log 'TPROXY: starting rfor'
    RFOR_MODE=TPROXY
    RFOR_LOG=$WORK_DIR/tproxy.log
    rfor --config /integration/config-tproxy.yaml >"$RFOR_LOG" 2>&1 &
    RFOR_PID=$!
    wait_for_log 'tproxy listen: [::]:15080'
    assert_tproxy_rules
    assert_family_forwarding "$ORIGIN_IPV4"
    assert_family_forwarding "$ORIGIN_IPV6"
    assert_udp_forwarding "$UDP_ORIGIN_IPV4"
    assert_udp_forwarding "$UDP_ORIGIN_IPV6"
    stress_reload TPROXY
    assert_route_reload /integration/config-tproxy.yaml
    assert_immutable_reload_rejected /integration/config-tproxy.yaml
    grep --quiet 'TPROXY:' "$RFOR_LOG" || fail 'TPROXY traffic was not observed in the route log'
    assert_not_reconciled TPROXY mangle rfor-it-mark
    stop_rfor TPROXY
    assert_tproxy_cleanup
    log 'TPROXY: passed'
}

run_redirect_test() {
    log 'REDIRECT: starting rfor'
    RFOR_MODE=REDIRECT
    RFOR_LOG=$WORK_DIR/redirect.log
    rfor --config /integration/config-redirect.yaml >"$RFOR_LOG" 2>&1 &
    RFOR_PID=$!
    wait_for_log 'redirect listen:'
    assert_redirect_rules
    assert_family_forwarding "$ORIGIN_IPV4"
    assert_family_forwarding "$ORIGIN_IPV6"
    stress_reload REDIRECT
    assert_route_reload /integration/config-redirect.yaml
    assert_immutable_reload_rejected /integration/config-redirect.yaml
    grep --quiet 'REDIRECT:' "$RFOR_LOG" || fail 'REDIRECT traffic was not observed in the route log'
    assert_not_reconciled REDIRECT nat rfor-it-redirect
    stop_rfor REDIRECT
    assert_redirect_cleanup
    log 'REDIRECT: passed'
}

mkdir -p "$WORK_DIR"
run_tproxy_test
run_redirect_test
log 'all Docker integration checks passed'
