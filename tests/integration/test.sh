#!/usr/bin/env bash

set -Eeuo pipefail

readonly ORIGIN_HOST=198.18.0.10
readonly HTTP_URL="http://${ORIGIN_HOST}:18080/test"
readonly EXPECTED_HTTP_BODY=rfor-integration-ok
readonly EXPECTED_SERVER_FIRST_BODY=server-first-ok
readonly SERVER_FIRST_TIMEOUT_SECONDS=8
readonly WORK_DIR=/tmp/rfor-integration

RFOR_PID=
RFOR_LOG=

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

assert_http_forwarding() {
    local body
    body=$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "$HTTP_URL") ||
        fail "HTTP forwarding failed"
    [[ $body == "$EXPECTED_HTTP_BODY" ]] || fail "unexpected HTTP response: ${body}"
}

assert_timed_http_forwarding() {
    local direct_count
    local first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    python3 - "$ORIGIN_HOST" "$EXPECTED_HTTP_BODY" <<'PY' || fail "timed HTTP forwarding failed"
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
    (5.5, [(request, 0)]),
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
    wait_for_log_after '-> 198.18.0.10:18080 -> Outbound(PROXY)' "$first_line"
    direct_count=$(tail -n "+${first_line}" "$RFOR_LOG" 2>/dev/null |
        grep --fixed-strings --count -- '-> split.test:18080 -> Outbound(DIRECT)' || true)
    [[ $direct_count -eq 3 ]] ||
        fail "expected three domain-routed timed requests, observed ${direct_count}"
}

assert_server_first_forwarding() {
    local body
    body=$(python3 - "$ORIGIN_HOST" "$SERVER_FIRST_TIMEOUT_SECONDS" <<'PY'
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

stress_reload() {
    local mode=$1
    local request_count=32
    local -a request_pids=()
    local request_id
    local failed=0

    log "${mode}: starting ${request_count} concurrent requests with SIGHUP reloads"
    for request_id in $(seq 1 "$request_count"); do
        curl --noproxy '*' --fail --silent --show-error --max-time 10 \
            "$HTTP_URL?request=${request_id}" \
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
    assert_http_forwarding
}

assert_route_reload() {
    local config_file=$1
    local backup_file="$WORK_DIR/$(basename "$config_file").route-backup"
    local first_line

    cp "$config_file" "$backup_file"
    sed -i 's/^  - DEFAULT,,PROXY$/  - DEFAULT,,DROP/' "$config_file"
    first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    kill -HUP "$RFOR_PID"
    wait_for_log_after 'Settings reloaded successfully.' "$first_line"
    if curl --noproxy '*' --fail --silent --max-time 2 "$HTTP_URL" >/dev/null; then
        fail "route reload did not activate the DROP outbound"
    fi

    cp "$backup_file" "$config_file"
    first_line=$(( $(wc -l < "$RFOR_LOG") + 1 ))
    kill -HUP "$RFOR_PID"
    wait_for_log_after 'Settings reloaded successfully.' "$first_line"
    assert_http_forwarding
}

assert_immutable_reload_rejected() {
    local config_file=$1
    local backup_file="$WORK_DIR/$(basename "$config_file").backup"

    cp "$config_file" "$backup_file"
    sed -i 's/^disable-ipv6: true$/disable-ipv6: false/' "$config_file"
    sed -i 's/^  - DEFAULT,,PROXY$/  - DEFAULT,,DROP/' "$config_file"
    kill -HUP "$RFOR_PID"
    wait_for_log 'Settings reload rejected; restart required for changes to: disable-ipv6'
    cp "$backup_file" "$config_file"

    assert_http_forwarding
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
    iptables --wait 5 --table mangle --list-rules rfor-it-proxy >/dev/null ||
        fail "TPROXY proxy chain is missing"
    iptables --wait 5 --table mangle --list-rules rfor-it-mark >/dev/null ||
        fail "TPROXY mark chain is missing"
    ip rule show | grep --quiet 'fwmark 0xff42 lookup 66' ||
        fail "TPROXY policy rule is missing"
    ip route show table 66 | grep --quiet 'local default dev lo' ||
        fail "TPROXY local route is missing"
}

assert_tproxy_cleanup() {
    if iptables --wait 5 --table mangle --list-rules rfor-it-proxy >/dev/null 2>&1; then
        fail "TPROXY proxy chain remained after shutdown"
    fi
    if iptables --wait 5 --table mangle --list-rules rfor-it-mark >/dev/null 2>&1; then
        fail "TPROXY mark chain remained after shutdown"
    fi
    if ip rule show | grep --quiet 'fwmark 0xff42 lookup 66'; then
        fail "TPROXY policy rule remained after shutdown"
    fi
    if ip route show table 66 | grep --quiet .; then
        fail "TPROXY route table remained after shutdown"
    fi
}

assert_redirect_rules() {
    iptables --wait 5 --table nat --check OUTPUT --jump rfor-it-redirect ||
        fail "REDIRECT OUTPUT jump is missing"
    iptables --wait 5 --table nat --list-rules rfor-it-redirect >/dev/null ||
        fail "REDIRECT chain is missing"
}

assert_redirect_cleanup() {
    if iptables --wait 5 --table nat --list-rules rfor-it-redirect >/dev/null 2>&1; then
        fail "REDIRECT chain remained after shutdown"
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
    RFOR_LOG=$WORK_DIR/tproxy.log
    rfor --config /integration/config-tproxy.yaml >"$RFOR_LOG" 2>&1 &
    RFOR_PID=$!
    wait_for_log 'tproxy listen: 0.0.0.0:15080'
    assert_tproxy_rules
    assert_http_forwarding
    assert_timed_http_forwarding
    assert_server_first_forwarding
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
    RFOR_LOG=$WORK_DIR/redirect.log
    rfor --config /integration/config-redirect.yaml >"$RFOR_LOG" 2>&1 &
    RFOR_PID=$!
    wait_for_log 'redirect listen:'
    assert_redirect_rules
    assert_http_forwarding
    assert_timed_http_forwarding
    assert_server_first_forwarding
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
