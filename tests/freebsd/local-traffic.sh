#!/bin/sh
# FreeBSD local-traffic integration test (ipfw fwd).
#
# Installs rfor's ipfw rules under rule base 62000 and exercises repeated
# local TCP/DNS traffic. Run on a disposable FreeBSD VM; the default route
# is not changed, but the firewall is modified.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f /tmp/request-bench.sh ]; then
    . /tmp/request-bench.sh
elif [ -f "$SCRIPT_DIR/../common/request-bench.sh" ]; then
    . "$SCRIPT_DIR/../common/request-bench.sh"
else
    echo "FAIL: request-bench.sh not found"
    exit 1
fi
cd "$SCRIPT_DIR/../.."

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "SKIP: this integration test only runs on FreeBSD"
    exit 0
fi
if [ "$(id -u)" != 0 ]; then
    echo "SKIP: root is required"
    exit 0
fi
if [ "${RFOR_ALLOW_IPFW_TEST:-}" != "1" ]; then
    echo "Set RFOR_ALLOW_IPFW_TEST=1 to install test ipfw rules."
    exit 1
fi

RFOR_BIN="${RFOR_BIN:-target/release/rfor}"
TCP_URL="${RFOR_TCP_URL:-https://1.1.1.1/}"
DNS_SERVER="${RFOR_DNS_SERVER:-8.8.8.8}"
DNS_NAME="${RFOR_DNS_NAME:-example.com}"
TCP_SEQ_REQUESTS=5
TCP_BURST_REQUESTS=4
DNS_REQUESTS=10
DNS_MIN_OK=7
ANCHOR="rfor:rfortest"
ALLOW_ANCHOR="rfor:rfortest-allow"
ALLOW_RULE=65534
TABLE="rfor_15080_rfortest"
LOG=""

fail() {
    echo "FAIL: $*"
    if [ -n "$LOG" ] && [ -f "$LOG" ]; then
        echo "--- rfor log ---"
        tail -80 "$LOG" || true
    fi
    exit 1
}
pass() {
    echo "PASS: $*"
}

if [ ! -x "$RFOR_BIN" ]; then
    echo "FAIL: rfor binary not executable: $RFOR_BIN"
    echo "Build it on FreeBSD with: cargo build --release"
    exit 1
fi
for tool in ipfw curl dig awk sort; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "FAIL: missing tool: $tool (pkg install curl bind-tools)"
        exit 1
    fi
done
if ! ipfw list >/dev/null 2>&1; then
    echo "FAIL: ipfw is not loaded."
    echo "Load it from the VM console and keep an allow rule, for example:"
    echo "  kldload ipfw"
    echo "  ipfw add 65530 allow ip from any to any"
    exit 1
fi
# Do not load ipfw over SSH: a freshly loaded ipfw defaults to deny and
# would drop this session before the test allow rule can be installed.
if ipfw list 2>/dev/null | grep -q "// $ANCHOR$"; then
    fail "stale $ANCHOR ipfw rules exist"
fi
if ipfw list 2>/dev/null | grep -q "// $ALLOW_ANCHOR$"; then
    fail "stale $ALLOW_ANCHOR ipfw rules exist"
fi
ipfw add "$ALLOW_RULE" allow ip from any to any // "$ALLOW_ANCHOR" >/dev/null || fail "could not add the test allow rule"

TMP=$(mktemp -d /tmp/rfor-freebsd-local.XXXXXX)
CONF="$TMP/rfor.yaml"
LOG="$TMP/rfor.log"
PID=""

cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    ipfw list 2>/dev/null | awk -v marker="// $ANCHOR$" '$0 ~ marker {print $1}' | while read -r rule; do
        ipfw delete "$rule" >/dev/null 2>&1 || true
    done
    ipfw list 2>/dev/null | awk -v marker="// $ALLOW_ANCHOR$" '$0 ~ marker {print $1}' | while read -r rule; do
        ipfw delete "$rule" >/dev/null 2>&1 || true
    done
    ipfw table "$TABLE" destroy >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

cat >"$CONF" <<YAML
debug: true
tproxy-listen: "127.0.0.1:15080"
socks5-listen: "127.0.0.1:11080"
udp-enabled: true
traffic-intercept:
  mode: ipfw
  local-traffic: true
  ports: [80, 443, 53]
  ipfw-rule-base: 62000
  tproxy-proxy-chain: rfor-test
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
YAML

"$RFOR_BIN" -c "$CONF" -w "$TMP" >"$LOG" 2>&1 &
PID=$!

i=0
READY=0
while [ "$i" -lt 20 ]; do
    if ! kill -0 "$PID" 2>/dev/null; then
        break
    fi
    if grep -q 'tproxy listen' "$LOG" 2>/dev/null && ipfw list 2>/dev/null | grep -q "// $ANCHOR"; then
        READY=1
        break
    fi
    sleep 1
    i=$((i + 1))
done
if [ "$READY" != "1" ]; then
    fail "rfor ipfw rules did not come up"
fi
pass "FreeBSD ipfw local-traffic rules are active"

TCP_LAT="$TMP/tcp.lat"
bench_tcp "$TCP_URL" "$TCP_SEQ_REQUESTS" "$TCP_LAT"
bench_stats "FreeBSD TCP sequential" "$BENCH_TCP_OK" "$TCP_SEQ_REQUESTS" "$TCP_LAT"
if [ "$BENCH_TCP_OK" -ne "$TCP_SEQ_REQUESTS" ]; then
    fail "local TCP succeeded $BENCH_TCP_OK/$TCP_SEQ_REQUESTS"
fi
pass "FreeBSD local TCP HTTPS ($BENCH_TCP_OK/$TCP_SEQ_REQUESTS)"

TCP_BURST_DIR="$TMP/tcp-burst"
bench_tcp_burst "$TCP_URL" "$TCP_BURST_REQUESTS" "$TCP_BURST_DIR"
bench_stats "FreeBSD TCP burst" "$BENCH_BURST_OK" "$TCP_BURST_REQUESTS" "$TCP_BURST_DIR/times"
if [ "$BENCH_BURST_OK" -ne "$TCP_BURST_REQUESTS" ]; then
    fail "local TCP burst succeeded $BENCH_BURST_OK/$TCP_BURST_REQUESTS"
fi
pass "FreeBSD local TCP burst ($BENCH_BURST_OK/$TCP_BURST_REQUESTS)"

DNS_LAT="$TMP/dns.lat"
bench_dns "$DNS_SERVER" "$DNS_NAME" "$DNS_REQUESTS" "$DNS_LAT"
bench_stats "FreeBSD UDP DNS" "$BENCH_DNS_OK" "$DNS_REQUESTS" "$DNS_LAT"
if [ "$BENCH_DNS_OK" -lt "$DNS_MIN_OK" ]; then
    fail "local UDP DNS succeeded $BENCH_DNS_OK/$DNS_REQUESTS, need at least $DNS_MIN_OK"
fi
pass "FreeBSD local UDP DNS ($BENCH_DNS_OK/$DNS_REQUESTS)"

if ! grep -q 'TPROXY:' "$LOG"; then
    fail "local traffic was not observed in the rfor route log"
fi
if ! grep -q 'Outbound(DIRECT)' "$LOG"; then
    fail "local traffic did not select the DIRECT outbound"
fi

kill "$PID"
wait "$PID" 2>/dev/null || true
PID=""
ipfw delete "$ALLOW_RULE" >/dev/null 2>&1 || true
if ipfw list 2>/dev/null | grep -q "// $ANCHOR$"; then
    fail "SIGTERM left ipfw rules behind"
fi
if ipfw table "$TABLE" list >/dev/null 2>&1; then
    fail "SIGTERM left the ipfw table behind"
fi
pass "SIGTERM removed the ipfw rules and table"

echo "all FreeBSD local-traffic integration tests passed"
