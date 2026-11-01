#!/bin/sh
# Repeated FreeBSD ipfw rule/table start-stop cleanup test.
set -eu

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "SKIP: this test only runs on FreeBSD"
    exit 0
fi
if [ "$(id -u)" != "0" ]; then
    echo "SKIP: root is required"
    exit 0
fi
if [ "${RFOR_ALLOW_IPFW_TEST:-}" != "1" ]; then
    echo "Set RFOR_ALLOW_IPFW_TEST=1 on a disposable VM."
    exit 1
fi

RFOR_BIN="${RFOR_BIN:-target/release/rfor}"
CYCLES="${RFOR_RESTART_CYCLES:-10}"
PORT=15082
CHAIN="rfor-restart"
MARKER="rfor:rforrestart"
TABLE="rfor_15082_rforrestart"
RULE_BASE=62100
LOG=""
PID=""
CLEANED=0

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
    fail "rfor binary not executable: $RFOR_BIN"
fi
for tool in ipfw awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "missing tool: $tool"
    fi
done
if ! ipfw list >/dev/null 2>&1; then
    fail "ipfw is not loaded; load it from the VM console first"
fi
if ipfw list 2>/dev/null | grep -q "// $MARKER$"; then
    fail "stale $MARKER ipfw rules exist"
fi
if ipfw table "$TABLE" list >/dev/null 2>&1; then
    fail "stale ipfw table exists: $TABLE"
fi

BASE_RULES=$(ipfw list | wc -l | tr -d ' ')
TMP=$(mktemp -d /tmp/rfor-freebsd-restart.XXXXXX)
CONF="$TMP/rfor.yaml"
LOG="$TMP/rfor.log"

cleanup() {
    if [ "$CLEANED" = "1" ]; then
        return
    fi
    CLEANED=1
    exec >/dev/null 2>&1
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    ipfw list 2>/dev/null | awk -v marker="// $MARKER$" '$0 ~ marker {print $1}' | while read -r rule; do
        ipfw delete "$rule" >/dev/null 2>&1 || true
    done
    ipfw table "$TABLE" destroy >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

cat >"$CONF" <<YAML
debug: false
tproxy-listen: "127.0.0.1:$PORT"
socks5-listen: "127.0.0.1:11082"
udp-enabled: false
traffic-intercept:
  mode: ipfw
  local-traffic: true
  ports: [80, 443]
  ipfw-rule-base: $RULE_BASE
  tproxy-proxy-chain: $CHAIN
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
YAML

start_rfor() {
    "$RFOR_BIN" -c "$CONF" -w "$TMP" >"$LOG" 2>&1 &
    PID=$!
}

wait_up() {
    local i=0
    while [ "$i" -lt 20 ]; do
        if ! kill -0 "$PID" 2>/dev/null; then
            return 1
        fi
        if grep -q 'tproxy listen' "$LOG" 2>/dev/null &&            ipfw list 2>/dev/null | grep -q "// $MARKER$"; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

wait_clean() {
    local i=0
    while [ "$i" -lt 15 ]; do
        RULES=$(ipfw list | wc -l | tr -d ' ')
        if [ "$RULES" = "$BASE_RULES" ] &&            ! ipfw list 2>/dev/null | grep -q "// $MARKER$" &&            ! ipfw table "$TABLE" list >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

cycle=0
while [ "$cycle" -lt "$CYCLES" ]; do
    cycle=$((cycle + 1))
    start_rfor
    if ! wait_up; then
        fail "cycle $cycle: ipfw rules did not come up"
    fi
    pass "cycle $cycle: ipfw rules are up"

    kill "$PID"
    wait "$PID" 2>/dev/null || true
    PID=""
    if ! wait_clean; then
        fail "cycle $cycle: ipfw rules/table did not return to baseline"
    fi
    pass "cycle $cycle: ipfw rules and table cleaned"
done

echo "all $CYCLES FreeBSD restart soak cycles passed"
