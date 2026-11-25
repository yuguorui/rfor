#!/bin/sh
# macOS local-traffic integration test (utun + smoltcp + IP_BOUND_IF).
#
# Installs split-default routes onto a dynamically created utun interface and
# exercises local TCP, HTTPS/TLS SNI, HTTP Host, UDP DNS, SOCKS5 TCP/UDP
# upstreams, NXDOMAIN drop replies, QUIC v1/v2 SNI sniffing, non-intercepted
# port bypass, SIGTERM route cleanup, and restart soak cycles.
# Run inside a disposable macOS VM as root with RFOR_ALLOW_UTUN_TEST=1.
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

if [ "$(uname -s)" != "Darwin" ]; then
    echo "SKIP: this integration test only runs on macOS"
    exit 0
fi
if [ "$(id -u)" != 0 ]; then
    echo "SKIP: root is required"
    exit 0
fi
if [ "${RFOR_ALLOW_UTUN_TEST:-}" != "1" ]; then
    echo "Set RFOR_ALLOW_UTUN_TEST=1 on a disposable macOS VM."
    exit 1
fi

RFOR_BIN="${RFOR_BIN:-${1:-target/release/rfor}}"
QUIC_SNI_PY="${QUIC_SNI_PY:-}"
if [ -z "$QUIC_SNI_PY" ]; then
    if [ -f /tmp/quic_sni.py ]; then
        QUIC_SNI_PY=/tmp/quic_sni.py
    elif [ -f "$SCRIPT_DIR/../integration/quic_sni.py" ]; then
        QUIC_SNI_PY="$SCRIPT_DIR/../integration/quic_sni.py"
    fi
fi

TCP_URL="${RFOR_TCP_URL:-https://1.1.1.1/}"
DNS_SERVER="${RFOR_DNS_SERVER:-8.8.8.8}"
DNS_NAME="${RFOR_DNS_NAME:-example.com}"
TCP_SEQ_REQUESTS=5
TCP_BURST_REQUESTS=8
DNS_REQUESTS=10
DNS_MIN_OK=8
SOAK_CYCLES="${RFOR_RESTART_CYCLES:-5}"

fail() {
    echo "FAIL: $*" >&2
    if [ -n "${LOG:-}" ] && [ -f "$LOG" ]; then
        echo "--- rfor log ---" >&2
        tail -120 "$LOG" >&2 || true
    fi
    if [ -n "${UPSTREAM_LOG:-}" ] && [ -f "$UPSTREAM_LOG" ]; then
        echo "--- upstream socks5 log ---" >&2
        tail -60 "$UPSTREAM_LOG" >&2 || true
    fi
    exit 1
}

pass() {
    echo "PASS: $*"
}

if [ ! -x "$RFOR_BIN" ]; then
    fail "rfor binary not executable: $RFOR_BIN"
fi
for tool in curl ifconfig route netstat awk sort grep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "missing required tool: $tool"
    fi
done

PYTHON_BIN=""
for cand in /opt/homebrew/bin/python3 /usr/local/bin/python3 "$(command -v python3 2>/dev/null || true)"; do
    if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" -c "import socket, struct" >/dev/null 2>&1; then
        PYTHON_BIN="$cand"
        break
    fi
done
[ -n "$PYTHON_BIN" ] || fail "working python3 interpreter not found"

TMP=$(mktemp -d /tmp/rfor-macos-local.XXXXXX)
UPSTREAM_CONF="$TMP/upstream.yaml"
UPSTREAM_LOG="$TMP/upstream.log"
CONF="$TMP/rfor.yaml"
LOG="$TMP/rfor.log"
DNS_HELPER="$TMP/dns_query.py"
UPSTREAM_PID=""
PID=""

cat >"$DNS_HELPER" <<'PY'
import socket
import struct
import sys
import time

def build_query(qname, qid=0x4242):
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.strip(".").split("."))
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    return header + question

def query(server, name, timeout=3.0):
    pkt = build_query(name)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.sendto(pkt, (server, 53))
        resp, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    dt_ms = (time.monotonic() - t0) * 1000.0
    if len(resp) < 12:
        raise RuntimeError(f"short dns response: {len(resp)}")
    qid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", resp[:12])
    rcode = flags & 0x0F
    qr = (flags >> 15) & 1
    if qid != 0x4242 or qr != 1:
        raise RuntimeError(f"unexpected dns header: qid={qid:#x} flags={flags:#x}")
    return rcode, ancount, dt_ms

if __name__ == "__main__":
    mode = sys.argv[1]
    server = sys.argv[2]
    name = sys.argv[3]
    if mode == "check":
        expect_rcode = int(sys.argv[4])
        last_err = None
        for _attempt in range(3):
            try:
                rcode, ancount, dt_ms = query(server, name)
                break
            except (TimeoutError, socket.timeout) as exc:
                last_err = exc
        else:
            raise last_err
        if rcode != expect_rcode:
            raise SystemExit(f"expected rcode={expect_rcode}, got {rcode} (ancount={ancount})")
        if expect_rcode == 0 and ancount < 1:
            raise SystemExit(f"expected >=1 answer for {name}, got 0")
        print(f"{dt_ms:.3f}")
    elif mode == "bench":
        count = int(sys.argv[4])
        out_path = sys.argv[5]
        ok = 0
        with open(out_path, "w", encoding="ascii") as fh:
            for _ in range(count):
                try:
                    rcode, ancount, dt_ms = query(server, name)
                    if rcode == 0 and ancount >= 1:
                        ok += 1
                        print(f"{dt_ms:.3f}", file=fh)
                except Exception:
                    pass
        print(ok)
    elif mode == "burst":
        import concurrent.futures
        count = int(sys.argv[4])
        out_path = sys.argv[5]
        def one(_):
            try:
                rcode, ancount, dt_ms = query(server, name)
                if rcode == 0 and ancount >= 1:
                    return dt_ms
            except Exception:
                pass
            return None
        ok = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            results = list(pool.map(one, range(count)))
        with open(out_path, "w", encoding="ascii") as fh:
            for val in results:
                if val is not None:
                    ok += 1
                    print(f"{val:.3f}", file=fh)
        print(ok)
PY

ORIG_EGRESS_IF=""
ORIG_GW=""

cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    if [ -n "$UPSTREAM_PID" ] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        kill -TERM "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    if [ -n "$ORIG_GW" ] && ! route -n get default >/dev/null 2>&1; then
        route -n add default "$ORIG_GW" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

snapshot_utun() {
    ifconfig -l | tr ' ' '\n' | grep '^utun' | sort || true
}

snapshot_v4_routes() {
    netstat -rn -f inet | awk 'NF >= 4 && $3 !~ /W/ {print $1, $2, $3, $4}' | sort
}

BASE_UTUNS="$TMP/base.utuns"
BASE_ROUTES="$TMP/base.routes"
snapshot_utun >"$BASE_UTUNS"
snapshot_v4_routes >"$BASE_ROUTES"

# Start an upstream SOCKS5 rfor instance on loopback to verify both
# loopback bypass (IP_BOUND_IF skipped for 127.0.0.1) and SOCKS5 TCP/UDP relay.
# Pin its outbound sockets to the physical default egress interface so they use
# the -ifscope bypass route rather than re-entering utun via 0.0.0.0/1.
EGRESS_IF=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')
[ -n "$EGRESS_IF" ] || fail "failed to determine default egress interface"

cat >"$UPSTREAM_CONF" <<YAML
debug: true
socks5-listen: "127.0.0.1:11081"
egress-interface: "$EGRESS_IF"
udp-enabled: true
traffic-intercept:
  mode: manual
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
YAML

"$RFOR_BIN" -c "$UPSTREAM_CONF" -w "$TMP" >"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!

i=0
while [ "$i" -lt 20 ]; do
    if ! kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        fail "upstream socks5 rfor exited unexpectedly"
    fi
    if grep -q 'socks5 listen: 127.0.0.1:11081' "$UPSTREAM_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.25
    i=$((i + 1))
done
grep -q 'socks5 listen: 127.0.0.1:11081' "$UPSTREAM_LOG" || fail "upstream socks5 did not listen"
pass "upstream loopback SOCKS5 listener is up"

cat >"$CONF" <<YAML
debug: true
udp-enabled: true
udp-timeout: 30
drop-reply:
  dns: nxdomain
traffic-intercept:
  mode: auto
  local-traffic: true
  ports: [80, 443, 53]
  bypass-cidrs:
    - "1.0.0.1/32"
    - "30.0.0.0/8"
    - "2001:db8:cafe::/48"
outbounds:
  - name: DIRECT
  - name: PROXY
    url: socks5://127.0.0.1:11081
  - name: DROP
    url: drop://0.0.0.0
rules:
  - DEFAULT,,DIRECT
  - IP-CIDR,203.0.113.10/32,PROXY
  - IP-CIDR,203.0.113.20/32,DROP
  - DOMAIN,one.one.one.one,PROXY
  - DOMAIN,quic-v1.test,PROXY
  - DOMAIN,quic-v2.test,PROXY
  - DOMAIN,blocked.test,DROP
YAML

start_rfor() {
    local conf="${1:-$CONF}"
    local log_filter="${2:-rfor=info}"
    : >"$LOG"
    RUST_LOG="$log_filter" "$RFOR_BIN" -c "$conf" -w "$TMP" >"$LOG" 2>&1 &
    PID=$!
    local j=0
    while [ "$j" -lt 40 ]; do
        if ! kill -0 "$PID" 2>/dev/null; then
            return 1
        fi
        if grep -q 'utun listen:' "$LOG" 2>/dev/null &&
            netstat -rn -f inet | awk '{print $1}' | grep -q '^0/1$' &&
            netstat -rn -f inet | awk '{print $1}' | grep -q '^128\.0/1$'; then
            return 0
        fi
        sleep 0.25
        j=$((j + 1))
    done
    return 1
}

stop_and_verify_clean() {
    local ignore_default_flags="${1:-0}"
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID"
        wait "$PID" 2>/dev/null || true
    fi
    PID=""

    local cur_utuns="$TMP/cur.utuns"
    local cur_routes="$TMP/cur.routes"
    local base_cmp="$BASE_ROUTES"
    local cur_cmp="$cur_routes"
    if [ "$ignore_default_flags" = "1" ]; then
        base_cmp="$TMP/base.routes.norm"
        cur_cmp="$TMP/cur.routes.norm"
        awk '{if ($1 == "default") $3 = "*"; print}' "$BASE_ROUTES" >"$base_cmp"
    fi
    local settled=0
    local j=0
    while [ "$j" -lt 20 ]; do
        snapshot_utun >"$cur_utuns"
        snapshot_v4_routes >"$cur_routes"
        if [ "$ignore_default_flags" = "1" ]; then
            awk '{if ($1 == "default") $3 = "*"; print}' "$cur_routes" >"$cur_cmp"
        fi
        if diff -u "$BASE_UTUNS" "$cur_utuns" >/dev/null 2>&1 &&
            diff -u "$base_cmp" "$cur_cmp" >/dev/null 2>&1; then
            settled=1
            break
        fi
        sleep 0.25
        j=$((j + 1))
    done
    if [ "$settled" != "1" ]; then
        diff -u "$BASE_UTUNS" "$cur_utuns" >&2 || true
        diff -u "$base_cmp" "$cur_cmp" >&2 || true
        fail "utun interface or routes did not return to baseline after SIGTERM"
    fi
    if netstat -rn -f inet6 | awk '$1 ~ /^2001:db8:cafe::/ {found=1} END {exit !found}'; then
        fail "IPv6 bypass-cidrs route 2001:db8:cafe::/48 still present after SIGTERM"
    fi
}

start_rfor || fail "rfor utun failed to start"
pass "macOS utun local-traffic mode active"

# 1a. bypass-cidrs IPv4/IPv6 bypass routes and kernel-level bypass
ROUTE_BYPASS_HOST_IF=$(route -n get 1.0.0.1 2>/dev/null | awk '/interface:/ {print $2; exit}')
[ "$ROUTE_BYPASS_HOST_IF" = "$EGRESS_IF" ] || fail "expected bypassed host 1.0.0.1 via $EGRESS_IF, got '$ROUTE_BYPASS_HOST_IF'"
ROUTE_BYPASS_NET_IF=$(route -n get 30.0.0.1 2>/dev/null | awk '/interface:/ {print $2; exit}')
[ "$ROUTE_BYPASS_NET_IF" = "$EGRESS_IF" ] || fail "expected bypassed CIDR 30.0.0.0/8 via $EGRESS_IF, got '$ROUTE_BYPASS_NET_IF'"
BYPASS_HTTPS_CODE=$(curl -4 -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' https://1.0.0.1/) || BYPASS_HTTPS_CODE="000"
case "$BYPASS_HTTPS_CODE" in
    2*|3*) ;;
    *) fail "bypass-cidrs HTTPS to 1.0.0.1 returned $BYPASS_HTTPS_CODE" ;;
esac
if grep -q '1\.0\.0\.1:443' "$LOG"; then
    fail "bypassed host 1.0.0.1:443 unexpectedly entered rfor"
fi
if route -n get -inet6 default >/dev/null 2>&1; then
    V6_EGRESS_IF=$(route -n get -inet6 default 2>/dev/null | awk '/interface:/ {print $2; exit}')
    ROUTE_BYPASS_V6_IF=$(route -n get -inet6 2001:db8:cafe::1 2>/dev/null | awk '/interface:/ {print $2; exit}')
    [ "$ROUTE_BYPASS_V6_IF" = "$V6_EGRESS_IF" ] || fail "expected bypassed IPv6 CIDR 2001:db8:cafe::/48 via $V6_EGRESS_IF, got '$ROUTE_BYPASS_V6_IF'"
fi
pass "bypass-cidrs (v4/v6) bypassed utun cleanly ($BYPASS_HTTPS_CODE)"

# 1. Sequential & concurrent HTTPS to 1.1.1.1 -> Outbound(DIRECT)
TCP_LAT="$TMP/tcp.lat"
bench_tcp "$TCP_URL" "$TCP_SEQ_REQUESTS" "$TCP_LAT"
bench_stats "macOS local TCP sequential" "$BENCH_TCP_OK" "$TCP_SEQ_REQUESTS" "$TCP_LAT"
[ "$BENCH_TCP_OK" -eq "$TCP_SEQ_REQUESTS" ] || fail "local TCP succeeded $BENCH_TCP_OK/$TCP_SEQ_REQUESTS"
pass "macOS local TCP HTTPS ($BENCH_TCP_OK/$TCP_SEQ_REQUESTS)"

TCP_BURST_DIR="$TMP/tcp-burst"
bench_tcp_burst "$TCP_URL" "$TCP_BURST_REQUESTS" "$TCP_BURST_DIR"
bench_stats "macOS local TCP burst" "$BENCH_BURST_OK" "$TCP_BURST_REQUESTS" "$TCP_BURST_DIR/times"
[ "$BENCH_BURST_OK" -eq "$TCP_BURST_REQUESTS" ] || fail "local TCP burst succeeded $BENCH_BURST_OK/$TCP_BURST_REQUESTS"
pass "macOS local TCP burst ($BENCH_BURST_OK/$TCP_BURST_REQUESTS)"

# 2. HTTP Host and TLS SNI routing -> Outbound(PROXY)
HTTP_CODE=$(curl -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' -H 'Host: one.one.one.one' http://1.1.1.1/) || HTTP_CODE="000"
case "$HTTP_CODE" in
    2*|3*) ;;
    *) fail "HTTP Host sniffed request returned $HTTP_CODE" ;;
esac
grep -q 'one.one.one.one:80 (1.1.1.1:80) \[http\] -> Outbound(PROXY)' "$LOG" || fail "HTTP Host routing to PROXY not observed"
pass "HTTP Host sniffing routed through loopback SOCKS5 ($HTTP_CODE)"

TLS_CODE=$(curl -4 --resolve one.one.one.one:443:1.1.1.1 -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' https://one.one.one.one/) || TLS_CODE="000"
case "$TLS_CODE" in
    2*|3*) ;;
    *) fail "TLS SNI sniffed request returned $TLS_CODE" ;;
esac
grep -q 'one.one.one.one:443 (.*) \[tls\] -> Outbound(PROXY)' "$LOG" || fail "TLS SNI routing to PROXY not observed"
pass "TLS SNI sniffing routed through loopback SOCKS5 ($TLS_CODE)"

# 3. UDP DNS sequential & burst -> Outbound(DIRECT)
DNS_LAT="$TMP/dns.lat"
DNS_OK=$("$PYTHON_BIN" "$DNS_HELPER" bench "$DNS_SERVER" "$DNS_NAME" "$DNS_REQUESTS" "$DNS_LAT")
bench_stats "macOS local UDP DNS" "$DNS_OK" "$DNS_REQUESTS" "$DNS_LAT"
[ "$DNS_OK" -ge "$DNS_MIN_OK" ] || fail "local UDP DNS succeeded $DNS_OK/$DNS_REQUESTS"
pass "macOS local UDP DNS ($DNS_OK/$DNS_REQUESTS)"

DNS_BURST_LAT="$TMP/dns-burst.lat"
DNS_BURST_OK=$("$PYTHON_BIN" "$DNS_HELPER" burst "$DNS_SERVER" "$DNS_NAME" 4 "$DNS_BURST_LAT")
bench_stats "macOS local UDP DNS burst" "$DNS_BURST_OK" 4 "$DNS_BURST_LAT"
[ "$DNS_BURST_OK" -ge 3 ] || fail "local UDP DNS burst succeeded $DNS_BURST_OK/4"
pass "macOS local UDP DNS burst ($DNS_BURST_OK/4)"

# 4. DNS sniffing -> PROXY (SOCKS5 UDP ASSOCIATE) and DROP -> NXDOMAIN
"$PYTHON_BIN" "$DNS_HELPER" check "$DNS_SERVER" "one.one.one.one" 0 >/dev/null || fail "DNS query via SOCKS5 UDP ASSOCIATE failed"
grep -q 'one.one.one.one:53 (8.8.8.8:53) \[dns\] -> Outbound(PROXY)' "$LOG" || fail "DNS routing to PROXY not observed"
pass "DNS query sniffed and relayed via SOCKS5 UDP ASSOCIATE"

"$PYTHON_BIN" "$DNS_HELPER" check "$DNS_SERVER" "blocked.test" 3 >/dev/null || fail "dropped DNS query did not return NXDOMAIN"
grep -q 'blocked.test:53 (8.8.8.8:53) \[dns\] -> Outbound(DROP)' "$LOG" || fail "DNS routing to DROP not observed"
pass "DROP outbound answered blocked.test with NXDOMAIN"

# 4a. Route-aware ICMP handling (DIRECT forward, PROXY error, DROP error)
ping -n -c 2 -t 4 1.1.1.1 >/dev/null || fail "DIRECT ICMP ping to 1.1.1.1 failed"
grep -q 'icmp relay: .* -> 1\.1\.1\.1 -> Outbound(DIRECT)' "$LOG" || fail "DIRECT ICMP log missing"
pass "DIRECT ICMP Echo forwarded via physical egress interface"

PING_PROXY_OUT=$(ping -n -c 1 -t 2 203.0.113.10 2>&1 || true)
printf '%s\n' "$PING_PROXY_OUT" | grep -Eqi 'Protocol|198\.19\.254\.2' || fail "PROXY ICMP did not return Protocol Unreachable: $PING_PROXY_OUT"
grep -q 'icmp: .* -> 203\.0\.113\.10 -> Outbound(PROXY)' "$LOG" || fail "PROXY ICMP log missing"
pass "PROXY ICMP returned Protocol Unreachable without leaking direct traffic"

PING_DROP_OUT=$(ping -n -c 1 -t 2 203.0.113.20 2>&1 || true)
printf '%s\n' "$PING_DROP_OUT" | grep -qi 'prohibited' || fail "DROP ICMP did not return Administratively Prohibited: $PING_DROP_OUT"
grep -q 'icmp: .* -> 203\.0\.113\.20 -> Outbound(DROP)' "$LOG" || fail "DROP ICMP log missing"
pass "DROP ICMP returned Administratively Prohibited"

# 5. QUIC v1 & v2 SNI sniffing
if [ -n "$QUIC_SNI_PY" ] && "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
    "$PYTHON_BIN" "$QUIC_SNI_PY" 1.1.1.1 443 quic-v1.test v1
    "$PYTHON_BIN" "$QUIC_SNI_PY" 1.1.1.1 443 quic-v2.test v2
    sleep 0.5
    grep -q 'quic-v1.test:443 (1.1.1.1:443) \[quic-v1\] -> Outbound(PROXY)' "$LOG" || fail "QUIC v1 SNI routing not observed"
    grep -q 'quic-v2.test:443 (1.1.1.1:443) \[quic-v2\] -> Outbound(PROXY)' "$LOG" || fail "QUIC v2 SNI routing not observed"
    pass "QUIC v1 and QUIC v2 Initial SNI sniffing routed to PROXY"
else
    echo "INFO: skipping QUIC SNI packet crafter (python3 cryptography module unavailable)"
fi

# 6. Non-intercepted port direct bypass
NON_PORT_CODE=$(curl -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' https://cloudflare.com:8443/) || NON_PORT_CODE="000"
case "$NON_PORT_CODE" in
    2*|3*|4*) ;;
    *) fail "non-intercepted port 8443 bypass failed ($NON_PORT_CODE)" ;;
esac
if grep -q ':8443' "$LOG"; then
    fail "non-intercepted port 8443 unexpectedly entered RouteTable"
fi
pass "non-intercepted port 8443 bypassed RouteTable ($NON_PORT_CODE)"

# Confirm upstream SOCKS5 actually handled the proxied TCP + UDP flows
grep -q 'SOCKS5:.*-> one.one.one.one:443' "$UPSTREAM_LOG" || fail "upstream SOCKS5 log missing TCP flow"
grep -q 'SOCKS5:.*DGRAM.*-> 8.8.8.8:53' "$UPSTREAM_LOG" || fail "upstream SOCKS5 log missing UDP flow"
pass "upstream SOCKS5 observed both TCP and UDP flows"

# 7. Clean SIGTERM teardown
stop_and_verify_clean
pass "SIGTERM cleaned utun interface and restored routing table"

# 7a. Non-intercepted UDP port bypass and udp-enabled: false bypass (relay_udp_bypass)
UDP_BYPASS_CONF="$TMP/rfor-udp-port-bypass.yaml"
cat >"$UDP_BYPASS_CONF" <<'YAML'
debug: true
udp-enabled: true
udp-timeout: 15
traffic-intercept:
  mode: auto
  local-traffic: true
  ports: [80, 443]
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
YAML

start_rfor "$UDP_BYPASS_CONF" "rfor=debug" || fail "rfor utun failed to start for UDP port-bypass test"
for _ in 1 2 3; do
    "$PYTHON_BIN" "$DNS_HELPER" check "$DNS_SERVER" "$DNS_NAME" 0 >/dev/null || fail "non-intercepted UDP port 53 query failed"
done
grep -q 'udp bypass: create tunnel .*<-> 8\.8\.8\.8:53' "$LOG" || fail "expected udp bypass log for non-intercepted port 53"
if grep -q '8\.8\.8\.8:53.*Outbound(' "$LOG"; then
    fail "non-intercepted UDP port 53 unexpectedly entered RouteTable"
fi
stop_and_verify_clean
pass "non-intercepted UDP port 53 bypassed RouteTable via relay_udp_bypass"

UDP_DISABLED_CONF="$TMP/rfor-udp-disabled.yaml"
cat >"$UDP_DISABLED_CONF" <<'YAML'
debug: true
udp-enabled: false
udp-timeout: 15
traffic-intercept:
  mode: auto
  local-traffic: true
  ports: [80, 443, 53]
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
YAML

start_rfor "$UDP_DISABLED_CONF" "rfor=debug" || fail "rfor utun failed to start for udp-enabled=false test"
"$PYTHON_BIN" "$DNS_HELPER" check "$DNS_SERVER" "$DNS_NAME" 0 >/dev/null || fail "UDP query failed when udp-enabled=false"
grep -q 'udp bypass: create tunnel .*<-> 8\.8\.8\.8:53' "$LOG" || fail "expected udp bypass log when udp-enabled=false"
if grep -q '8\.8\.8\.8:53.*Outbound(' "$LOG"; then
    fail "UDP unexpectedly entered RouteTable when udp-enabled=false"
fi
stop_and_verify_clean
pass "udp-enabled: false relayed UDP via relay_udp_bypass"

# 8. Restart soak (repeated start -> live traffic -> SIGTERM -> baseline check)
cycle=0
while [ "$cycle" -lt "$SOAK_CYCLES" ]; do
    cycle=$((cycle + 1))
    start_rfor || fail "soak cycle $cycle: rfor utun did not come up"
    bench_tcp_ok "$TCP_URL" 3 || fail "soak cycle $cycle: HTTPS through utun failed"
    stop_and_verify_clean
    pass "soak cycle $cycle/$SOAK_CYCLES: started, served traffic, and cleaned up"
done

# 9. Offline startup -> low CPU -> automatic PF_ROUTE reconciliation, and live disconnect/reconnect recovery.
ORIG_EGRESS_IF=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')
ORIG_GW=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2; exit}')
[ -n "$ORIG_EGRESS_IF" ] && [ -n "$ORIG_GW" ] || fail "failed to capture baseline default route ($ORIG_EGRESS_IF / $ORIG_GW)"

OFFLINE_CONF="$TMP/rfor-offline.yaml"
cat >"$OFFLINE_CONF" <<YAML
debug: true
udp-enabled: true
udp-timeout: 15
traffic-intercept:
  mode: auto
  local-traffic: true
  egress-interface: "$ORIG_EGRESS_IF"
  ports: [80, 443, 53]
  bypass-cidrs:
    - "1.0.0.1/32"
outbounds:
  - name: DIRECT
  - name: PROXY
    url: socks5://127.0.0.1:11081
rules:
  - DEFAULT,,DIRECT
  - DOMAIN,one.one.one.one,PROXY
YAML

OFFLINE_AUTO_CONF="$TMP/rfor-offline-auto.yaml"
cat >"$OFFLINE_AUTO_CONF" <<'YAML'
debug: true
udp-enabled: true
udp-timeout: 15
traffic-intercept:
  mode: auto
  local-traffic: true
  ports: [80, 443, 53]
  bypass-cidrs:
    - "1.0.0.1/32"
outbounds:
  - name: DIRECT
  - name: PROXY
    url: socks5://127.0.0.1:11081
rules:
  - DEFAULT,,DIRECT
  - DOMAIN,one.one.one.one,PROXY
YAML

check_low_cpu() {
    local pid="$1"
    local phase="$2"
    local cpu_int
    cpu_int=$(ps -p "$pid" -o %cpu= 2>/dev/null | awk '{printf "%d", ($1 + 0.5)}')
    [ -n "$cpu_int" ] || fail "failed to read CPU% for rfor pid=$pid during $phase"
    [ "$cpu_int" -lt 25 ] || fail "rfor CPU too high during $phase (${cpu_int}%)"
}

start_offline_rfor() {
    local conf="$1"
    : >"$LOG"
    RUST_LOG="rfor=debug" "$RFOR_BIN" -c "$conf" -w "$TMP" >"$LOG" 2>&1 &
    PID=$!
    local j=0
    while [ "$j" -lt 32 ]; do
        kill -0 "$PID" 2>/dev/null || fail "rfor exited when started offline ($conf)"
        grep -q 'utun listen:' "$LOG" 2>/dev/null && return 0
        sleep 0.25
        j=$((j + 1))
    done
    fail "rfor did not start utun listener when offline ($conf)"
}

wait_for_routes_active() {
    local expect_gw="$1"
    local expect_if="$2"
    local k=0
    while [ "$k" -lt 32 ]; do
        local r_if scoped_gw
        r_if=$(route -n get 1.0.0.0 2>/dev/null | awk '/interface:/ {print $2; exit}' || true)
        scoped_gw=$(route -n get -ifscope "$expect_if" default 2>/dev/null | awk '/gateway:/ {print $2; exit}' || true)
        case "$r_if" in
            utun*)
                if [ "$scoped_gw" = "$expect_gw" ]; then
                    return 0
                fi
                ;;
        esac
        sleep 0.25
        k=$((k + 1))
    done
    return 1
}

wait_for_routes_withdrawn() {
    local k=0
    while [ "$k" -lt 20 ]; do
        local r_if
        r_if=$(route -n get 1.0.0.0 2>/dev/null | awk '/interface:/ {print $2; exit}' || true)
        case "$r_if" in
            utun*) ;;
            *) return 0 ;;
        esac
        sleep 0.25
        k=$((k + 1))
    done
    return 1
}

assert_no_unreachable_since() {
    local mark="$1"
    local label="$2"
    if tail -n +"$((mark + 1))" "$LOG" | grep -q 'Network is unreachable'; then
        fail "unexpected Network is unreachable after $label"
    fi
}

# 9a. Offline startup with egress-interface -> traffic probes + low CPU -> recover -> all protocols
route -n delete default >/dev/null || fail "failed to delete default route for offline startup test"
start_offline_rfor "$OFFLINE_CONF"

curl -4 -sS --noproxy '*' --max-time 2 -o /dev/null "$TCP_URL" >/dev/null 2>&1 || true
ping -n -c 1 -t 1 1.1.1.1 >/dev/null 2>&1 || true
sleep 2
kill -0 "$PID" 2>/dev/null || fail "rfor died while idle offline"
OFFLINE_IF=$(route -n get 1.0.0.0 2>/dev/null | awk '/interface:/ {print $2; exit}' || true)
case "$OFFLINE_IF" in
    utun*) fail "1.0.0.0 unexpectedly routed into $OFFLINE_IF while offline" ;;
esac
check_low_cpu "$PID" "offline idle (egress-interface)"
pass "offline startup (egress-interface) deferred split-default routes and stayed low-CPU"

route -n add default "$ORIG_GW" >/dev/null || fail "failed to restore default route $ORIG_GW"
wait_for_routes_active "$ORIG_GW" "$ORIG_EGRESS_IF" || fail "rfor did not reconcile routes after network recovery"
RECOVER_MARK=$(wc -l <"$LOG" | tr -d ' ')

RECOVER_BYPASS_IF=$(route -n get 1.0.0.1 2>/dev/null | awk '/interface:/ {print $2; exit}' || true)
[ "$RECOVER_BYPASS_IF" = "$ORIG_EGRESS_IF" ] || fail "expected recovered bypass route 1.0.0.1 via $ORIG_EGRESS_IF, got '$RECOVER_BYPASS_IF'"
RECOVER_CODE=$(curl -4 -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' "$TCP_URL") || RECOVER_CODE="000"
case "$RECOVER_CODE" in
    2*|3*) ;;
    *) fail "DIRECT HTTPS through utun failed after network recovery ($RECOVER_CODE)" ;;
esac
RECOVER_PROXY_CODE=$(curl -4 --resolve one.one.one.one:443:1.1.1.1 -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' https://one.one.one.one/) || RECOVER_PROXY_CODE="000"
case "$RECOVER_PROXY_CODE" in
    2*|3*) ;;
    *) fail "PROXY TLS SNI through utun failed after network recovery ($RECOVER_PROXY_CODE)" ;;
esac
"$PYTHON_BIN" "$DNS_HELPER" check "$DNS_SERVER" "$DNS_NAME" 0 >/dev/null || fail "DIRECT UDP DNS failed after network recovery"
RECOVER_PING_OUT=$(ping -n -c 2 -t 4 1.1.1.1 2>&1) || fail "DIRECT ICMP failed after network recovery: $RECOVER_PING_OUT"
assert_no_unreachable_since "$RECOVER_MARK" "offline recovery"
pass "network recovery installed bypass/scoped routes and restored DIRECT TCP/UDP/ICMP + PROXY TCP ($RECOVER_CODE/$RECOVER_PROXY_CODE)"

# 9b. Running online -> disconnect -> auto withdraw + low CPU -> reconnect -> auto recover
route -n delete default >/dev/null 2>&1 || true
route -n delete -inet -ifscope "$ORIG_EGRESS_IF" default "$ORIG_GW" >/dev/null 2>&1 || true
wait_for_routes_withdrawn || fail "rfor did not withdraw split-default routes after disconnect"
curl -4 -sS --noproxy '*' --max-time 2 -o /dev/null "$TCP_URL" >/dev/null 2>&1 || true
sleep 1.5
check_low_cpu "$PID" "post-disconnect idle"
pass "disconnect withdrew split-default routes and kept CPU low"

route -n add default "$ORIG_GW" >/dev/null || fail "failed to restore default route after disconnect"
wait_for_routes_active "$ORIG_GW" "$ORIG_EGRESS_IF" || fail "rfor did not re-install routes after reconnect"
RECONNECT_MARK=$(wc -l <"$LOG" | tr -d ' ')
RECOVER2_CODE=$(curl -4 -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' "$TCP_URL") || RECOVER2_CODE="000"
case "$RECOVER2_CODE" in
    2*|3*) ;;
    *) fail "HTTPS through utun failed after reconnect ($RECOVER2_CODE)" ;;
esac
RECONNECT_PING_OUT=$(ping -n -c 2 -t 4 1.1.1.1 2>&1) || fail "DIRECT ICMP failed after reconnect: $RECONNECT_PING_OUT"
assert_no_unreachable_since "$RECONNECT_MARK" "reconnect"
pass "reconnect restored routes, TCP, and ICMP cleanly ($RECOVER2_CODE)"

stop_and_verify_clean 1

# 9c. Offline startup WITHOUT egress-interface (mode: auto pure auto-detect) -> recover
route -n delete default >/dev/null || fail "failed to delete default route for auto-detect offline test"
start_offline_rfor "$OFFLINE_AUTO_CONF"

sleep 2
kill -0 "$PID" 2>/dev/null || fail "rfor (auto-detect) died while idle offline"
AUTO_OFFLINE_IF=$(route -n get 1.0.0.0 2>/dev/null | awk '/interface:/ {print $2; exit}' || true)
case "$AUTO_OFFLINE_IF" in
    utun*) fail "1.0.0.0 unexpectedly routed into $AUTO_OFFLINE_IF while offline (auto-detect)" ;;
esac
check_low_cpu "$PID" "offline idle (auto-detect)"
pass "offline startup (auto-detect) deferred split-default routes and stayed low-CPU"

route -n add default "$ORIG_GW" >/dev/null || fail "failed to restore default route for auto-detect recovery"
wait_for_routes_active "$ORIG_GW" "$ORIG_EGRESS_IF" || fail "rfor (auto-detect) did not reconcile routes after recovery"
AUTO_RECOVER_CODE=$(curl -4 -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' "$TCP_URL") || AUTO_RECOVER_CODE="000"
case "$AUTO_RECOVER_CODE" in
    2*|3*) ;;
    *) fail "HTTPS through utun failed after auto-detect recovery ($AUTO_RECOVER_CODE)" ;;
esac
pass "offline startup (auto-detect) recovered routes and HTTPS cleanly ($AUTO_RECOVER_CODE)"

stop_and_verify_clean 1
ORIG_GW=""
pass "offline-recovery lifecycle cleaned up to baseline"

echo "all macOS local-traffic integration tests passed"
