#!/bin/sh
# Two-VM macOS forwarded-traffic integration test (PF route-to utun, local-traffic: false).
#
# Runs from the host against two booted tart VMs:
#   - gateway VM: runs rfor with `mode: utun` and `local-traffic: false`
#   - client VM: routes test destination IPs (1.1.1.1, 1.0.0.1, 8.8.8.8) via gateway VM
#
# Usage: forwarded-traffic.sh <ssh-key> <gw-target> <gw-ip> <client-target> <client-ip> <rfor-bin>
set -eu

if [ "$#" -lt 6 ]; then
    echo "Usage: $0 <ssh-key> <gw-target> <gw-ip> <client-target> <client-ip> <rfor-bin>" >&2
    exit 1
fi

SSH_KEY=$1
GW_TARGET=$2
GW_IP=$3
CLIENT_TARGET=$4
CLIENT_IP=$5
RFOR_BIN=$6

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$SCRIPT_DIR/../common/harness.sh"

QUIC_SNI_PY="$REPO_ROOT/tests/integration/quic_sni.py"
GW_LINK_IP="10.200.0.1"
CLIENT_LINK_IP="10.200.0.2"
HOST_TMP=$(mktemp -d /tmp/rfor-fwd-host.XXXXXX)
WIRE_READY="$HOST_TMP/wire.ready"
WIRE_LOG="$HOST_TMP/wire.log"
WIRE_PID=""

gw_ssh() {
    rfor_ssh "$GW_TARGET" 22 "$SSH_KEY" "$@"
}

client_ssh() {
    rfor_ssh "$CLIENT_TARGET" 22 "$SSH_KEY" "$@"
}

fail() {
    echo "FAIL: $*" >&2
    if [ -f "$WIRE_LOG" ]; then
        echo "--- utun wire log ---" >&2
        tail -60 "$WIRE_LOG" >&2 || true
    fi
    echo "--- gateway rfor log ---" >&2
    gw_ssh 'tail -120 /tmp/rfor-fwd-test/rfor.log 2>/dev/null || true' >&2 || true
    echo "--- gateway upstream log ---" >&2
    gw_ssh 'tail -60 /tmp/rfor-fwd-test/upstream.log 2>/dev/null || true' >&2 || true
    exit 1
}

pass() {
    echo "PASS: $*"
}

cleanup() {
    client_ssh 'sudo sh -c "
        for ip in 1.1.1.1 1.0.0.1 8.8.8.8; do
            route -n delete -host \$ip >/dev/null 2>&1 || true
        done
        rm -f /tmp/rfor-utun-wire.py
    "' >/dev/null 2>&1 || true

    gw_ssh 'sudo sh -c "
        if [ -f /tmp/rfor-fwd-test/rfor.pid ]; then
            kill -TERM \$(cat /tmp/rfor-fwd-test/rfor.pid) 2>/dev/null || true
            sleep 1
        fi
        if [ -f /tmp/rfor-fwd-test/upstream.pid ]; then
            kill -TERM \$(cat /tmp/rfor-fwd-test/upstream.pid) 2>/dev/null || true
        fi
        pfctl -a rfor/rforfwd -F all >/dev/null 2>&1 || true
        if [ -f /tmp/rfor-fwd-test/pf.conf.bak ]; then
            cp /tmp/rfor-fwd-test/pf.conf.bak /etc/pf.conf
            pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
        fi
        if [ -f /tmp/rfor-fwd-test/ip_forwarding.bak ]; then
            sysctl -w net.inet.ip.forwarding=\$(cat /tmp/rfor-fwd-test/ip_forwarding.bak) >/dev/null 2>&1 || true
        fi
        rm -rf /tmp/rfor-fwd-test /tmp/rfor-utun-wire.py
    "' >/dev/null 2>&1 || true

    if [ -n "$WIRE_PID" ] && kill -0 "$WIRE_PID" 2>/dev/null; then
        kill -TERM "$WIRE_PID" 2>/dev/null || true
        wait "$WIRE_PID" 2>/dev/null || true
    fi
    rm -rf "$HOST_TMP"
}
trap cleanup EXIT INT TERM

echo "=== Preparing forwarded-traffic assets on gateway ($GW_IP) and client ($CLIENT_IP) ==="
rfor_scp_to "$GW_TARGET" 22 "$SSH_KEY" "$RFOR_BIN" /tmp/rfor-fwd-bin
if [ -f "$QUIC_SNI_PY" ]; then
    rfor_scp_to "$CLIENT_TARGET" 22 "$SSH_KEY" "$QUIC_SNI_PY" /tmp/quic_sni.py
fi

gw_ssh 'chmod 755 /tmp/rfor-fwd-bin && sudo rm -rf /tmp/rfor-fwd-test && mkdir -p /tmp/rfor-fwd-test && sudo sh -c "
    cp /etc/pf.conf /tmp/rfor-fwd-test/pf.conf.bak
    sysctl -n net.inet.ip.forwarding > /tmp/rfor-fwd-test/ip_forwarding.bak
    if ! grep -q '\''anchor \"rfor/\*\"'\'' /etc/pf.conf; then
        printf \"\nanchor \\\"rfor/*\\\"\n\" >> /etc/pf.conf
    fi
    pfctl -f /etc/pf.conf
    sysctl -w net.inet.ip.forwarding=1
"'

# Start L3 utun link before rfor so rfor opens a distinct utun device and
# client transit packets reach the gateway bypassing vmnet L2 guest isolation.
echo "=== Starting point-to-point L3 utun wire ($GW_LINK_IP <-> $CLIENT_LINK_IP) ==="
python3 "$SCRIPT_DIR/utun-wire.py" --bridge \
    "$SSH_KEY" "$GW_TARGET" "$CLIENT_TARGET" "$GW_LINK_IP" "$CLIENT_LINK_IP" "$WIRE_READY" \
    >"$WIRE_LOG" 2>&1 &
WIRE_PID=$!

wire_i=0
while [ "$wire_i" -lt 80 ]; do
    if ! kill -0 "$WIRE_PID" 2>/dev/null; then
        cat "$WIRE_LOG" >&2 || true
        fail "utun wire bridge exited unexpectedly"
    fi
    if [ -s "$WIRE_READY" ]; then
        break
    fi
    sleep 0.25
    wire_i=$((wire_i + 1))
done
[ -s "$WIRE_READY" ] || {
    cat "$WIRE_LOG" >&2 || true
    fail "timed out waiting for L3 utun wire"
}
client_ssh "ping -c 1 -t 2 $GW_LINK_IP >/dev/null" || fail "client failed to ping gateway link IP $GW_LINK_IP"
pass "point-to-point L3 wire active ($(cat "$WIRE_READY"))"

gw_ssh 'cat >/tmp/rfor-fwd-test/upstream.yaml <<YAML
debug: true
socks5-listen: "127.0.0.1:11081"
udp-enabled: true
traffic-intercept:
  mode: manual
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
YAML
cat >/tmp/rfor-fwd-test/rfor-fwd.yaml <<YAML
debug: true
udp-enabled: true
udp-timeout: 30
drop-reply:
  dns: nxdomain
traffic-intercept:
  mode: utun
  local-traffic: false
  ports: [80, 443, 53]
  tproxy-proxy-chain: rfor-fwd
  bypass-cidrs:
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
  - DOMAIN,one.one.one.one,PROXY
  - DOMAIN,quic-v1.test,PROXY
  - DOMAIN,quic-v2.test,PROXY
  - DOMAIN,blocked.test,DROP
YAML'

gw_ssh 'sudo sh -c "
    nohup /tmp/rfor-fwd-bin -c /tmp/rfor-fwd-test/upstream.yaml -w /tmp/rfor-fwd-test >/tmp/rfor-fwd-test/upstream.log 2>&1 </dev/null &
    echo \$! >/tmp/rfor-fwd-test/upstream.pid
    i=0
    while [ \$i -lt 20 ]; do
        grep -q \"socks5 listen: 127.0.0.1:11081\" /tmp/rfor-fwd-test/upstream.log 2>/dev/null && break
        sleep 0.25
        i=\$((i + 1))
    done
    grep -q \"socks5 listen: 127.0.0.1:11081\" /tmp/rfor-fwd-test/upstream.log

    nohup /tmp/rfor-fwd-bin -c /tmp/rfor-fwd-test/rfor-fwd.yaml -w /tmp/rfor-fwd-test >/tmp/rfor-fwd-test/rfor.log 2>&1 </dev/null &
    echo \$! >/tmp/rfor-fwd-test/rfor.pid
    i=0
    while [ \$i -lt 30 ]; do
        grep -q \"utun listen:\" /tmp/rfor-fwd-test/rfor.log 2>/dev/null && break
        sleep 0.25
        i=\$((i + 1))
    done
    grep -q \"utun listen:\" /tmp/rfor-fwd-test/rfor.log
    pfctl -a rfor/rforfwd -sr | grep -q \"route-to\"
    pfctl -a rfor/rforfwd -t rfor_np4 -T show | grep -q '30\.0\.0\.0/8'
    pfctl -a rfor/rforfwd -t rfor_np6 -T show | grep -q '2001:db8:cafe::/48'
"' || fail "gateway forwarded-only rfor failed to initialize PF anchor"
pass "gateway forwarded-only utun + PF route-to anchor is active"

# Verify gateway's own host-local traffic is NOT intercepted
GW_LOCAL_CODE=$(gw_ssh "curl -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' https://1.1.1.1/") || GW_LOCAL_CODE="000"
case "$GW_LOCAL_CODE" in
    2*|3*) ;;
    *) fail "gateway host-local HTTPS returned $GW_LOCAL_CODE" ;;
esac
if gw_ssh "grep -Eq 'TPROXY:(${GW_IP}|${GW_LINK_IP}):' /tmp/rfor-fwd-test/rfor.log"; then
    fail "gateway host-local traffic was unexpectedly intercepted in local-traffic: false mode"
fi
pass "gateway host-local traffic bypassed interception ($GW_LOCAL_CODE)"

# Route client test destinations via gateway VM's L3 wire address
client_ssh "sudo sh -c '
    for ip in 1.1.1.1 1.0.0.1 8.8.8.8; do
        route -n delete -host \$ip >/dev/null 2>&1 || true
        route -n add -host \$ip $GW_LINK_IP >/dev/null
    done
'" || fail "failed to add client host routes via $GW_LINK_IP"
pass "client VM routed 1.1.1.1, 1.0.0.1, 8.8.8.8 through gateway $GW_LINK_IP ($GW_IP)"

# Client TCP HTTPS -> DIRECT
C_TCP_CODE=$(client_ssh "curl -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' https://1.1.1.1/") || C_TCP_CODE="000"
case "$C_TCP_CODE" in
    2*|3*) ;;
    *) fail "forwarded client HTTPS to 1.1.1.1 returned $C_TCP_CODE" ;;
esac
gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:STREAM -> 1.1.1.1:443 -> Outbound(DIRECT)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded TCP DIRECT"
pass "forwarded TCP HTTPS routed via DIRECT ($C_TCP_CODE)"

# Client HTTP Host -> PROXY
C_HTTP_CODE=$(client_ssh "curl -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' -H 'Host: one.one.one.one' http://1.1.1.1/") || C_HTTP_CODE="000"
case "$C_HTTP_CODE" in
    2*|3*) ;;
    *) fail "forwarded client HTTP Host request returned $C_HTTP_CODE" ;;
esac
gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:STREAM -> one.one.one.one:80 (1.1.1.1:80) \[http\] -> Outbound(PROXY)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded HTTP PROXY"
pass "forwarded HTTP Host sniffed and routed via PROXY ($C_HTTP_CODE)"

# Client TLS SNI -> PROXY
C_TLS_CODE=$(client_ssh "curl -4 -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' https://one.one.one.one/") || C_TLS_CODE="000"
case "$C_TLS_CODE" in
    2*|3*) ;;
    *) fail "forwarded client TLS SNI request returned $C_TLS_CODE" ;;
esac
gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:STREAM -> one.one.one.one:443 (.*) \[tls\] -> Outbound(PROXY)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded TLS PROXY"
pass "forwarded TLS SNI sniffed and routed via PROXY ($C_TLS_CODE)"

# Client UDP DNS -> DIRECT, PROXY, DROP(NXDOMAIN)
CLIENT_PY=$(client_ssh 'for c in /opt/homebrew/bin/python3 /usr/local/bin/python3 $(command -v python3 2>/dev/null); do if [ -x "$c" ] && "$c" -c "import socket, struct" >/dev/null 2>&1; then echo "$c"; break; fi; done')
[ -n "$CLIENT_PY" ] || fail "working python3 not found on client VM"

client_ssh "$CLIENT_PY - 8.8.8.8" <<'PY' || fail "forwarded client UDP DNS tests failed"
import socket
import struct
import sys

server = sys.argv[1]

def query(name):
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split("."))
    pkt = struct.pack("!HHHHHH", 0x5151, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4.0)
    try:
        s.sendto(pkt, (server, 53))
        resp, _ = s.recvfrom(4096)
    finally:
        s.close()
    _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", resp[:12])
    return flags & 0x0F, ancount

rcode, ancount = query("example.com")
assert rcode == 0 and ancount >= 1, f"example.com failed: rcode={rcode}, ancount={ancount}"

rcode, ancount = query("one.one.one.one")
assert rcode == 0 and ancount >= 1, f"one.one.one.one failed: rcode={rcode}, ancount={ancount}"

rcode, ancount = query("blocked.test")
assert rcode == 3, f"blocked.test expected NXDOMAIN (3), got {rcode}"
PY

gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:DGRAM -> example.com:53 (8.8.8.8:53) \[dns\] -> Outbound(DIRECT)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded UDP DNS DIRECT"
gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:DGRAM -> one.one.one.one:53 (8.8.8.8:53) \[dns\] -> Outbound(PROXY)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded UDP DNS PROXY"
gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:DGRAM -> blocked.test:53 (8.8.8.8:53) \[dns\] -> Outbound(DROP)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded UDP DNS DROP"
pass "forwarded UDP DNS DIRECT, SOCKS5 PROXY, and NXDOMAIN DROP all succeeded"

# Client QUIC v1/v2 SNI forwarded
if client_ssh "$CLIENT_PY -c 'import cryptography' >/dev/null 2>&1" && [ -f "$QUIC_SNI_PY" ]; then
    client_ssh "$CLIENT_PY /tmp/quic_sni.py 1.1.1.1 443 quic-v1.test v1 && $CLIENT_PY /tmp/quic_sni.py 1.1.1.1 443 quic-v2.test v2"
    sleep 0.5
    gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:DGRAM -> quic-v1.test:443 (1.1.1.1:443) \[quic-v1\] -> Outbound(PROXY)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded QUIC v1"
    gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:DGRAM -> quic-v2.test:443 (1.1.1.1:443) \[quic-v2\] -> Outbound(PROXY)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing forwarded QUIC v2"
    pass "forwarded QUIC v1 and v2 Initial SNI sniffing succeeded"
fi

# Stop gateway rfor with SIGTERM and verify PF anchor + utun cleanup
BEFORE_UTUN=$(gw_ssh "grep 'utun listen:' /tmp/rfor-fwd-test/rfor.log | tr ' ' '\n' | grep -E '^utun[0-9]+$' | head -n 1")
gw_ssh 'sudo sh -c "
    pid=\$(cat /tmp/rfor-fwd-test/rfor.pid)
    kill -TERM \$pid
    i=0
    while [ \$i -lt 20 ]; do
        kill -0 \$pid 2>/dev/null || break
        sleep 0.25
        i=\$((i + 1))
    done
    if kill -0 \$pid 2>/dev/null; then
        echo \"rfor did not exit on SIGTERM\" >&2
        exit 1
    fi
"' || fail "gateway rfor did not exit cleanly on SIGTERM"

ANCHOR_RULES=$(gw_ssh "sudo pfctl -a rfor/rforfwd -sr 2>/dev/null || true")
[ -z "$ANCHOR_RULES" ] || fail "PF anchor rfor/rforfwd still had rules after SIGTERM: $ANCHOR_RULES"
if [ -n "$BEFORE_UTUN" ] && gw_ssh "ifconfig $BEFORE_UTUN >/dev/null 2>&1"; then
    fail "utun interface $BEFORE_UTUN still existed after SIGTERM"
fi
pass "SIGTERM flushed PF anchor, released reference token, and destroyed $BEFORE_UTUN"

echo "all macOS forwarded-traffic integration tests passed"
