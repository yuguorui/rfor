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
GW_LINK_V6="fd00:200::1"
CLIENT_LINK_V6="fd00:200::2"
UDP_DIRECT_V4="203.0.113.50"
UDP_PROXY_V4="203.0.113.51"
UDP_DIRECT_V6="2001:db8:50::1"
UDP_PROXY_V6="2001:db8:51::1"
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
    echo "--- gateway udp_server log ---" >&2
    gw_ssh 'tail -60 /tmp/rfor-fwd-test/udp_server.log 2>/dev/null || true' >&2 || true
    echo "--- gateway pf anchor ---" >&2
    gw_ssh 'sudo pfctl -a rfor/rforfwd -sr 2>/dev/null || true' >&2 || true
    echo "--- gateway routes and lo0 ---" >&2
    gw_ssh 'netstat -rn -f inet | head -40; ifconfig lo0' >&2 || true
    exit 1
}

pass() {
    echo "PASS: $*"
}

cleanup() {
    client_ssh 'sudo sh -c "
        for ip in 1.1.1.1 1.0.0.1 8.8.8.8 203.0.113.50 203.0.113.51; do
            route -n delete -host \$ip >/dev/null 2>&1 || true
        done
        for ip6 in 2001:db8:50::1 2001:db8:51::1; do
            route -n delete -inet6 -host \$ip6 >/dev/null 2>&1 || true
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
        if [ -f /tmp/rfor-fwd-test/udp_server.pid ]; then
            kill -TERM \$(cat /tmp/rfor-fwd-test/udp_server.pid) 2>/dev/null || true
        fi
        pfctl -a rfor/rforfwd -F all >/dev/null 2>&1 || true
        if [ -f /tmp/rfor-fwd-test/pf.conf.bak ]; then
            cp /tmp/rfor-fwd-test/pf.conf.bak /etc/pf.conf
            pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
        fi
        if [ -f /tmp/rfor-fwd-test/ip_forwarding.bak ]; then
            sysctl -w net.inet.ip.forwarding=\$(cat /tmp/rfor-fwd-test/ip_forwarding.bak) >/dev/null 2>&1 || true
        fi
        if [ -f /tmp/rfor-fwd-test/ip6_forwarding.bak ]; then
            sysctl -w net.inet6.ip6.forwarding=\$(cat /tmp/rfor-fwd-test/ip6_forwarding.bak) >/dev/null 2>&1 || true
        fi
        for ip in 203.0.113.50 203.0.113.51; do
            ifconfig lo0 -alias \$ip >/dev/null 2>&1 || true
        done
        for ip6 in 2001:db8:50::1 2001:db8:51::1; do
            ifconfig lo0 inet6 \$ip6 delete >/dev/null 2>&1 || true
        done
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
    sysctl -n net.inet6.ip6.forwarding > /tmp/rfor-fwd-test/ip6_forwarding.bak
    if ! grep -q '\''anchor \"rfor/\*\"'\'' /etc/pf.conf; then
        printf \"\nanchor \\\"rfor/*\\\"\n\" >> /etc/pf.conf
    fi
    pfctl -f /etc/pf.conf
    sysctl -w net.inet.ip.forwarding=1
    sysctl -w net.inet6.ip6.forwarding=1
"'

# Start L3 utun link before rfor so rfor opens a distinct utun device and
# client transit packets reach the gateway bypassing vmnet L2 guest isolation.
echo "=== Starting point-to-point L3 utun wire ($GW_LINK_IP <-> $CLIENT_LINK_IP, $GW_LINK_V6 <-> $CLIENT_LINK_V6) ==="
python3 "$SCRIPT_DIR/utun-wire.py" --bridge \
    "$SSH_KEY" "$GW_TARGET" "$CLIENT_TARGET" "$GW_LINK_IP" "$CLIENT_LINK_IP" "$WIRE_READY" \
    "$GW_LINK_V6" "$CLIENT_LINK_V6" \
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
CLIENT_PY=$(client_ssh 'for c in /opt/homebrew/bin/python3 /usr/local/bin/python3 $(command -v python3 2>/dev/null); do if [ -x "$c" ] && "$c" -c "import socket, struct, subprocess" >/dev/null 2>&1; then echo "$c"; break; fi; done')
[ -n "$CLIENT_PY" ] || fail "working python3 not found on client VM"
GW_PY=$(gw_ssh 'for c in /opt/homebrew/bin/python3 /usr/local/bin/python3 $(command -v python3 2>/dev/null); do if [ -x "$c" ] && "$c" -c "import selectors, socket" >/dev/null 2>&1; then echo "$c"; break; fi; done')
[ -n "$GW_PY" ] || fail "working python3 not found on gateway VM"

client_ssh "ping -c 1 -t 2 $GW_LINK_IP >/dev/null" || fail "client failed to ping gateway link IP $GW_LINK_IP"
CL_UTUN=$(sed -n 's/.*cl=\([^ ]*\).*/\1/p' "$WIRE_READY")
[ -n "$CL_UTUN" ] || fail "failed to parse client utun interface from $(cat "$WIRE_READY")"
client_ssh "$CLIENT_PY -c 'import subprocess; subprocess.run([\"ping6\", \"-n\", \"-c\", \"1\", \"$GW_LINK_V6\"], check=True, timeout=4)' >/dev/null" || fail "client failed to ping gateway IPv6 link IP $GW_LINK_V6"
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
udp-fullcone: false
drop-reply:
  dns: nxdomain
traffic-intercept:
  mode: utun
  local-traffic: false
  ports: [80, 443, 53, 9001]
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
  - IP-CIDR,203.0.113.51/32,PROXY
  - IP-CIDR,2001:db8:51::1/128,PROXY
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

# Add loopback test aliases AFTER rfor-fwd loads <rfor_np4>/<rfor_np6> so PF
# still intercepts client transit packets to these addresses on gw_utun (!lo0),
# then start the dual-stack UDP echo + full-cone responder.
gw_ssh "cat >/tmp/rfor-fwd-test/udp_server.py <<'PY'
import selectors
import socket
import sys

BIND_PAIRS = [
    (socket.AF_INET, '$UDP_DIRECT_V4'),
    (socket.AF_INET, '$UDP_PROXY_V4'),
    (socket.AF_INET6, '$UDP_DIRECT_V6'),
    (socket.AF_INET6, '$UDP_PROXY_V6'),
]

sel = selectors.DefaultSelector()
sockets = {}

for family, ip in BIND_PAIRS:
    primary = socket.socket(family, socket.SOCK_DGRAM)
    secondary = socket.socket(family, socket.SOCK_DGRAM)
    primary.bind((ip, 9001))
    secondary.bind((ip, 9002))
    primary.setblocking(False)
    secondary.setblocking(False)
    sockets[(family, ip)] = (primary, secondary)
    sel.register(primary, selectors.EVENT_READ, data=(primary, secondary))

sys.stdout.write('READY\n')
sys.stdout.flush()

while True:
    for key, _ in sel.select():
        primary, secondary = key.data
        data, addr = primary.recvfrom(65536)
        if data.startswith(b'ECHO:'):
            primary.sendto(b'OK:' + data[5:], addr)
        elif data.startswith(b'CONE:'):
            secondary.sendto(b'CONE_OK:' + data[5:], addr)
PY
sudo sh -c '
    for ip in $UDP_DIRECT_V4 $UDP_PROXY_V4; do
        ifconfig lo0 alias \$ip netmask 255.255.255.255
    done
    for ip6 in $UDP_DIRECT_V6 $UDP_PROXY_V6; do
        ifconfig lo0 inet6 \$ip6 prefixlen 128 alias
    done
    nohup $GW_PY /tmp/rfor-fwd-test/udp_server.py >/tmp/rfor-fwd-test/udp_server.log 2>&1 </dev/null &
    echo \$! >/tmp/rfor-fwd-test/udp_server.pid
    i=0
    while [ \$i -lt 20 ]; do
        grep -q READY /tmp/rfor-fwd-test/udp_server.log 2>/dev/null && break
        sleep 0.25
        i=\$((i + 1))
    done
    grep -q READY /tmp/rfor-fwd-test/udp_server.log
'" || fail "failed to start gateway UDP echo/fullcone server"
pass "gateway dual-stack UDP echo and full-cone test server active"

# Verify gateway's own host-local traffic is NOT intercepted
GW_LOCAL_CODE="000"
for _attempt in 1 2; do
    GW_LOCAL_CODE=$(gw_ssh "curl -4 -sS --noproxy '*' --max-time 15 -o /dev/null -w '%{http_code}' https://1.1.1.1/") || GW_LOCAL_CODE="000"
    case "$GW_LOCAL_CODE" in
        2*|3*) break ;;
    esac
    [ "$_attempt" -lt 2 ] && sleep 1
done
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
    for ip in 1.1.1.1 1.0.0.1 8.8.8.8 $UDP_DIRECT_V4 $UDP_PROXY_V4; do
        route -n delete -host \$ip >/dev/null 2>&1 || true
        route -n add -host \$ip $GW_LINK_IP >/dev/null
    done
    for ip6 in $UDP_DIRECT_V6 $UDP_PROXY_V6; do
        route -n delete -inet6 -host \$ip6 >/dev/null 2>&1 || true
        route -n add -inet6 -host \$ip6 -interface $CL_UTUN >/dev/null
    done
'" || fail "failed to add client host routes via $GW_LINK_IP / $CL_UTUN"
pass "client VM routed test v4/v6 destinations through gateway $GW_LINK_IP ($CL_UTUN)"

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

# Client multi-packet near-MTU UDP streams (IPv4 & IPv6, DIRECT & SOCKS5 PROXY),
# IPv6 DNS DROP NXDOMAIN, and symmetric rejection (udp-fullcone: false).
client_ssh "$CLIENT_PY - $UDP_DIRECT_V4 $UDP_PROXY_V4 $UDP_DIRECT_V6 $UDP_PROXY_V6" <<'PY' || fail "forwarded multi-packet / IPv6 / symmetric UDP tests failed"
import socket
import struct
import sys

v4_direct, v4_proxy, v6_direct, v6_proxy = sys.argv[1:5]

def check_stream(family, dst_ip, dst_port, payload_size, count=20):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(4.0)
    try:
        for i in range(count):
            tag = f"{i:04d}:".encode("ascii")
            body = tag + bytes([(i + j) % 251 for j in range(payload_size - len(tag))])
            sock.sendto(b"ECHO:" + body, (dst_ip, dst_port))
            resp, addr = sock.recvfrom(65536)
            assert resp == b"OK:" + body, f"mismatch for {dst_ip} seq={i}: got len={len(resp)}"
            assert addr[0] == dst_ip and addr[1] == dst_port, f"unexpected src addr {addr}"
    finally:
        sock.close()

check_stream(socket.AF_INET, v4_direct, 9001, 1300)
check_stream(socket.AF_INET, v4_proxy, 9001, 1300)
check_stream(socket.AF_INET6, v6_direct, 9001, 1250)
check_stream(socket.AF_INET6, v6_proxy, 9001, 1250)

# IPv6 UDP DNS query -> DROP outbound -> NXDOMAIN reply
labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in "blocked.test".split("."))
dns_pkt = struct.pack("!HHHHHH", 0x6262, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)
dns_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
dns_sock.settimeout(3.0)
try:
    dns_sock.sendto(dns_pkt, (v6_direct, 53))
    dns_resp, _ = dns_sock.recvfrom(4096)
finally:
    dns_sock.close()
qid, flags, _, _, _, _ = struct.unpack("!HHHHHH", dns_resp[:12])
assert qid == 0x6262 and (flags & 0x0F) == 3, f"expected NXDOMAIN over IPv6, got qid={qid:#x} flags={flags:#x}"

# With udp-fullcone: false, replies from alternate port 9002 must be dropped.
for family, dst_ip, label in [
    (socket.AF_INET, v4_direct, b"CONE:sym4"),
    (socket.AF_INET, v4_proxy, b"CONE:sym4proxy"),
    (socket.AF_INET6, v6_direct, b"CONE:sym6"),
    (socket.AF_INET6, v6_proxy, b"CONE:sym6proxy"),
]:
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(1.2)
    try:
        s.sendto(label, (dst_ip, 9001))
        try:
            resp, addr = s.recvfrom(4096)
        except TimeoutError:
            pass
        else:
            raise AssertionError(f"expected symmetric drop from {dst_ip}:9002, got {resp!r} from {addr}")
    finally:
        s.close()
PY

gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:DGRAM -> ${UDP_DIRECT_V4}:9001 -> Outbound(DIRECT)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing IPv4 UDP DIRECT stream"
gw_ssh "grep -q 'TPROXY:${CLIENT_LINK_IP}:.*:DGRAM -> ${UDP_PROXY_V4}:9001 -> Outbound(PROXY)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing IPv4 UDP PROXY stream"
gw_ssh "grep -q 'DGRAM -> \[${UDP_DIRECT_V6}\]:9001 -> Outbound(DIRECT)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing IPv6 UDP DIRECT stream"
gw_ssh "grep -q 'DGRAM -> \[${UDP_PROXY_V6}\]:9001 -> Outbound(PROXY)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing IPv6 UDP PROXY stream"
gw_ssh "grep -q 'DGRAM -> blocked.test:53 (\[${UDP_DIRECT_V6}\]:53) \[dns\] -> Outbound(DROP)' /tmp/rfor-fwd-test/rfor.log" || fail "gateway log missing IPv6 UDP DNS DROP"
gw_ssh "grep -q 'SOCKS5:.*:DGRAM -> ${UDP_PROXY_V4}:9001' /tmp/rfor-fwd-test/upstream.log" || fail "upstream SOCKS5 log missing IPv4 UDP PROXY stream"
gw_ssh "grep -q 'SOCKS5:.*:DGRAM -> \[${UDP_PROXY_V6}\]:9001' /tmp/rfor-fwd-test/upstream.log" || fail "upstream SOCKS5 log missing IPv6 UDP PROXY stream"
pass "forwarded multi-packet IPv4/IPv6 UDP (DIRECT/PROXY), IPv6 NXDOMAIN, and symmetric rejection succeeded"

# Enable udp-fullcone: true via SIGHUP hot-reload and verify alternate-port replies pass.
gw_ssh 'sudo sh -c "
    sed -i \"\" \"s/udp-fullcone: false/udp-fullcone: true/\" /tmp/rfor-fwd-test/rfor-fwd.yaml
    kill -HUP \$(cat /tmp/rfor-fwd-test/rfor.pid)
    i=0
    while [ \$i -lt 20 ]; do
        grep -q \"Settings reloaded successfully.\" /tmp/rfor-fwd-test/rfor.log 2>/dev/null && break
        sleep 0.25
        i=\$((i + 1))
    done
    grep -q \"Settings reloaded successfully.\" /tmp/rfor-fwd-test/rfor.log
"' || fail "failed to hot-reload udp-fullcone: true via SIGHUP"

client_ssh "$CLIENT_PY - $UDP_DIRECT_V4 $UDP_PROXY_V4 $UDP_DIRECT_V6 $UDP_PROXY_V6" <<'PY' || fail "forwarded full-cone UDP test failed"
import socket
import sys

v4_direct, v4_proxy, v6_direct, v6_proxy = sys.argv[1:5]

for family, dst_ip, tag in [
    (socket.AF_INET, v4_direct, b"fc4"),
    (socket.AF_INET, v4_proxy, b"fc4proxy"),
    (socket.AF_INET6, v6_direct, b"fc6"),
    (socket.AF_INET6, v6_proxy, b"fc6proxy"),
]:
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(4.0)
    try:
        s.sendto(b"CONE:" + tag, (dst_ip, 9001))
        resp, addr = s.recvfrom(4096)
        assert resp == b"CONE_OK:" + tag, f"fullcone mismatch for {dst_ip}: got {resp!r}"
        assert addr[0] == dst_ip and addr[1] == 9002, f"expected peer {dst_ip}:9002, got {addr}"
    finally:
        s.close()
PY
pass "forwarded full-cone UDP (SIGHUP reload) delivered port-9002 replies over IPv4/IPv6 DIRECT and PROXY"

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
