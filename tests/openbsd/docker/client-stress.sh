#!/bin/sh
set -eu
. /opt/lib.sh
RFOR_SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
RFOR_SCP_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
IMAGE=/image/openbsd.qcow2
KEY=$(rfor_materialize_key /keys/id_ed25519)
RFOR=/opt/rfor
GW_PORT=2222
CL_PORT=2224
LANPORT=2345
GWPID=/tmp/gw.pid
CLPID=/tmp/cl.pid
GWLOG=/tmp/gw-rfor.log
GWSER=/tmp/gw-serial.log
CLSER=/tmp/cl-serial.log
STRESS_COUNT=${RFOR_CLIENT_STRESS_COUNT:-64}
cleanup() {
  set +e
  [ -f "$GWPID" ] && kill "$(cat "$GWPID")" 2>/dev/null
  [ -f "$CLPID" ] && kill "$(cat "$CLPID")" 2>/dev/null
  rfor_ssh root@127.0.0.1 "$GW_PORT" "$KEY" 'kill $(cat /tmp/rfor-client-stress.pid 2>/dev/null) 2>/dev/null || true' >/dev/null 2>&1
  rfor_ssh root@127.0.0.1 "$GW_PORT" "$KEY" 'cp -p /tmp/pf.client-stress /etc/pf.conf 2>/dev/null; pfctl -f /etc/pf.conf 2>/dev/null || true' >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

qemu-system-x86_64 -M pc -accel tcg,thread=single -m 1024 -smp 2 \
  -drive file="$IMAGE",if=virtio,format=qcow2,snapshot=on \
  -netdev user,id=n0,net=192.168.51.0/24,host=192.168.51.1,hostfwd=tcp:127.0.0.1:$GW_PORT-192.168.51.254:22 \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56 \
  -netdev socket,id=n1,listen=:$LANPORT \
  -device virtio-net-pci,netdev=n1,mac=52:54:00:12:34:57 \
  -display none -serial file:"$GWSER" -daemonize -pidfile "$GWPID"
qemu-system-x86_64 -M pc -accel tcg,thread=single -m 512 -smp 1 \
  -drive file="$IMAGE",if=virtio,format=qcow2,snapshot=on \
  -netdev user,id=c0,net=192.168.51.0/24,host=192.168.51.1,hostfwd=tcp:127.0.0.1:$CL_PORT-192.168.51.254:22 \
  -device virtio-net-pci,netdev=c0,mac=52:54:00:12:34:59 \
  -netdev socket,id=c1,connect=127.0.0.1:$LANPORT \
  -device virtio-net-pci,netdev=c1,mac=52:54:00:12:34:58 \
  -display none -serial file:"$CLSER" -daemonize -pidfile "$CLPID"

if ! rfor_wait_ssh root@127.0.0.1 "$GW_PORT" "$KEY" 300 /tmp/gw-ssh.log; then echo "FAIL: gateway ssh"; tail -80 "$GWSER"; exit 1; fi
echo "PASS: gateway ssh"
if ! rfor_wait_ssh root@127.0.0.1 "$CL_PORT" "$KEY" 300 /tmp/cl-ssh.log; then echo "FAIL: client ssh"; tail -80 "$CLSER"; exit 1; fi
echo "PASS: client ssh"

rfor_ssh root@127.0.0.1 "$GW_PORT" "$KEY" 'ifconfig vio1 inet 10.55.0.1/24 up; sysctl net.inet.ip.forwarding=1 >/dev/null; echo gateway-vio1-ok'
rfor_ssh root@127.0.0.1 "$CL_PORT" "$KEY" 'ifconfig vio1 inet 10.55.0.2/24 up; route delete 223.5.5.5 >/dev/null 2>&1 || true; route add 223.5.5.5 10.55.0.1; route -n get 223.5.5.5 | head -6; echo client-route-ok'

rfor_scp_to root@127.0.0.1 "$GW_PORT" "$KEY" "$RFOR" /tmp/rfor-client-stress
cat >/tmp/rfor-client-stress.yaml <<'YAML'
debug: true
tproxy-listen: 127.0.0.1:15080
socks5-listen: 127.0.0.1:11080
udp-enabled: true
udp-fullcone: false
traffic-intercept:
  mode: pf
  local-traffic: false
  ports: [53]
  tproxy-proxy-chain: rfor-client-test
outbounds:
  - name: DIRECT
rules:
  - DEFAULT,,DIRECT
YAML
rfor_scp_to root@127.0.0.1 "$GW_PORT" "$KEY" /tmp/rfor-client-stress.yaml /tmp/rfor-client-stress.yaml
rfor_ssh root@127.0.0.1 "$GW_PORT" "$KEY" 'cp -p /etc/pf.conf /tmp/pf.client-stress; grep -q "^pass out on vio1" /etc/pf.conf || printf "\npass in on vio1\npass out on vio1\n" >> /etc/pf.conf; pfctl -nf /etc/pf.conf; pfctl -f /etc/pf.conf; nohup /tmp/rfor-client-stress -c /tmp/rfor-client-stress.yaml -w /tmp >/tmp/gw-rfor.log 2>&1 & echo $! >/tmp/rfor-client-stress.pid; sleep 2; pfctl -s Anchors; grep -c "create tunnel" /tmp/gw-rfor.log || true'

rfor_ssh root@127.0.0.1 "$CL_PORT" "$KEY" "seq 1 $STRESS_COUNT | xargs -P $STRESS_COUNT -I{} dig @223.5.5.5 q{}.example.com +time=1 +tries=1 >/dev/null 2>&1 || true"
sleep 2
rfor_ssh root@127.0.0.1 "$GW_PORT" "$KEY" 'echo "--- rfor log ---"; grep -c "create tunnel" /tmp/gw-rfor.log 2>/dev/null || true; ERRORS=$(grep -c "Address already in use" /tmp/gw-rfor.log 2>/dev/null || true); echo "bind_errors=$ERRORS"; grep "Address already in use" /tmp/gw-rfor.log 2>/dev/null | tail -5 || true; echo "--- pf ---"; pfctl -a rfor/15080_rforclienttest -ss 2>/dev/null | grep -c "223.5.5.5:53" || true'
