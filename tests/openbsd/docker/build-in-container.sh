#!/bin/sh
# Build a fresh OpenBSD qcow2 from the official install ISO.
set -eu

if [ ! -f /opt/lib.sh ]; then
    echo "FAIL: /opt/lib.sh is not mounted"
    exit 1
fi
. /opt/lib.sh
RFOR_SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3"
RFOR_SCP_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3"

IMAGE="${OPENBSD_IMAGE:-/out/openbsd-8.0.qcow2}"
FINAL_IMAGE="$IMAGE"
IMAGE="$IMAGE.tmp"
BUILD_OK=0
ISO="${OPENBSD_ISO:-/opt/install80-serial.iso}"
CONF_DIR="${INSTALL_CONF_DIR:-/conf}"
KEY="${SSH_KEY:-/keys/id_ed25519}"
SERIAL=/tmp/serial.log
READY=/tmp/install.ready
HTTP_PID=""
PEXPECT_PID=""

if [ ! -f "$ISO" ]; then
    echo "FAIL: install ISO not found: $ISO"
    exit 1
fi
if [ ! -f "$CONF_DIR/install.conf" ]; then
    echo "FAIL: install.conf not found in $CONF_DIR"
    exit 1
fi
KEY=$(rfor_materialize_key "$KEY")

cleanup() {
    if [ -n "$PEXPECT_PID" ]; then
        kill "$PEXPECT_PID" 2>/dev/null || true
    fi
    if [ -n "$HTTP_PID" ]; then
        kill "$HTTP_PID" 2>/dev/null || true
    fi
    if [ "$BUILD_OK" != "1" ] && [ "${RFOR_KEEP_IMAGE:-0}" != "1" ]; then
        rm -f "$IMAGE" "$READY"
    fi
}
trap cleanup EXIT INT TERM

rm -f "$IMAGE" "$SERIAL" "$READY"
qemu-img create -f qcow2 "$IMAGE" 4G >/dev/null
( cd "$CONF_DIR" && exec python3 -m http.server 80 --bind 0.0.0.0 ) >/tmp/http.log 2>&1 &
HTTP_PID=$!

# Probe the file the installer fetches instead of sleeping for the server.
i=0
HTTP_OK=0
while [ "$i" -lt 50 ]; do
    if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1/install.conf", timeout=1)' 2>/dev/null; then
        HTTP_OK=1
        break
    fi
    if ! kill -0 "$HTTP_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
    i=$((i + 1))
done
if [ "$HTTP_OK" != "1" ]; then
    echo "FAIL: install.conf HTTP server did not come up"
    cat /tmp/http.log 2>/dev/null || true
    exit 1
fi

echo "--- installing OpenBSD 8.0 under QEMU TCG ---"
python3 /opt/install-pexpect.py "$IMAGE" "$ISO" "$SERIAL" "$READY" &
PEXPECT_PID=$!

# pexpect writes READY only after the installed guest reaches login:.  The
# loop is an event wait, not a guessed install duration.
i=0
READY_OK=0
while [ "$i" -lt 3600 ]; do
    if [ -f "$READY" ]; then
        READY_OK=1
        break
    fi
    if ! kill -0 "$PEXPECT_PID" 2>/dev/null; then
        break
    fi
    sleep 1
    i=$((i + 1))
done
if [ "$READY_OK" != "1" ]; then
    echo "FAIL: installer did not produce a ready guest"
    wait "$PEXPECT_PID" 2>/dev/null || true
    PEXPECT_PID=""
    tail -160 "$SERIAL" 2>/dev/null || true
    exit 1
fi

if ! rfor_wait_ssh root@127.0.0.1 2222 "$KEY" 30 /tmp/ssh.log; then
    echo "FAIL: installed guest did not accept SSH after the login prompt"
    tail -20 /tmp/ssh.log 2>/dev/null || true
    tail -160 "$SERIAL" 2>/dev/null || true
    exit 1
fi

cat >/tmp/pf.conf <<PF
set skip on lo
block return all
anchor "rfor/*"
pass all
PF
cat >/tmp/provision.sh <<'PROV'
set -eu
cp /tmp/pf.conf /etc/pf.conf
chmod 644 /etc/pf.conf
rcctl enable pf
pfctl -f /etc/pf.conf
pfctl -s info | grep -q "Status: Enabled"
pfctl -sr | grep -q 'anchor "rfor/\*"'
if [ ! -s /etc/installurl ]; then
    echo https://cdn.openbsd.org/pub/OpenBSD > /etc/installurl
fi
pkg_add -I curl
command -v curl
sync
PROV
rfor_scp_to root@127.0.0.1 2222 "$KEY" /tmp/pf.conf /tmp/pf.conf
rfor_scp_to root@127.0.0.1 2222 "$KEY" /tmp/provision.sh /tmp/provision.sh
if ! rfor_ssh root@127.0.0.1 2222 "$KEY" 'sh /tmp/provision.sh' >/tmp/provision.log 2>&1; then
    echo "FAIL: guest provisioning failed"
    cat /tmp/provision.log 2>/dev/null || true
    exit 1
fi

rfor_shutdown_guest root@127.0.0.1 2222 "$KEY" >/dev/null 2>&1 || true
wait "$PEXPECT_PID"
PEXPECT_PID=""
mv "$IMAGE" "$FINAL_IMAGE"
BUILD_OK=1
echo "built image: $FINAL_IMAGE"
