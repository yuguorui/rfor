#!/bin/sh
# Boot the FreeBSD qcow2 under QEMU, then run the local-traffic test.
set -eu

if [ ! -f /opt/lib.sh ]; then
    echo "FAIL: /opt/lib.sh is not mounted"
    exit 1
fi
. /opt/lib.sh
RFOR_SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
RFOR_SCP_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

IMAGE="${FREEBSD_IMAGE:-/image/freebsd.qcow2}"
KEY="${SSH_KEY:-/keys/id_ed25519}"
HOST=127.0.0.1
PORT=2223
SERIAL=/tmp/freebsd-serial.log
PIDFILE=/tmp/qemu.pid
EFI=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd

if [ ! -f "$IMAGE" ]; then
    echo "FAIL: FreeBSD image not found inside the container: $IMAGE"
    exit 1
fi
if [ ! -f /seed/user-data ] || [ ! -f /seed/meta-data ]; then
    echo "FAIL: cloud-init seed is not mounted at /seed"
    exit 1
fi
if [ ! -f "$EFI" ]; then
    echo "FAIL: aarch64 UEFI firmware not found: $EFI"
    exit 1
fi
KEY=$(rfor_materialize_key "$KEY")

genisoimage -quiet -output /tmp/seed.iso -volid cidata -joliet -rock /seed
qemu-system-aarch64 \
    -M virt \
    -cpu max \
    -accel tcg,thread=single \
    -m 2048 \
    -smp 2 \
    -drive file="$IMAGE",if=virtio,format=qcow2,snapshot=on \
    -cdrom /tmp/seed.iso \
    -netdev "user,id=n0,hostfwd=tcp:$HOST:$PORT-:22" \
    -device virtio-net-pci,netdev=n0,romfile= \
    -bios "$EFI" \
    -display none \
    -serial "file:$SERIAL" \
    -daemonize \
    -pidfile "$PIDFILE"

cleanup() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if ! rfor_wait_ssh root@"$HOST" "$PORT" "$KEY" 1800 /tmp/ssh.log; then
    echo "FAIL: FreeBSD guest did not become reachable over SSH"
    tail -30 /tmp/ssh.log 2>/dev/null || true
    tail -160 "$SERIAL" 2>/dev/null || true
    exit 1
fi
echo "PASS: FreeBSD guest is reachable over SSH"

if ! rfor_ssh root@"$HOST" "$PORT" "$KEY" 'ipfw list >/dev/null 2>&1'; then
    echo "--- loading ipfw in the guest ---"
    rfor_ssh root@"$HOST" "$PORT" "$KEY"         'nohup sh -c "kldload ipfw; ipfw add 65530 allow ip from any to any" >/tmp/ipfw.log 2>&1 &'         >/dev/null 2>&1 || true
    sleep 2
    if ! rfor_wait_ssh root@"$HOST" "$PORT" "$KEY" 120 /tmp/ssh-after-ipfw.log; then
        echo "FAIL: SSH did not recover after loading ipfw"
        rfor_ssh root@"$HOST" "$PORT" "$KEY" 'cat /tmp/ipfw.log' 2>/dev/null || true
        tail -80 "$SERIAL" 2>/dev/null || true
        exit 1
    fi
fi

if ! rfor_ssh root@"$HOST" "$PORT" "$KEY" 'pkg install -y curl bind-tools' >/tmp/pkg.log 2>&1; then
    echo "FAIL: could not install curl/bind-tools in the guest"
    tail -80 /tmp/pkg.log 2>/dev/null || true
    exit 1
fi

rfor_copy_test_assets root@"$HOST" "$PORT" "$KEY" /test/rfor /test/local-traffic.sh
rfor_scp_to root@"$HOST" "$PORT" "$KEY" /test/request-bench.sh /tmp/request-bench.sh

set +e
rfor_ssh root@"$HOST" "$PORT" "$KEY" \
    'RFOR_BIN=/tmp/rfor-local-traffic.bin RFOR_ALLOW_IPFW_TEST=1 sh /tmp/local-traffic.sh'
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
    echo "FAIL: in-VM test exited $RC"
    tail -160 "$SERIAL" 2>/dev/null || true
fi

rfor_shutdown_guest root@"$HOST" "$PORT" "$KEY" >/dev/null 2>&1 || true
exit "$RC"
