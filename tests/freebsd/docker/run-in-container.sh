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
PREPARE="${PREPARE:-0}"
SNAPSHOT=",snapshot=on"
if [ "$PREPARE" = "1" ]; then
    SNAPSHOT=""
fi
HOST=127.0.0.1
PORT=2223
SERIAL=/tmp/freebsd-serial.log
PIDFILE=/tmp/qemu.pid
EFI=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd

if [ ! -f "$IMAGE" ]; then
    echo "FAIL: FreeBSD image not found inside the container: $IMAGE"
    exit 1
fi
if [ "$PREPARE" = "1" ] && { [ ! -f /seed/user-data ] || [ ! -f /seed/meta-data ]; }; then
    echo "FAIL: cloud-init seed is not mounted at /seed"
    exit 1
fi
if [ ! -f "$EFI" ]; then
    echo "FAIL: aarch64 UEFI firmware not found: $EFI"
    exit 1
fi
KEY=$(rfor_materialize_key "$KEY")

CDROM_ARGS=""
if [ "$PREPARE" = "1" ]; then
    genisoimage -quiet -output /tmp/seed.iso -volid cidata -joliet -rock /seed
    CDROM_ARGS="-cdrom /tmp/seed.iso"
fi
qemu-system-aarch64 \
    -M virt \
    -cpu max \
    -accel tcg,thread=single \
    -m 2048 \
    -smp 2 \
    -drive file="$IMAGE",if=virtio,format=qcow2$SNAPSHOT \
    $CDROM_ARGS \
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

if [ "$PREPARE" = "0" ]; then
    # Cloud-init runs exactly once while building the prepared overlay.
    # Test boots must not carry a seed and must not enable it again.
    if ! rfor_ssh root@"$HOST" "$PORT" "$KEY"         'test "$(sysrc -n cloudinit_enable 2>/dev/null)" = NO'; then
        echo "FAIL: prepared image still enables cloud-init; rebuild it with tests/freebsd/docker/build-image.sh"
        exit 1
    fi
    echo "PASS: cloud-init is disabled in the prepared image"
fi

if [ "$PREPARE" = "1" ]; then
    if ! rfor_ssh root@"$HOST" "$PORT" "$KEY" 'pkg install -y curl bind-tools' >/tmp/pkg.log 2>&1; then
        echo "FAIL: could not install curl/bind-tools during image preparation"
        tail -80 /tmp/pkg.log 2>/dev/null || true
        exit 1
    fi
    if ! rfor_ssh root@"$HOST" "$PORT" "$KEY"         'sysrc firewall_enable=YES; sysrc firewall_type=open; sysrc cloudinit_enable=NO 2>/dev/null || true; for svc in cloudinit cloud-init; do if service -l 2>/dev/null | grep -qx "$svc"; then sysrc "${svc}_enable=NO"; fi; done; command -v curl; command -v dig; sysrc -n firewall_enable; sysrc -n firewall_type'         >/tmp/prepare.log 2>&1; then
        echo "FAIL: could not prepare the FreeBSD image"
        cat /tmp/prepare.log 2>/dev/null || true
        exit 1
    fi
    cat /tmp/prepare.log 2>/dev/null || true
    rfor_shutdown_guest root@"$HOST" "$PORT" "$KEY" >/dev/null 2>&1 || true
    # Wait for the guest to sync and QEMU to exit before the container cleanup
    # kills QEMU. Otherwise the writable prepared image can be left dirty.
    if [ -f "$PIDFILE" ]; then
        i=0
        while [ "$i" -lt 180 ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; do
            sleep 1
            i=$((i + 1))
        done
    fi
    exit 0
fi

if ! rfor_ssh root@"$HOST" "$PORT" "$KEY" 'command -v curl >/dev/null 2>&1 && command -v dig >/dev/null 2>&1'; then
    if ! rfor_ssh root@"$HOST" "$PORT" "$KEY" 'pkg install -y curl bind-tools' >/tmp/pkg.log 2>&1; then
        echo "FAIL: could not install curl/bind-tools in the guest"
        tail -80 /tmp/pkg.log 2>/dev/null || true
        exit 1
    fi
fi

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

rfor_copy_test_assets root@"$HOST" "$PORT" "$KEY" /test/rfor /test/local-traffic.sh
rfor_scp_to root@"$HOST" "$PORT" "$KEY" /test/request-bench.sh /tmp/request-bench.sh
rfor_scp_to root@"$HOST" "$PORT" "$KEY" /test/restart-soak.sh /tmp/restart-soak.sh

set +e
rfor_ssh root@"$HOST" "$PORT" "$KEY" \
    'RFOR_BIN=/tmp/rfor-local-traffic.bin RFOR_ALLOW_IPFW_TEST=1 sh /tmp/local-traffic.sh'
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
    set +e
    rfor_ssh root@"$HOST" "$PORT" "$KEY" 'RFOR_BIN=/tmp/rfor-local-traffic.bin RFOR_ALLOW_IPFW_TEST=1 sh /tmp/restart-soak.sh'
    RESTART_RC=$?
    set -e
    if [ "$RESTART_RC" -ne 0 ]; then
        echo "FAIL: restart soak exited $RESTART_RC"
        tail -160 "$SERIAL" 2>/dev/null || true
        RC=$RESTART_RC
    fi
else
    echo "FAIL: in-VM test exited $RC"
    tail -160 "$SERIAL" 2>/dev/null || true
fi

rfor_shutdown_guest root@"$HOST" "$PORT" "$KEY" >/dev/null 2>&1 || true
exit "$RC"
