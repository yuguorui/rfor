#!/bin/sh
# Automated macOS VM end-to-end test runner using Cirrus Labs / OpenAI `tart`.
#
# Prepares a cached macOS template VM once (`rfor-macos-base`), clones
# disposable APFS COW VMs for isolated testing, builds `rfor` natively, and
# runs both:
#   1. tests/macos/local-traffic.sh      (local-traffic: true)
#   2. tests/macos/forwarded-traffic.sh  (two-VM local-traffic: false)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
. "$REPO_ROOT/tests/common/harness.sh"

cd "$REPO_ROOT"

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
    echo "FAIL: tart macOS VM tests require Apple Silicon macOS" >&2
    exit 1
fi

if ! command -v tart >/dev/null 2>&1; then
    echo "FAIL: tart not found; install with: brew install openai/tools/tart" >&2
    exit 1
fi

CACHE_DIR="$(rfor_cache_root)/rfor"
mkdir -p "$CACHE_DIR"

SSH_KEY="${RFOR_MACOS_KEY:-$CACHE_DIR/macos-test-key}"
if [ ! -f "$SSH_KEY" ]; then
    ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "rfor-macos-test" >/dev/null
    chmod 600 "$SSH_KEY"
fi
SSH_PUB_KEY="${SSH_KEY}.pub"

BASE_VM="${RFOR_MACOS_BASE_VM:-rfor-macos-base}"
BASE_READY="$CACHE_DIR/${BASE_VM}.ready"
IMAGE="${RFOR_MACOS_IMAGE:-ghcr.io/cirruslabs/macos-sequoia-base:latest}"
GUEST_USER="${RFOR_MACOS_USER:-admin}"
GUEST_PASS="${RFOR_MACOS_PASS:-admin}"
GW_VM="rfor-macos-gw-$$"
CLIENT_VM="rfor-macos-client-$$"

export RFOR_SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
export RFOR_SCP_OPTS="-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

GW_RUN_PID=""
CLIENT_RUN_PID=""
BASE_RUN_PID=""

stop_and_delete_vm() {
    _vm=$1
    tart stop "$_vm" >/dev/null 2>&1 || true
    tart delete "$_vm" >/dev/null 2>&1 || true
}

cleanup() {
    if [ -n "$CLIENT_RUN_PID" ] && kill -0 "$CLIENT_RUN_PID" 2>/dev/null; then
        tart stop "$CLIENT_VM" >/dev/null 2>&1 || true
        kill "$CLIENT_RUN_PID" >/dev/null 2>&1 || true
        wait "$CLIENT_RUN_PID" 2>/dev/null || true
    fi
    if [ -n "$GW_RUN_PID" ] && kill -0 "$GW_RUN_PID" 2>/dev/null; then
        tart stop "$GW_VM" >/dev/null 2>&1 || true
        kill "$GW_RUN_PID" >/dev/null 2>&1 || true
        wait "$GW_RUN_PID" 2>/dev/null || true
    fi
    if [ -n "$BASE_RUN_PID" ] && kill -0 "$BASE_RUN_PID" 2>/dev/null; then
        tart stop "$BASE_VM" >/dev/null 2>&1 || true
        kill "$BASE_RUN_PID" >/dev/null 2>&1 || true
        wait "$BASE_RUN_PID" 2>/dev/null || true
    fi
    tart delete "$CLIENT_VM" >/dev/null 2>&1 || true
    tart delete "$GW_VM" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_tart_ip() {
    _vm=$1
    _timeout=${2:-180}
    _i=0
    while [ "$_i" -lt "$_timeout" ]; do
        _ip=$(tart ip "$_vm" 2>/dev/null || true)
        if [ -n "$_ip" ]; then
            printf '%s\n' "$_ip"
            return 0
        fi
        sleep 2
        _i=$((_i + 2))
    done
    return 1
}

ssh_with_password_setup() {
    _ip=$1
    _pub_b64=$(base64 <"$SSH_PUB_KEY" | tr -d '\n')
    _exp=$(mktemp /tmp/rfor-expect.XXXXXX)
    cat >"$_exp" <<'EXP'
set timeout 120
set user [lindex $argv 0]
set host [lindex $argv 1]
set pass [lindex $argv 2]
set pub_b64 [lindex $argv 3]

spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no "$user@$host" \
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$pub_b64' | base64 -d >> ~/.ssh/authorized_keys && sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo '$pass' | sudo -S sh -c 'echo \"$user ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/$user && chmod 440 /etc/sudoers.d/$user'"
expect {
    "assword:" {
        send "$pass\r"
        exp_continue
    }
    eof {
        lassign [wait] pid spawnid os_error exit_code
        exit $exit_code
    }
}
EXP
    expect -f "$_exp" -- "$GUEST_USER" "$_ip" "$GUEST_PASS" "$_pub_b64"
    _rc=$?
    rm -f "$_exp"
    return $_rc
}

wait_ssh_port() {
    _ip=$1
    _timeout=${2:-180}
    _i=0
    while [ "$_i" -lt "$_timeout" ]; do
        if nc -z "$_ip" 22 >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        _i=$((_i + 2))
    done
    return 1
}

prepare_base_vm() {
    if tart list --quiet | grep -Fxq "$BASE_VM" && [ -f "$BASE_READY" ]; then
        echo "=== Reusing cached template VM: $BASE_VM ==="
        return 0
    fi

    if ! tart list --quiet | grep -Fxq "$BASE_VM"; then
        echo "=== Cloning template image $IMAGE -> $BASE_VM ==="
        tart clone "$IMAGE" "$BASE_VM"
    else
        echo "=== Finishing setup on existing template VM $BASE_VM ==="
        tart stop "$BASE_VM" >/dev/null 2>&1 || true
    fi

    echo "=== Booting $BASE_VM for one-time SSH and test dependency setup ==="
    tart run --no-graphics "$BASE_VM" >/tmp/rfor-tart-base.log 2>&1 &
    BASE_RUN_PID=$!

    _base_ip=$(wait_tart_ip "$BASE_VM" 240) || {
        echo "FAIL: timed out waiting for $BASE_VM IP" >&2
        cat /tmp/rfor-tart-base.log >&2 || true
        exit 1
    }
    wait_ssh_port "$_base_ip" 240 || {
        echo "FAIL: timed out waiting for SSH on $BASE_VM ($_base_ip)" >&2
        exit 1
    }

    ssh_with_password_setup "$_base_ip"

    # Install python cryptography if missing so QUIC SNI tests run end to end.
    rfor_ssh "$GUEST_USER@$_base_ip" 22 "$SSH_KEY" '
        set -e
        PY=$(command -v /opt/homebrew/bin/python3 || command -v /usr/local/bin/python3 || command -v python3 || true)
        if [ -z "$PY" ] || ! "$PY" -c "import socket, struct" >/dev/null 2>&1; then
            if command -v /opt/homebrew/bin/brew >/dev/null 2>&1; then
                /opt/homebrew/bin/brew install python
                PY=/opt/homebrew/bin/python3
            fi
        fi
        if [ -n "$PY" ] && ! "$PY" -c "import cryptography" >/dev/null 2>&1; then
            "$PY" -m pip install --break-system-packages cryptography >/dev/null 2>&1 || \
            "$PY" -m pip install cryptography >/dev/null 2>&1 || true
        fi
    '

    rfor_ssh "$GUEST_USER@$_base_ip" 22 "$SSH_KEY" 'sudo shutdown -h now' >/dev/null 2>&1 || true
    wait "$BASE_RUN_PID" >/dev/null 2>&1 || true
    BASE_RUN_PID=""
    touch "$BASE_READY"
    echo "=== Cached template VM $BASE_VM ready ==="
}

RFOR_BIN="${RFOR_BIN:-$REPO_ROOT/target/release/rfor}"
if [ "${RFOR_SKIP_BUILD:-0}" != "1" ]; then
    echo "=== Building release rfor binary ==="
    cargo build --release
fi
rfor_require_file "$RFOR_BIN" "rfor release binary"

prepare_base_vm

echo "=== Cloning disposable gateway VM ($GW_VM) ==="
tart clone "$BASE_VM" "$GW_VM"
tart run --no-graphics "$GW_VM" >/tmp/rfor-tart-gw.log 2>&1 &
GW_RUN_PID=$!

GW_IP=$(wait_tart_ip "$GW_VM" 180) || {
    echo "FAIL: timed out waiting for $GW_VM IP" >&2
    cat /tmp/rfor-tart-gw.log >&2 || true
    exit 1
}
rfor_wait_ssh "$GUEST_USER@$GW_IP" 22 "$SSH_KEY" 180 /tmp/rfor-tart-gw-ssh.log || {
    echo "FAIL: timed out waiting for SSH on $GW_VM ($GW_IP)" >&2
    cat /tmp/rfor-tart-gw-ssh.log >&2 || true
    exit 1
}
echo "=== Gateway VM ready at $GW_IP ==="

echo "=== Running macOS local-traffic E2E inside $GW_VM ==="
rfor_scp_to "$GUEST_USER@$GW_IP" 22 "$SSH_KEY" "$RFOR_BIN" /tmp/rfor-local-traffic.bin
rfor_scp_to "$GUEST_USER@$GW_IP" 22 "$SSH_KEY" "$REPO_ROOT/tests/macos/local-traffic.sh" /tmp/local-traffic.sh
rfor_scp_to "$GUEST_USER@$GW_IP" 22 "$SSH_KEY" "$REPO_ROOT/tests/common/request-bench.sh" /tmp/request-bench.sh
rfor_scp_to "$GUEST_USER@$GW_IP" 22 "$SSH_KEY" "$REPO_ROOT/tests/integration/quic_sni.py" /tmp/quic_sni.py
rfor_ssh "$GUEST_USER@$GW_IP" 22 "$SSH_KEY" 'chmod 755 /tmp/rfor-local-traffic.bin /tmp/local-traffic.sh'
rfor_ssh "$GUEST_USER@$GW_IP" 22 "$SSH_KEY" \
    'sudo RFOR_ALLOW_UTUN_TEST=1 RFOR_BIN=/tmp/rfor-local-traffic.bin QUIC_SNI_PY=/tmp/quic_sni.py sh /tmp/local-traffic.sh'

echo "=== Cloning disposable client VM ($CLIENT_VM) ==="
tart clone "$BASE_VM" "$CLIENT_VM"
tart run --no-graphics "$CLIENT_VM" >/tmp/rfor-tart-client.log 2>&1 &
CLIENT_RUN_PID=$!

CLIENT_IP=$(wait_tart_ip "$CLIENT_VM" 180) || {
    echo "FAIL: timed out waiting for $CLIENT_VM IP" >&2
    cat /tmp/rfor-tart-client.log >&2 || true
    exit 1
}
rfor_wait_ssh "$GUEST_USER@$CLIENT_IP" 22 "$SSH_KEY" 180 /tmp/rfor-tart-client-ssh.log || {
    echo "FAIL: timed out waiting for SSH on $CLIENT_VM ($CLIENT_IP)" >&2
    cat /tmp/rfor-tart-client-ssh.log >&2 || true
    exit 1
}
echo "=== Client VM ready at $CLIENT_IP ==="

echo "=== Running two-VM macOS forwarded-traffic E2E ==="
"$REPO_ROOT/tests/macos/forwarded-traffic.sh" \
    "$SSH_KEY" \
    "$GUEST_USER@$GW_IP" \
    "$GW_IP" \
    "$GUEST_USER@$CLIENT_IP" \
    "$CLIENT_IP" \
    "$RFOR_BIN"

echo "=== All macOS VM end-to-end tests passed ==="
