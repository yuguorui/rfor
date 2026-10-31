#!/bin/sh
# Build a fresh OpenBSD 8.0 qcow2 from the official install ISO.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
. "$REPO_ROOT/tests/openbsd/lib.sh"

DOCKER_IMAGE="${RFOR_OPENBSD_DOCKER_IMAGE:-rfor-openbsd-qemu-test}"

CACHE_ROOT=$(rfor_cache_root)
OPENBSD_IMAGE="${OPENBSD_IMAGE:-$CACHE_ROOT/rfor/openbsd-8.0.qcow2}"
mkdir -p "$(dirname "$OPENBSD_IMAGE")" "$CACHE_ROOT/rfor"
OPENBSD_IMAGE=$(rfor_abs_path "$OPENBSD_IMAGE")

# A disposable VM should not depend on the user's passphrase-protected
# personal key.  Generate a test-only key next to the cached image unless
# SSH_KEY is set explicitly.
SSH_KEY="${SSH_KEY:-$CACHE_ROOT/rfor/openbsd-test-key}"
SSH_PUBKEY="${SSH_PUBKEY:-$SSH_KEY.pub}"

if [ -f "$OPENBSD_IMAGE" ]; then
    echo "image already exists: $OPENBSD_IMAGE"
    exit 0
fi
if [ ! -f "$SSH_KEY" ]; then
    mkdir -p "$(dirname "$SSH_KEY")"
    ssh-keygen -q -t ed25519 -N '' -C rfor-openbsd-test -f "$SSH_KEY"
fi
if [ ! -f "$SSH_PUBKEY" ]; then
    echo "FAIL: SSH public key not found: $SSH_PUBKEY"
    exit 1
fi
if ! ssh-keygen -y -P '' -f "$SSH_KEY" >/dev/null 2>&1; then
    echo "FAIL: SSH_KEY must be an unencrypted key usable in the container"
    echo "      unset SSH_KEY to use $CACHE_ROOT/rfor/openbsd-test-key"
    exit 1
fi

CONF_DIR=$(mktemp -d "$CACHE_ROOT/rfor/install.XXXXXX")
trap 'rm -rf "$CONF_DIR"' EXIT INT TERM
cat >"$CONF_DIR/install.conf" <<EOF
System hostname = openbsd-qemu
Password for root = *************
Public ssh key for root account = $(cat "$SSH_PUBKEY")
Change the default console to com0 = yes
Which speed should com0 use = 115200
Which network interface = vio0
IPv4 address for vio0 = 192.168.51.254
Netmask for vio0 = 255.255.255.0
IPv6 address for vio0 = none
Default IPv4 route = 192.168.51.1
DNS domain name = lan
DNS nameservers = 192.168.51.2
Start sshd by default = yes
Allow root ssh login = prohibit-password
Do you expect to run the X Window System = no
Do you want to suspend on lid close = no
Do you want to use a disk partition = whole
Disk to install to = sd0
Use (W)hole disk or (E)dit the MBR = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a
Location of sets = cd0
Set name(s) = done
Continue without verification = yes
EOF

if ! docker info >/dev/null 2>&1; then
    echo "FAIL: Docker is not available"
    exit 1
fi
if [ "${RFOR_DOCKER_REBUILD:-0}" = "1" ] || \
   ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "--- building $DOCKER_IMAGE ---"
    docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"
fi

echo "--- building OpenBSD image from scratch (TCG may take several minutes) ---"
docker run --rm \
    -v "$(dirname "$OPENBSD_IMAGE"):/out" \
    -v "$CONF_DIR:/conf:ro" \
    -v "$SSH_KEY:/keys/id_ed25519:ro" \
    -v "$REPO_ROOT/tests/openbsd/lib.sh:/opt/lib.sh:ro" \
    -e "OPENBSD_IMAGE=/out/$(basename "$OPENBSD_IMAGE")" \
    -e SSH_KEY=/keys/id_ed25519 \
    "$DOCKER_IMAGE" build

if [ ! -f "$OPENBSD_IMAGE" ]; then
    echo "FAIL: image builder did not produce $OPENBSD_IMAGE"
    exit 1
fi
echo "built: $OPENBSD_IMAGE"
