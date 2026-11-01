#!/bin/sh
# Prepare a FreeBSD cloud image once so tests do not rerun cloud-init.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
. "$REPO_ROOT/tests/common/harness.sh"

DOCKER_IMAGE="${RFOR_FREEBSD_DOCKER_IMAGE:-rfor-freebsd-qemu-test}"
CACHE_ROOT=$(rfor_cache_root)
OFFICIAL="${FREEBSD_BASE_IMAGE:-$CACHE_ROOT/rfor/freebsd-15.1/FreeBSD-15.1.qcow2}"
PREPARED="${FREEBSD_IMAGE:-$CACHE_ROOT/rfor/freebsd-15.1/FreeBSD-15.1-prepared.qcow2}"
SSH_KEY="${SSH_KEY:-$CACHE_ROOT/rfor/freebsd-test-key}"
BASE_NAME=$(basename "$OFFICIAL")
PARTIAL="$PREPARED.partial"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

if [ -f "$PREPARED" ]; then
    echo "prepared image already exists: $PREPARED"
    exit 0
fi
if [ ! -f "$OFFICIAL" ]; then
    fail "official FreeBSD image not found: $OFFICIAL"
fi
if ! command -v qemu-img >/dev/null 2>&1; then
    fail "qemu-img is required to create the prepared overlay"
fi
if [ ! -f "$SSH_KEY" ]; then
    mkdir -p "$(dirname "$SSH_KEY")"
    ssh-keygen -q -t ed25519 -N '' -C rfor-freebsd-test -f "$SSH_KEY"
fi
if ! ssh-keygen -y -P '' -f "$SSH_KEY" >/dev/null 2>&1; then
    fail "SSH_KEY is not usable non-interactively: $SSH_KEY"
fi

mkdir -p "$(dirname "$PREPARED")"
rm -f "$PARTIAL"
( cd "$(dirname "$PREPARED")" && qemu-img create -f qcow2 -b "$BASE_NAME" -F qcow2 "$(basename "$PARTIAL")" >/dev/null )

CONF_DIR=$(mktemp -d "$CACHE_ROOT/rfor/freebsd-seed.XXXXXX")
trap 'rm -rf "$CONF_DIR"; rm -f "$PARTIAL"' EXIT INT TERM
PUB=$(cat "$SSH_KEY.pub")
cat >"$CONF_DIR/meta-data" <<EOF
instance-id: rfor-freebsd-prepared
local-hostname: freebsd-rfor
EOF
cat >"$CONF_DIR/user-data" <<EOF
#cloud-config
runcmd:
  - mkdir -p /root/.ssh
  - chmod 700 /root/.ssh
  - echo "$PUB" > /root/.ssh/authorized_keys
  - chmod 600 /root/.ssh/authorized_keys
  - sed -i '' -e 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' -e 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  - service sshd restart
EOF

if ! docker info >/dev/null 2>&1; then
    fail "Docker is not available"
fi
# Always invoke the build so COPY changes (run-in-container.sh) take effect.
# Docker layer caching makes this a no-op when nothing changed.
echo "--- building $DOCKER_IMAGE (cached unless inputs changed) ---"
docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"

echo "--- preparing FreeBSD image (first cloud-init may take several minutes) ---"
docker run --rm \
    -v "$PARTIAL:/image/freebsd.qcow2" \
    -v "$OFFICIAL:/image/$BASE_NAME:ro" \
    -v "$CONF_DIR:/seed:ro" \
    -v "$SSH_KEY:/keys/id_ed25519:ro" \
    -v "$REPO_ROOT/tests/common/harness.sh:/opt/lib.sh:ro" \
    -e PREPARE=1 \
    -e FREEBSD_IMAGE=/image/freebsd.qcow2 \
    -e SSH_KEY=/keys/id_ed25519 \
    "$DOCKER_IMAGE"

if [ ! -f "$PARTIAL" ]; then
    fail "image preparation did not produce $PARTIAL"
fi
mv "$PARTIAL" "$PREPARED"
echo "prepared image: $PREPARED"
