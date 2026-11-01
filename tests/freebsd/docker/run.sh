#!/bin/sh
# Build the FreeBSD test container on demand and run the local-traffic test.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
. "$REPO_ROOT/tests/common/harness.sh"

DOCKER_IMAGE="${RFOR_FREEBSD_DOCKER_IMAGE:-rfor-freebsd-qemu-test}"
CACHE_ROOT=$(rfor_cache_root)
FREEBSD_BASE_IMAGE="${FREEBSD_BASE_IMAGE:-$CACHE_ROOT/rfor/freebsd-15.1/FreeBSD-15.1.qcow2}"
FREEBSD_IMAGE="${FREEBSD_IMAGE:-$CACHE_ROOT/rfor/freebsd-15.1/FreeBSD-15.1-prepared.qcow2}"
RFOR_BIN="${RFOR_BIN:-$REPO_ROOT/target/aarch64-unknown-freebsd/release/rfor}"
SSH_KEY="${SSH_KEY:-$CACHE_ROOT/rfor/freebsd-test-key}"
LOCAL_TRAFFIC="$REPO_ROOT/tests/freebsd/local-traffic.sh"
RESTART_SOAK="$REPO_ROOT/tests/freebsd/restart-soak.sh"
REQUEST_BENCH="$REPO_ROOT/tests/common/request-bench.sh"
HARNESS="$REPO_ROOT/tests/common/harness.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

if [ ! -f "$FREEBSD_IMAGE" ]; then
    if [ ! -f "$FREEBSD_BASE_IMAGE" ]; then
        echo "FAIL: official FreeBSD image not found: $FREEBSD_BASE_IMAGE"
        echo "Download and decompress it first:"
        echo "  curl -fL -o /tmp/freebsd.qcow2.xz \\"
        echo "    https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/aarch64/Latest/FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz"
        echo "  sha256 9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963"
        echo "  xz -d /tmp/freebsd.qcow2.xz"
        echo "  mkdir -p $(dirname "$FREEBSD_BASE_IMAGE")"
        echo "  mv /tmp/freebsd.qcow2 $FREEBSD_BASE_IMAGE"
        exit 1
    fi
    echo "--- preparing FreeBSD image (one-time cloud-init) ---"
    FREEBSD_IMAGE="$FREEBSD_IMAGE" \
    FREEBSD_BASE_IMAGE="$FREEBSD_BASE_IMAGE" \
    SSH_KEY="$SSH_KEY" \
    RFOR_FREEBSD_DOCKER_IMAGE="$DOCKER_IMAGE" \
    sh "$SCRIPT_DIR/build-image.sh"
fi
if [ ! -f "$SSH_KEY" ]; then
    mkdir -p "$(dirname "$SSH_KEY")"
    ssh-keygen -q -t ed25519 -N '' -C rfor-freebsd-test -f "$SSH_KEY"
fi
if [ ! -f "$SSH_KEY.pub" ]; then
    fail "SSH public key not found: $SSH_KEY.pub"
fi
if ! ssh-keygen -y -P '' -f "$SSH_KEY" >/dev/null 2>&1; then
    fail "SSH_KEY is not usable non-interactively: $SSH_KEY"
fi
if [ ! -f "$RFOR_BIN" ]; then
    echo "FAIL: FreeBSD rfor binary not found: $RFOR_BIN"
    echo "Cross-build it with:"
    echo "  RUSTC_BOOTSTRAP=1 cargo zigbuild -Z build-std=std,panic_abort \\"
    echo "    --target aarch64-unknown-freebsd --release"
    exit 1
fi
FREEBSD_BASE_IMAGE="${FREEBSD_BASE_IMAGE:-$CACHE_ROOT/rfor/freebsd-15.1/FreeBSD-15.1.qcow2}"
FREEBSD_IMAGE="${FREEBSD_IMAGE:-$CACHE_ROOT/rfor/freebsd-15.1/FreeBSD-15.1-prepared.qcow2}"
RFOR_BIN=$(rfor_abs_path "$RFOR_BIN")
SSH_KEY=$(rfor_abs_path "$SSH_KEY")

CONF_DIR=$(mktemp -d "$CACHE_ROOT/rfor/freebsd-seed.XXXXXX")
trap 'rm -rf "$CONF_DIR"' EXIT INT TERM
PUB=$(cat "$SSH_KEY.pub")
cat >"$CONF_DIR/meta-data" <<EOF
instance-id: rfor-freebsd-docker
local-hostname: freebsd-rfor
EOF
cat >"$CONF_DIR/user-data" <<EOF
#cloud-config
package_upgrade: false
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
if [ "${RFOR_DOCKER_REBUILD:-0}" = "1" ] || ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "--- building $DOCKER_IMAGE ---"
    docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"
fi

exec docker run --rm \
    -v "$FREEBSD_IMAGE:/image/freebsd.qcow2:ro" \
    -v "$FREEBSD_BASE_IMAGE:/image/$(basename "$FREEBSD_BASE_IMAGE"):ro" \
    -v "$RFOR_BIN:/test/rfor:ro" \
    -v "$LOCAL_TRAFFIC:/test/local-traffic.sh:ro" \
    -v "$RESTART_SOAK:/test/restart-soak.sh:ro" \
    -v "$REQUEST_BENCH:/test/request-bench.sh:ro" \
    -v "$HARNESS:/opt/lib.sh:ro" \
    -v "$CONF_DIR:/seed:ro" \
    -v "$SSH_KEY:/keys/id_ed25519:ro" \
    "$DOCKER_IMAGE"
