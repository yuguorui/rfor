#!/bin/sh
# Run the two-VM OpenBSD gateway/client UDP reply-socket stress test.
# The client sends DNS queries to 223.5.5.5 through the gateway, while the
# gateway has local-traffic disabled (forwarded path).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
. "$REPO_ROOT/tests/common/harness.sh"

DOCKER_IMAGE="${RFOR_OPENBSD_DOCKER_IMAGE:-rfor-openbsd-qemu-test}"
CACHE_ROOT=$(rfor_cache_root)
IMAGE="${OPENBSD_IMAGE:-$CACHE_ROOT/rfor/openbsd-8.0.qcow2}"
KEY="${SSH_KEY:-$CACHE_ROOT/rfor/openbsd-test-key}"
RFOR_BIN="${RFOR_BIN:-$REPO_ROOT/target/x86_64-unknown-openbsd/release/rfor}"
STRESS_COUNT="${RFOR_CLIENT_STRESS_COUNT:-64}"

if [ ! -f "$IMAGE" ]; then
    echo "FAIL: OpenBSD image not found: $IMAGE" >&2
    exit 1
fi
if [ ! -f "$KEY" ]; then
    echo "FAIL: SSH key not found: $KEY" >&2
    exit 1
fi
if [ ! -x "$RFOR_BIN" ]; then
    echo "FAIL: OpenBSD rfor binary not found: $RFOR_BIN" >&2
    exit 1
fi

if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"
fi

exec docker run --rm --entrypoint /bin/sh \
    -e RFOR_CLIENT_STRESS_COUNT="$STRESS_COUNT" \
    -v "$IMAGE:/image/openbsd.qcow2:ro" \
    -v "$KEY:/keys/id_ed25519:ro" \
    -v "$RFOR_BIN:/opt/rfor:ro" \
    -v "$REPO_ROOT/tests/common/harness.sh:/opt/lib.sh:ro" \
    -v "$SCRIPT_DIR/client-stress.sh:/opt/client-stress.sh:ro" \
    "$DOCKER_IMAGE" /opt/client-stress.sh
