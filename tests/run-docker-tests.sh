#!/bin/sh
# Run the Linux, OpenBSD, and FreeBSD Docker/QEMU integration tests.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

echo "=== Linux Docker integration ==="
./tests/integration/run.sh

if [ "${RFOR_SKIP_BUILD:-0}" != "1" ]; then
    echo "=== building OpenBSD test binary ==="
    ./tests/openbsd/build-rfor.sh
    if [ ! -f target/aarch64-unknown-freebsd/release/rfor ]; then
        echo "=== building FreeBSD test binary ==="
        RUSTC_BOOTSTRAP=1 cargo zigbuild -Z build-std=std,panic_abort \
            --target aarch64-unknown-freebsd --release
    fi
fi

echo "=== OpenBSD forwarded-traffic stress ==="
if [ -f "$HOME/Library/Caches/rfor/openbsd-8.0.qcow2" ] && [ -f "$HOME/Library/Caches/rfor/openbsd-test-key" ]; then
    ./tests/openbsd/docker/run-client-stress.sh
else
    echo "SKIP: build the OpenBSD qcow2/key first with tests/openbsd/docker/build-image.sh"
fi

echo "=== FreeBSD Docker/QEMU integration ==="
cargo test --release --test freebsd_local_traffic -- --ignored --nocapture
