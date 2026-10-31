#!/bin/sh
# Build the OpenBSD/amd64 rfor binary used by the integration harness.
#
# The default build needs the OpenBSD 8.0 sysroot, cargo-zigbuild, clang,
# and rust-src. The sysroot is not downloaded unless RFOR_SYSROOT_AUTO=1.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$SCRIPT_DIR/lib.sh"
cd "$REPO_ROOT"

RFOR_BIN="${RFOR_BIN:-target/x86_64-unknown-openbsd/release/rfor}"
if [ -z "${OPENBSD_SYSROOT:-}" ]; then
    CACHE_ROOT=$(rfor_cache_root)
    OPENBSD_SYSROOT="$CACHE_ROOT/rfor/openbsd-8.0-sysroot"
    if [ ! -f "$OPENBSD_SYSROOT/usr/lib/libc.a" ] && [ -f /tmp/openbsd-sysroot-80/usr/lib/libc.a ]; then
        echo "NOTE: using legacy sysroot /tmp/openbsd-sysroot-80;" >&2
        echo "move it to $OPENBSD_SYSROOT for a persistent cache." >&2
        OPENBSD_SYSROOT=/tmp/openbsd-sysroot-80
    fi
fi

if [ "${RFOR_SKIP_BUILD:-0}" = "1" ]; then
    if [ ! -x "$RFOR_BIN" ]; then
        echo "FAIL: RFOR_SKIP_BUILD=1 but rfor binary is missing: $RFOR_BIN"
        exit 1
    fi
    echo "using existing binary: $RFOR_BIN"
    exit 0
fi

ensure_sysroot() {
    if [ -f "$OPENBSD_SYSROOT/usr/lib/libc.a" ]; then
        return 0
    fi
    if [ "${RFOR_SYSROOT_AUTO:-0}" != "1" ]; then
        echo "FAIL: missing OpenBSD 8.0 sysroot: $OPENBSD_SYSROOT"
        echo "The builder does not download it by default; base80.tgz and"
        echo "comp80.tgz are about 660 MB."
        echo "Provision it with:"
        echo "  mkdir -p $OPENBSD_SYSROOT"
        echo "  curl -fL -o /tmp/base80.tgz https://cdn.openbsd.org/pub/OpenBSD/8.0/amd64/base80.tgz"
        echo "  curl -fL -o /tmp/comp80.tgz https://cdn.openbsd.org/pub/OpenBSD/8.0/amd64/comp80.tgz"
        echo "  tar -xzf /tmp/base80.tgz -C $OPENBSD_SYSROOT"
        echo "  tar -xzf /tmp/comp80.tgz -C $OPENBSD_SYSROOT"
        echo "Or set RFOR_SYSROOT_AUTO=1 to download and verify them."
        exit 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
        echo "FAIL: curl is required to download the sysroot"
        exit 1
    fi

    BASE_URL="https://cdn.openbsd.org/pub/OpenBSD/8.0/amd64"
    TMP_SETS=$(mktemp -d /tmp/rfor-openbsd-sysroot.XXXXXX)
    echo "--- downloading OpenBSD 8.0 sysroot (about 660 MB) ---"
    for file in base80.tgz comp80.tgz SHA256; do
        if ! curl -fL --retry 3 -o "$TMP_SETS/$file" "$BASE_URL/$file"; then
            echo "FAIL: could not download $file"
            rm -rf "$TMP_SETS"
            exit 1
        fi
    done
    for file in base80.tgz comp80.tgz; do
        EXPECTED=$(awk -v f="$file" '$2 == "(" f ")" {print $4}' "$TMP_SETS/SHA256")
        ACTUAL=$(rfor_sha256 "$TMP_SETS/$file")
        if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
            echo "FAIL: SHA256 mismatch for $file"
            rm -rf "$TMP_SETS"
            exit 1
        fi
    done
    mkdir -p "$OPENBSD_SYSROOT"
    if ! tar -xzf "$TMP_SETS/base80.tgz" -C "$OPENBSD_SYSROOT"; then
        echo "FAIL: could not extract base80.tgz"
        rm -rf "$TMP_SETS"
        exit 1
    fi
    if ! tar -xzf "$TMP_SETS/comp80.tgz" -C "$OPENBSD_SYSROOT"; then
        echo "FAIL: could not extract comp80.tgz"
        rm -rf "$TMP_SETS"
        exit 1
    fi
    rm -rf "$TMP_SETS"
    if [ ! -f "$OPENBSD_SYSROOT/usr/lib/libc.a" ]; then
        echo "FAIL: sysroot extraction did not produce usr/lib/libc.a"
        exit 1
    fi
}

ensure_sysroot
for tool in cargo cargo-zigbuild clang; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "FAIL: missing build tool: $tool"
        exit 1
    fi
done
echo "--- building OpenBSD binary ---"
RUSTC_BOOTSTRAP=1 CC_x86_64_unknown_openbsd=clang CFLAGS_x86_64_unknown_openbsd="--sysroot=$OPENBSD_SYSROOT" cargo zigbuild -Z build-std=std,panic_abort --target x86_64-unknown-openbsd --release
if [ ! -x "$RFOR_BIN" ]; then
    echo "FAIL: build did not produce $RFOR_BIN"
    exit 1
fi
echo "built: $RFOR_BIN"
