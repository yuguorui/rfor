# OpenBSD integration tests

OpenBSD interception is **forwarded traffic only**. Locally generated
traffic is intentionally unsupported (PF divert-to only tags inbound
packets); `local-traffic: true` is rejected at startup.

## Layout

    tests/openbsd/
      build-rfor.sh         builds the OpenBSD binary (sysroot + zigbuild)
      rfor-openbsd.yaml     forwarded-traffic fixture
      ../common/harness.sh  shared cache, SSH, and asset-copy helpers
      docker/               Docker + QEMU image builder and forwarded stress

## Build the binary

    ./tests/openbsd/build-rfor.sh

The default build needs the OpenBSD 8.0 sysroot plus cargo-zigbuild,
clang, and rust-src for -Z build-std. The sysroot cache is
~/Library/Caches/rfor/openbsd-8.0-sysroot on macOS and
$XDG_CACHE_HOME/rfor/openbsd-8.0-sysroot elsewhere; override it with
OPENBSD_SYSROOT. RFOR_SYSROOT_AUTO=1 downloads and verifies base80.tgz
and comp80.tgz (about 660 MB). RFOR_SKIP_BUILD=1 only checks an existing
RFOR_BIN.

## Forwarded-traffic stress

    ./tests/openbsd/docker/run-client-stress.sh

This is a two-VM test: a client sends UDP DNS queries to 223.5.5.5 through
the gateway's forwarded PF path while rfor runs on the gateway. It needs
the cached qcow2 and SSH key; create them with
`tests/openbsd/docker/build-image.sh`.

On macOS/colima QEMU uses TCG; with /dev/kvm it uses KVM. The image is
built from the official install ISO and cached outside the repository.

## Manual VM check

Copy `target/x86_64-unknown-openbsd/release/rfor` and
`tests/openbsd/rfor-openbsd.yaml` into a disposable guest, run rfor as
root, and point a client at the guest. Do not run this against a
production gateway.
