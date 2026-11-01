# FreeBSD local-traffic test inside Docker + QEMU

This backend boots the official FreeBSD 15.1 aarch64 BASIC-CLOUDINIT
qcow2 under QEMU in a Debian container. The qcow2 is mounted read-only and
QEMU uses snapshot=on, so the base image is never modified.

## Run

    cargo test --release --test freebsd_local_traffic -- --ignored --nocapture

or directly:

    ./tests/freebsd/docker/run.sh

The first run builds the Docker image. The FreeBSD qcow2 is expected in
the host cache:

    ~/Library/Caches/rfor/freebsd-15.1/FreeBSD-15.1.qcow2

The hash of the official compressed image is
9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963.
The cross-built test binary defaults to:

    target/aarch64-unknown-freebsd/release/rfor

Override the paths with FREEBSD_IMAGE, RFOR_BIN, or SSH_KEY.

The container injects a test-only root key through cloud-init, loads ipfw
with a terminal allow rule, installs curl/bind-tools, and then runs
tests/freebsd/local-traffic.sh. A fresh cloud-init boot performs a package
upgrade and can take several minutes under TCG.

## Notes

- QEMU uses TCG inside the container; KVM is not used.
- The guest uses the aarch64 UEFI firmware from qemu-efi-aarch64.
- The test key is for the disposable VM only; the private key never enters
  the cloud-init seed.
- The qcow2 is not baked into the Docker image.
