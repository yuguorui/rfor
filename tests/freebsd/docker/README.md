# FreeBSD local-traffic test inside Docker + QEMU

This backend boots a prepared FreeBSD 15.1 aarch64 cloud image under QEMU
in a Debian container. The prepared overlay is mounted read-only and QEMU
uses snapshot=on, so tests never modify it.

## Run

    cargo test --release --test freebsd_local_traffic -- --ignored --nocapture

or directly:

    ./tests/freebsd/docker/run.sh

The first run prepares the image once:

- boots the official BASIC-CLOUDINIT qcow2
- lets cloud-init run one time
- installs curl/bind-tools
- sets firewall_enable=YES and firewall_type=open
- disables cloud-init
- shuts down cleanly and saves the prepared overlay

Later runs boot the prepared image without a cloud-init seed, so cloud-init
does not rerun and there is no package upgrade. The test then runs the
local-traffic benchmark and ten restart/cleanup cycles.

## Images and paths

The official base image is expected at:

    ~/Library/Caches/rfor/freebsd-15.1/FreeBSD-15.1.qcow2

The prepared overlay is cached next to it:

    ~/Library/Caches/rfor/freebsd-15.1/FreeBSD-15.1-prepared.qcow2

The prepared overlay references the official qcow2 as its backing file;
keep both files together. Override them with FREEBSD_BASE_IMAGE and
FREEBSD_IMAGE. The hash of the official compressed image is
9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963.

The cross-built test binary defaults to:

    target/aarch64-unknown-freebsd/release/rfor

Override with RFOR_BIN. The test-only SSH key is
~/Library/Caches/rfor/freebsd-test-key unless SSH_KEY is set.

## Notes

- QEMU uses TCG inside the container; KVM is not used.
- The guest uses the aarch64 UEFI firmware from qemu-efi-aarch64.
- The prepared image has ipfw open at boot; the test adds and removes its
  own marker-scoped rules and tables.
- The private key never enters the cloud-init seed or the prepared image.
