# OpenBSD image builder inside Docker + QEMU

This directory packages QEMU, an SSH client, and the OpenBSD installer
automation. The official install ISO is downloaded in the Dockerfile, so
Docker layer caching keeps it across rebuilds. The qcow2 is built from
scratch by autoinstall on the first build and cached outside the image;
it is never copied from VM105 or baked into the Docker image.

`run-in-container.sh build` is the image-build entrypoint used by
`build-image.sh`; the same image is reused by the forwarded-traffic
stress test (`run-client-stress.sh`).

## Build the image

    ./tests/openbsd/docker/build-image.sh

The installer runs only during that one-time image build; later boots are
plain disk boots with snapshot=on and do not replay provisioning.

On macOS/colima there is no /dev/kvm, so QEMU uses TCG with
thread=single (OpenBSD guests are not safe with thread=multi). On a Linux
host with /dev/kvm, the runner passes the device through and QEMU uses
KVM.

## OpenBSD image

The Dockerfile downloads install80.iso from cdn.openbsd.org and verifies
the SHA256 build argument. patch-iso.py modifies /etc/boot.conf inside
the original ISO image (it does not rebuild the ISO or move the boot
image) to use the serial console and bsd.rd.

The qcow2 is built from scratch at runtime:

- install-pexpect.py boots QEMU and waits for the actual (A)utoinstall
  prompt instead of sleeping for a guessed boot time
- install.conf is served over HTTP and sets static 192.168.51.254/24,
  gateway 192.168.51.1, the root SSH key, and the serial console
- after the installer reboots, pexpect waits for the real login: prompt
  and writes /tmp/install.ready
- the builder waits for that ready file, not a fixed install duration; if
  the installer exits early the build fails immediately with the serial log
- SSH then installs curl, writes a minimal pf.conf with anchor "rfor/*",
  enables PF, and powers off with shutdown -p now
- the result is cached at ~/Library/Caches/rfor/openbsd-8.0.qcow2
  (macOS) or the XDG cache

The image has no VM105 secrets: root password login is disabled and only
the test key is authorized. The harness generates an unencrypted
$CACHE_ROOT/rfor/openbsd-test-key on first use; a personal
passphrase-protected key is not usable inside the non-interactive
container. Set SSH_KEY to override it with another unencrypted key.

To rebuild the image, remove the cached qcow2. To force a Docker layer
rebuild, use docker build --no-cache. RFOR_KEEP_IMAGE=1 keeps a failed
.tmp qcow2 for debugging.

OPENBSD_IMAGE can point at a prebuilt sanitized qcow2 instead. An optional
OPENBSD_IMAGE_URL plus OPENBSD_IMAGE_SHA256 downloads a prebuilt image on
demand into the cache; this is not the default path.
