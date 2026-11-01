# QEMU + SSH client for the FreeBSD local-traffic integration test.
#
# The FreeBSD qcow2 is mounted read-only at runtime; QEMU uses snapshot=on.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        qemu-system-arm \
        qemu-efi-aarch64 \
        qemu-utils \
        openssh-client \
        genisoimage \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY run-in-container.sh /opt/run-in-container.sh
ENTRYPOINT ["/bin/sh", "/opt/run-in-container.sh"]
