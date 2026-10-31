# QEMU + SSH client for the OpenBSD integration tests (qcow2 build + forwarded stress).
#
# The OpenBSD qcow2 image is intentionally not part of the build context.
# The host runner mounts it read-only and QEMU uses snapshot=on.

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        qemu-system-x86 \
        qemu-utils \
        openssh-client \
        ca-certificates \
        curl \
        python3 \
        python3-pexpect \
    && rm -rf /var/lib/apt/lists/*

ARG OPENBSD_ISO_SHA256=bc85d747c6ee4354d14fbfeee38087500386a2e9d86fa7b5ab13d840d902aa33
COPY patch-iso.py /opt/patch-iso.py
RUN curl -fL --retry 3 -o /opt/install80.iso \
        https://cdn.openbsd.org/pub/OpenBSD/8.0/amd64/install80.iso \
    && echo "$OPENBSD_ISO_SHA256  /opt/install80.iso" | sha256sum -c - \
    && python3 /opt/patch-iso.py /opt/install80.iso /opt/install80-serial.iso \
    && rm -f /opt/install80.iso

COPY run-in-container.sh /opt/run-in-container.sh
COPY build-in-container.sh /opt/build-in-container.sh
COPY install-pexpect.py /opt/install-pexpect.py
ENTRYPOINT ["/bin/sh", "/opt/run-in-container.sh"]
