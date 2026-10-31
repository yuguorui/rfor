#!/bin/sh
# Build the OpenBSD qcow2 used by the forwarded-traffic stress test.
set -eu

if [ "${1:-}" = "build" ]; then
    exec /bin/sh /opt/build-in-container.sh
fi

echo "This image builds the OpenBSD qcow2; use run-client-stress.sh." >&2
exit 1
