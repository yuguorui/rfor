#!/usr/bin/env bash
# Run the sustained local-traffic soak test in Docker.
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_NAME=${RFOR_SOAK_PROJECT:-rfor-soak}
COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$SCRIPT_DIR/compose.yaml")

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"${COMPOSE[@]}" build origin
"${COMPOSE[@]}" up -d --no-build origin socks
"${COMPOSE[@]}" run --rm --no-deps \
    -e SOAK_SECONDS="${SOAK_SECONDS:-30}" \
    -e SOAK_IDLE_SECONDS="${SOAK_IDLE_SECONDS:-75}" \
    -e SOAK_CYCLES="${SOAK_CYCLES:-2}"     -e SOAK_TCP_WORKERS="${SOAK_TCP_WORKERS:-4}"     -e SOAK_UDP_WORKERS="${SOAK_UDP_WORKERS:-4}"     -e SOAK_UDP_RECYCLE="${SOAK_UDP_RECYCLE:-100}"     -e SOAK_UDP_SLEEP_MS="${SOAK_UDP_SLEEP_MS:-5}"     -e SOAK_MAX_RSS_DELTA_KB="${SOAK_MAX_RSS_DELTA_KB:-65536}" -e SOAK_MAX_ERRORS="${SOAK_MAX_ERRORS:-0}" \
    --entrypoint /integration/soak.sh test
