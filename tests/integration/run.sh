#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_NAME=${RFOR_INTEGRATION_PROJECT:-rfor-integration}
COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$SCRIPT_DIR/compose.yaml")

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"${COMPOSE[@]}" build origin
"${COMPOSE[@]}" up --no-build --abort-on-container-exit --exit-code-from test
