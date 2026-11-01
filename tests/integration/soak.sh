#!/usr/bin/env bash
# Sustained local-traffic soak test with RSS/fd/UDP-socket sampling.
set -Eeuo pipefail

readonly WORK_DIR=/tmp/rfor-soak
readonly METRICS="$WORK_DIR/metrics.csv"
readonly RFOR_LOG="$WORK_DIR/rfor.log"
readonly SOAK_SECONDS="${SOAK_SECONDS:-30}"
readonly SOAK_IDLE_SECONDS="${SOAK_IDLE_SECONDS:-75}"
readonly SOAK_CYCLES="${SOAK_CYCLES:-2}"
readonly SOAK_TCP_WORKERS="${SOAK_TCP_WORKERS:-4}"
readonly SOAK_UDP_WORKERS="${SOAK_UDP_WORKERS:-4}"
readonly SOAK_UDP_RECYCLE="${SOAK_UDP_RECYCLE:-100}"
readonly SOAK_UDP_SLEEP_MS="${SOAK_UDP_SLEEP_MS:-5}"
readonly SOAK_MAX_RSS_DELTA_KB="${SOAK_MAX_RSS_DELTA_KB:-65536}"
readonly SOAK_MAX_ERRORS="${SOAK_MAX_ERRORS:-0}"
RFOR_PID=
LOAD_PID=

fail() {
    printf '[soak] ERROR: %s\n' "$*" >&2
    if [[ -f $RFOR_LOG ]]; then
        printf '%s\n' '--- rfor log tail ---' >&2
        tail -80 "$RFOR_LOG" >&2 || true
    fi
    exit 1
}

cleanup() {
    if [[ -n ${LOAD_PID:-} ]] && kill -0 "$LOAD_PID" 2>/dev/null; then
        kill -KILL "$LOAD_PID" 2>/dev/null || true
    fi
    if [[ -n ${RFOR_PID:-} ]] && kill -0 "$RFOR_PID" 2>/dev/null; then
        kill -KILL "$RFOR_PID" 2>/dev/null || true
        wait "$RFOR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

sample() {
    local phase=$1
    local rss threads fds udp
    rss=$(awk '/VmRSS:/{print $2}' "/proc/$RFOR_PID/status")
    threads=$(awk '/Threads:/{print $2}' "/proc/$RFOR_PID/status")
    fds=$(find "/proc/$RFOR_PID/fd" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
    udp=$(ss -uanp 2>/dev/null | grep -c "pid=$RFOR_PID" || true)
    printf '%s,%s,%s,%s,%s,%s\n' "$(date +%s)" "$phase" "$rss" "$threads" "$fds" "$udp" >> "$METRICS"
}

wait_for_log() {
    local pattern=$1
    local i=0
    while ((i < 100)); do
        if grep --fixed-strings --quiet -- "$pattern" "$RFOR_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$RFOR_PID" 2>/dev/null; then
            return 1
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

run_cycle() {
    local cycle=$1
    local load_json="$WORK_DIR/load-$cycle.json"
    python3 /integration/soak.py \
        --seconds "$SOAK_SECONDS" \
        --tcp-host 198.18.0.10 --tcp-port 18080 \
        --udp-host 198.18.0.11 --udp-port 19000 \
        --tcp-workers "$SOAK_TCP_WORKERS" --udp-workers "$SOAK_UDP_WORKERS"         --udp-recycle "$SOAK_UDP_RECYCLE" --udp-sleep-ms "$SOAK_UDP_SLEEP_MS" \
        >"$load_json" 2>"$WORK_DIR/load-$cycle.err" &
    LOAD_PID=$!
    while kill -0 "$LOAD_PID" 2>/dev/null; do
        sample "cycle$cycle-load"
        sleep 5
    done
    if ! wait "$LOAD_PID"; then
        tail -40 "$WORK_DIR/load-$cycle.err" >&2 || true
        fail "load generator failed in cycle $cycle"
    fi
    sample "cycle$cycle-postload"
    sleep "$SOAK_IDLE_SECONDS"
    sample "cycle$cycle-idle"
}

ulimit -n 65536 2>/dev/null || true

mkdir -p "$WORK_DIR"
rm -f "$METRICS"
printf 'epoch,phase,rss_kb,threads,fds,udp_sockets\n' > "$METRICS"

rfor --config /integration/config-tproxy.yaml >"$RFOR_LOG" 2>&1 &
RFOR_PID=$!
if ! wait_for_log 'tproxy listen: 0.0.0.0:15080'; then
    fail "rfor did not start"
fi
sleep 1
sample baseline

for ((cycle = 1; cycle <= SOAK_CYCLES; cycle++)); do
    run_cycle "$cycle"
done

eval "$(python3 - "$METRICS" "$SOAK_CYCLES" <<'PY'
import csv
import json
import os
import sys

metrics, cycles = sys.argv[1], int(sys.argv[2])
rows = list(csv.DictReader(open(metrics)))
if not rows:
    raise SystemExit("no metrics")
by_phase = {row["phase"]: row for row in rows}
base = by_phase["baseline"]
last = by_phase[f"cycle{cycles}-idle"]
first_idle = by_phase["cycle1-idle"]
peak = max(rows, key=lambda row: int(row["rss_kb"]))
fd_peak = max(rows, key=lambda row: int(row["fds"]))
udp_peak = max(rows, key=lambda row: int(row["udp_sockets"]))
tcp_ok = tcp_err = udp_ok = udp_err = 0
work_dir = os.path.dirname(metrics)
for cycle in range(1, cycles + 1):
    with open(os.path.join(work_dir, f"load-{cycle}.json")) as source:
        data = json.load(source)
    tcp_ok += data["tcp_ok"]
    tcp_err += data["tcp_errors"]
    udp_ok += data["udp_ok"]
    udp_err += data["udp_errors"]

values = {
    "BASE_RSS": base["rss_kb"],
    "BASE_FD": base["fds"],
    "BASE_UDP": base["udp_sockets"],
    "FIRST_RSS": first_idle["rss_kb"],
    "FIRST_FD": first_idle["fds"],
    "FIRST_UDP": first_idle["udp_sockets"],
    "LAST_RSS": last["rss_kb"],
    "LAST_FD": last["fds"],
    "LAST_UDP": last["udp_sockets"],
    "PEAK_RSS": peak["rss_kb"],
    "PEAK_FD": fd_peak["fds"],
    "PEAK_UDP": udp_peak["udp_sockets"],
    "TCP_OK": tcp_ok,
    "TCP_ERR": tcp_err,
    "UDP_OK": udp_ok,
    "UDP_ERR": udp_err,
}
for key, value in values.items():
    print(f"{key}={value}")
PY
)"

printf '[soak] requests: tcp_ok=%s tcp_err=%s udp_ok=%s udp_err=%s\n' "$TCP_OK" "$TCP_ERR" "$UDP_OK" "$UDP_ERR"
for load_file in "$WORK_DIR"/load-*.json; do
    printf '[soak] %s: %s' "$(basename "$load_file")" "$(cat "$load_file")"; echo
done
printf '[soak] RSS kB: baseline=%s first_idle=%s last_idle=%s peak=%s\n' "$BASE_RSS" "$FIRST_RSS" "$LAST_RSS" "$PEAK_RSS"
printf '[soak] fds: baseline=%s first_idle=%s last_idle=%s peak=%s\n' "$BASE_FD" "$FIRST_FD" "$LAST_FD" "$PEAK_FD"
printf '[soak] UDP sockets: baseline=%s first_idle=%s last_idle=%s peak=%s\n' "$BASE_UDP" "$FIRST_UDP" "$LAST_UDP" "$PEAK_UDP"

((TCP_ERR <= SOAK_MAX_ERRORS)) || fail "TCP errors: $TCP_ERR"
((UDP_ERR <= SOAK_MAX_ERRORS)) || fail "UDP errors: $UDP_ERR"
((LAST_RSS <= FIRST_RSS + 16384)) ||
    fail "RSS grew by more than 16 MiB between soak cycles"
((LAST_FD <= FIRST_FD + 4)) ||
    fail "fd count grew between soak cycles"
((LAST_UDP <= FIRST_UDP + 2)) ||
    fail "UDP socket count did not settle between soak cycles"
((LAST_RSS <= BASE_RSS + SOAK_MAX_RSS_DELTA_KB)) ||
    fail "idle RSS stayed more than $SOAK_MAX_RSS_DELTA_KB KiB above baseline"
printf '[soak] PASS: no linear RSS/fd/UDP-socket growth across cycles\n'
