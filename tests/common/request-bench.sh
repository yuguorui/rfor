#!/bin/sh
# Repeated request and latency helpers for local-traffic integration tests.
#
# Requires curl; bench_dns also requires dig. Times are reported in
# milliseconds. Functions set BENCH_* globals rather than printing counters.

bench_tcp_once() {
    _url=$1
    _code=$(curl -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' "$_url" 2>/dev/null) || _code="000"
    case "$_code" in
        2*|3*) return 0 ;;
        *) return 1 ;;
    esac
}

bench_tcp_ok() {
    _url=$1
    _retries=${2:-5}
    _i=0
    while [ "$_i" -lt "$_retries" ]; do
        if bench_tcp_once "$_url"; then
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

bench_tcp() {
    _url=$1
    _count=$2
    _file=$3
    BENCH_TCP_OK=0
    : >"$_file"
    _i=0
    while [ "$_i" -lt "$_count" ]; do
        _out=$(curl -sS --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code} %{time_total}' "$_url" 2>/dev/null) || _out="000 0"
        _code=${_out%% *}
        _time=${_out##* }
        case "$_code" in
            2*|3*)
                BENCH_TCP_OK=$((BENCH_TCP_OK + 1))
                _ms=$(awk -v t="$_time" 'BEGIN {printf "%.3f", t * 1000}')
                echo "$_ms" >>"$_file"
                ;;
        esac
        _i=$((_i + 1))
    done
}

bench_tcp_burst() {
    _url=$1
    _count=$2
    _dir=$3
    mkdir -p "$_dir"
    rm -f "$_dir"/*.out "$_dir"/times 2>/dev/null || true
    (
        _i=0
        while [ "$_i" -lt "$_count" ]; do
            (
                curl -sS --noproxy '*' --max-time 15 -o /dev/null -w '%{http_code} %{time_total}' "$_url" 2>/dev/null || echo "000 0"
            ) >"$_dir/$_i.out" &
            _i=$((_i + 1))
        done
        wait
    ) || true
    BENCH_BURST_OK=0
    : >"$_dir/times"
    for _f in "$_dir"/*.out; do
        [ -f "$_f" ] || continue
        _out=$(cat "$_f")
        _code=${_out%% *}
        _time=${_out##* }
        case "$_code" in
            2*|3*)
                BENCH_BURST_OK=$((BENCH_BURST_OK + 1))
                _ms=$(awk -v t="$_time" 'BEGIN {printf "%.3f", t * 1000}')
                echo "$_ms" >>"$_dir/times"
                ;;
        esac
    done
}

bench_dns_once() {
    _server=$1
    _name=$2
    _out=$(dig +time=2 +tries=2 +noall +answer +stats "$_name" @"$_server" 2>/dev/null) || _out=""
    printf '%s' "$_out" | grep -q "^$_name[.]"
}

bench_dns_ok() {
    _server=$1
    _name=$2
    _retries=${3:-5}
    _i=0
    while [ "$_i" -lt "$_retries" ]; do
        if bench_dns_once "$_server" "$_name"; then
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

bench_dns() {
    _server=$1
    _name=$2
    _count=$3
    _file=$4
    BENCH_DNS_OK=0
    : >"$_file"
    _i=0
    while [ "$_i" -lt "$_count" ]; do
        _out=$(dig +time=2 +tries=2 +noall +answer +stats "$_name" @"$_server" 2>/dev/null) || _out=""
        _time=$(printf '%s' "$_out" | awk '/Query time:/{print $4; exit}')
        if [ -n "$_time" ] && printf '%s' "$_out" | grep -q "^$_name[.]"; then
            BENCH_DNS_OK=$((BENCH_DNS_OK + 1))
            echo "$_time" >>"$_file"
        fi
        _i=$((_i + 1))
    done
}

bench_stats() {
    _label=$1
    _ok=$2
    _total=$3
    _file=$4
    if [ ! -s "$_file" ]; then
        echo "STATS: $_label ok=$_ok/$_total latency_ms=no-samples"
        return 0
    fi
    _n=$(wc -l <"$_file" | tr -d ' ')
    _min=$(sort -n "$_file" | head -1)
    _max=$(sort -n "$_file" | tail -1)
    _avg=$(awk '{s += $1} END {printf "%.1f", s / NR}' "$_file")
    _p50=$(sort -n "$_file" | awk '{a[NR] = $1} END {printf "%.1f", a[int((NR + 1) / 2)]}')
    echo "STATS: $_label ok=$_ok/$_total n=$_n latency_ms min=$_min avg=$_avg p50=$_p50 max=$_max"
}
