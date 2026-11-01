#!/bin/sh
# Shared helpers for the OpenBSD integration harness.
#
# This file is sourced by the host backends and mounted into the Docker
# container at /opt/lib.sh. It must stay POSIX sh compatible.

: "${RFOR_SSH_OPTS:=-o BatchMode=yes -o ConnectTimeout=3}"
: "${RFOR_SCP_OPTS:=-o BatchMode=yes -o ConnectTimeout=3}"

rfor_cache_root() {
    if [ -n "${XDG_CACHE_HOME:-}" ]; then
        printf '%s' "$XDG_CACHE_HOME"
    elif [ "$(uname -s)" = "Darwin" ]; then
        printf '%s' "$HOME/Library/Caches"
    else
        printf '%s' "$HOME/.cache"
    fi
    echo
}

rfor_abs_path() {
    _dir=$(dirname -- "$1")
    _base=$(basename -- "$1")
    printf '%s/%s' "$(CDPATH= cd -- "$_dir" && pwd)" "$_base"
    echo
}

rfor_sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

rfor_require_file() {
    if [ ! -f "$1" ]; then
        echo "FAIL: $2 not found: $1" >&2
        return 1
    fi
}

# A bind-mounted key keeps its host UID; OpenSSH running as root rejects
# foreign-owned private keys. Copy it to a root-owned 0600 path and print
# the destination.
rfor_materialize_key() {
    _src=$1
    _dst=${2:-/tmp/rfor-id_ed25519}
    if [ ! -f "$_src" ]; then
        echo "FAIL: SSH key not found: $_src" >&2
        return 1
    fi
    cp "$_src" "$_dst"
    chmod 600 "$_dst"
    printf '%s' "$_dst"
    echo
}

rfor_ssh() {
    _target=$1
    _port=$2
    _key=$3
    shift 3
    if [ -n "$_key" ]; then
        ssh -p "$_port" -i "$_key" $RFOR_SSH_OPTS "$_target" "$@"
    else
        ssh -p "$_port" $RFOR_SSH_OPTS "$_target" "$@"
    fi
}

rfor_scp_to() {
    _target=$1
    _port=$2
    _key=$3
    _src=$4
    _dst=$5
    if [ -n "$_key" ]; then
        scp -P "$_port" -i "$_key" $RFOR_SCP_OPTS "$_src" "$_target:$_dst"
    else
        scp -P "$_port" $RFOR_SCP_OPTS "$_src" "$_target:$_dst"
    fi
}

rfor_wait_ssh() {
    _target=$1
    _port=$2
    _key=$3
    _timeout=${4:-300}
    _log=${5:-/tmp/rfor-ssh.log}
    : >"$_log"
    _i=0
    while [ "$_i" -lt "$_timeout" ]; do
        if rfor_ssh "$_target" "$_port" "$_key" true >/dev/null 2>>"$_log"; then
            return 0
        fi
        sleep 2
        _i=$((_i + 2))
    done
    return 1
}

rfor_copy_test_assets() {
    _target=$1
    _port=$2
    _key=$3
    _bin=$4
    _test=$5
    rfor_scp_to "$_target" "$_port" "$_key" "$_bin" /tmp/rfor-local-traffic.bin
    rfor_scp_to "$_target" "$_port" "$_key" "$_test" /tmp/local-traffic.sh
    rfor_ssh "$_target" "$_port" "$_key" 'chmod 755 /tmp/local-traffic.sh /tmp/rfor-local-traffic.bin'
}

rfor_run_local_traffic() {
    _target=$1
    _port=$2
    _key=$3
    rfor_ssh "$_target" "$_port" "$_key" 'RFOR_ALLOW_DEFAULT_ROUTE_TEST=1 sh /tmp/local-traffic.sh /tmp/rfor-local-traffic.bin'
}

rfor_shutdown_guest() {
    _target=$1
    _port=$2
    _key=$3
    rfor_ssh "$_target" "$_port" "$_key" 'shutdown -p now'
}
