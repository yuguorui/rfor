#!/usr/bin/env python3
"""Point-to-point Layer-3 utun tunnel over SSH between two macOS VMs.

Apple's Virtualization.Framework shared NAT (vmnet) isolates guests from each
other at Layer 2. Forwarding through a host-bridged utun pair exercises real
macOS kernel IP forwarding and PF route-to rules on the gateway VM.
"""

import ctypes
import fcntl
import os
import select
import signal
import struct
import subprocess
import sys
import threading

AF_SYSTEM = 32
SOCK_DGRAM = 2
SYSPROTO_CONTROL = 2
AF_SYS_CONTROL = 2
UTUN_OPT_IFNAME = 2
# _IOWR('N', 3, struct ctl_info) with sizeof(struct ctl_info) == 100
CTLIOCGINFO = 0xC0644E03

SSH_OPTS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
]


def open_utun(local_ip: str, peer_ip: str, local_v6: str | None = None) -> tuple[int, str]:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libc.getsockopt.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]

    fd = libc.socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"socket(AF_SYSTEM) failed: {os.strerror(err)}")

    try:
        ctl_info = bytearray(struct.pack("I96s", 0, b"com.apple.net.utun_control\0"))
        fcntl.ioctl(fd, CTLIOCGINFO, ctl_info, True)
        ctl_id = struct.unpack("I", ctl_info[:4])[0]

        addr = ctypes.create_string_buffer(
            struct.pack("BBHII5I", 32, AF_SYSTEM, AF_SYS_CONTROL, ctl_id, 0, 0, 0, 0, 0, 0),
            32,
        )
        if libc.connect(fd, addr, 32) != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"connect(utun_control) failed: {os.strerror(err)}")

        name_buf = ctypes.create_string_buffer(64)
        name_len = ctypes.c_uint32(64)
        if (
            libc.getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf,
                ctypes.byref(name_len),
            )
            != 0
        ):
            err = ctypes.get_errno()
            raise OSError(err, f"getsockopt(UTUN_OPT_IFNAME) failed: {os.strerror(err)}")

        ifname = name_buf.value.decode("ascii")
        subprocess.run(
            [
                "ifconfig",
                ifname,
                "inet",
                local_ip,
                peer_ip,
                "netmask",
                "255.255.255.255",
                "mtu",
                "1500",
                "up",
            ],
            check=True,
        )
        if local_v6:
            subprocess.run(
                ["ifconfig", ifname, "inet6", local_v6, "prefixlen", "64"],
                check=True,
            )
        return fd, ifname
    except Exception:
        os.close(fd)
        raise


def write_all(wfd: int, data: bytes | memoryview) -> None:
    mv = memoryview(data)
    while mv:
        written = os.write(wfd, mv)
        mv = mv[written:]


def run_guest(local_ip: str, peer_ip: str, local_v6: str | None = None) -> int:
    stop = False

    def handle_sig(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    fd, ifname = open_utun(local_ip, peer_ip, local_v6)
    sys.stderr.write(f"READY {ifname}\n")
    sys.stderr.flush()

    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    inbuf = bytearray()

    try:
        while not stop:
            try:
                readable, _, _ = select.select([fd, stdin_fd], [], [], 1.0)
            except InterruptedError:
                continue

            if fd in readable:
                pkt = os.read(fd, 65536)
                if not pkt:
                    break
                write_all(stdout_fd, struct.pack("!H", len(pkt)) + pkt)

            if stdin_fd in readable:
                chunk = os.read(stdin_fd, 65536)
                if not chunk:
                    break
                inbuf.extend(chunk)
                while len(inbuf) >= 2:
                    plen = struct.unpack("!H", inbuf[:2])[0]
                    if len(inbuf) < 2 + plen:
                        break
                    pkt = bytes(inbuf[2 : 2 + plen])
                    del inbuf[: 2 + plen]
                    try:
                        os.write(fd, pkt)
                    except OSError:
                        pass
    except (BrokenPipeError, OSError):
        pass
    finally:
        os.close(fd)

    return 0


def spawn_guest_ssh(
    ssh_key: str,
    target: str,
    local_ip: str,
    peer_ip: str,
    local_v6: str | None = None,
) -> subprocess.Popen[bytes]:
    v6_arg = f" {local_v6}" if local_v6 else ""
    remote_cmd = (
        "PY=$(command -v /opt/homebrew/bin/python3 || command -v /usr/local/bin/python3 || command -v python3); "
        f'[ -n "$PY" ] || {{ echo "python3 not found" >&2; exit 1; }}; '
        f'exec sudo "$PY" /tmp/rfor-utun-wire.py --guest {local_ip} {peer_ip}{v6_arg}'
    )
    return subprocess.Popen(
        ["ssh", "-p", "22", "-i", ssh_key, *SSH_OPTS, target, remote_cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def pump_stream(src, dst) -> None:
    try:
        while True:
            data = src.read1(65536) if hasattr(src, "read1") else src.read(4096)
            if not data:
                break
            dst.write(data)
            dst.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass


def drain_stderr(proc: subprocess.Popen[bytes]) -> None:
    if proc.stderr is None:
        return
    try:
        while proc.stderr.readline():
            pass
    except (OSError, ValueError):
        pass


def terminate_proc(proc: subprocess.Popen[bytes]) -> None:
    for stream in (proc.stdin, proc.stdout):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def run_bridge(
    ssh_key: str,
    gw_target: str,
    client_target: str,
    gw_link_ip: str,
    client_link_ip: str,
    ready_file: str,
    gw_link_v6: str | None = None,
    client_link_v6: str | None = None,
) -> int:
    self_path = os.path.abspath(__file__)
    for target in (gw_target, client_target):
        subprocess.run(
            ["scp", "-P", "22", "-i", ssh_key, *SSH_OPTS, self_path, f"{target}:/tmp/rfor-utun-wire.py"],
            check=True,
        )

    stop_event = threading.Event()

    def handle_sig(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    p_gw = spawn_guest_ssh(ssh_key, gw_target, gw_link_ip, client_link_ip, gw_link_v6)
    p_cl = spawn_guest_ssh(ssh_key, client_target, client_link_ip, gw_link_ip, client_link_v6)

    try:
        assert p_gw.stderr is not None and p_cl.stderr is not None
        assert p_gw.stdout is not None and p_gw.stdin is not None
        assert p_cl.stdout is not None and p_cl.stdin is not None

        gw_line = p_gw.stderr.readline().decode("utf-8", errors="replace").strip()
        cl_line = p_cl.stderr.readline().decode("utf-8", errors="replace").strip()

        if not gw_line.startswith("READY ") or not cl_line.startswith("READY "):
            gw_rest = p_gw.stderr.read().decode("utf-8", errors="replace")
            cl_rest = p_cl.stderr.read().decode("utf-8", errors="replace")
            sys.stderr.write(
                f"FAIL: utun-wire guest startup failed\n"
                f"gw ({gw_target}): {gw_line}\n{gw_rest}\n"
                f"client ({client_target}): {cl_line}\n{cl_rest}\n"
            )
            return 1

        gw_if = gw_line.split()[1]
        cl_if = cl_line.split()[1]

        threading.Thread(target=pump_stream, args=(p_gw.stdout, p_cl.stdin), daemon=True).start()
        threading.Thread(target=pump_stream, args=(p_cl.stdout, p_gw.stdin), daemon=True).start()
        threading.Thread(target=drain_stderr, args=(p_gw,), daemon=True).start()
        threading.Thread(target=drain_stderr, args=(p_cl,), daemon=True).start()

        tmp_ready = f"{ready_file}.tmp"
        with open(tmp_ready, "w", encoding="ascii") as fh:
            fh.write(f"gw={gw_if} cl={cl_if}\n")
        os.replace(tmp_ready, ready_file)

        while not stop_event.is_set():
            if p_gw.poll() is not None or p_cl.poll() is not None:
                return 1
            stop_event.wait(0.25)

        return 0
    finally:
        terminate_proc(p_gw)
        terminate_proc(p_cl)


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: utun-wire.py --guest|--bridge ...\n")
        return 2

    mode = sys.argv[1]
    if mode == "--guest":
        if len(sys.argv) not in (4, 5):
            sys.stderr.write("Usage: utun-wire.py --guest <local-ip> <peer-ip> [local-v6]\n")
            return 2
        local_v6 = sys.argv[4] if len(sys.argv) == 5 else None
        return run_guest(sys.argv[2], sys.argv[3], local_v6)
    if mode == "--bridge":
        if len(sys.argv) not in (8, 10):
            sys.stderr.write(
                "Usage: utun-wire.py --bridge <ssh-key> <gw-target> <client-target> <gw-link-ip> <client-link-ip> <ready-file> [gw-link-v6 client-link-v6]\n"
            )
            return 2
        gw_link_v6 = sys.argv[8] if len(sys.argv) == 10 else None
        client_link_v6 = sys.argv[9] if len(sys.argv) == 10 else None
        return run_bridge(
            sys.argv[2],
            sys.argv[3],
            sys.argv[4],
            sys.argv[5],
            sys.argv[6],
            sys.argv[7],
            gw_link_v6,
            client_link_v6,
        )

    sys.stderr.write(f"Unknown mode: {mode}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
