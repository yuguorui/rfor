#!/usr/bin/env python3
"""Drive the OpenBSD serial installer and signal when the guest is ready.

The builder does not sleep for a guessed install duration.  This process
waits for the actual boot/install prompts, writes the ready file once the
installed system reaches its login prompt, and then waits for the poweroff
performed by the provisioning step.
"""

import argparse
import sys

import pexpect


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("iso")
    parser.add_argument("log")
    parser.add_argument("ready_file")
    parser.add_argument("--boot-timeout", type=int, default=300)
    parser.add_argument("--install-timeout", type=int, default=3600)
    return parser.parse_args()


def main():
    args = parse_args()
    net = (
        "user,id=n0,net=192.168.51.0/24,host=192.168.51.1,"
        "dns=192.168.51.2,bootfile=auto_install,"
        "hostfwd=tcp:127.0.0.1:2222-192.168.51.254:22"
    )
    qemu_args = [
        "-accel",
        "tcg,thread=single",
        "-m",
        "1024",
        "-smp",
        "2",
        "-drive",
        "file=%s,if=virtio,format=qcow2" % args.image,
        "-cdrom",
        args.iso,
        "-boot",
        "order=c,once=d",
        "-netdev",
        net,
        "-device",
        "virtio-net-pci,netdev=n0",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
    ]

    status = 0
    with open(args.log, "w", encoding="utf-8") as log:
        child = pexpect.spawn(
            "qemu-system-x86_64",
            qemu_args,
            encoding="utf-8",
            codec_errors="replace",
            timeout=args.boot_timeout,
            logfile=log,
        )
        try:
            child.expect(r"\(A\)utoinstall")
            child.send("a")
            child.send("\r")
            print("selected autoinstall", flush=True)

            # If install.conf was not applied the installer returns to its
            # menu instead of rebooting into the installed system.
            index = child.expect(
                [r"login:", r"\(I\)nstall, \(U\)pgrade"],
                timeout=args.install_timeout,
            )
            if index == 1:
                print(
                    "FAIL: installer returned to the main menu; "
                    "install.conf was not applied",
                    file=sys.stderr,
                )
                status = 1
                return status

            with open(args.ready_file, "w", encoding="ascii") as ready:
                ready.write("ready\n")
            print("installed guest reached the login prompt", flush=True)

            # The provisioning step powers the guest off over SSH.  Walking
            # the serial stream to EOF is the completion signal for QEMU.
            child.expect(pexpect.EOF, timeout=args.install_timeout)
        except pexpect.TIMEOUT:
            print(
                "FAIL: timed out waiting for the OpenBSD installer; "
                "see %s" % args.log,
                file=sys.stderr,
            )
            status = 1
        except pexpect.EOF:
            print("FAIL: QEMU exited before the guest was ready", file=sys.stderr)
            status = 1
        finally:
            if child.isalive():
                child.close(force=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
