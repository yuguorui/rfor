#!/usr/bin/env python3
"""Patch /etc/boot.conf in an OpenBSD ISO without relocating the boot image."""

import shutil
import struct
import sys

SECTOR = 2048
NEW_CONF = b"set image /8.0/amd64/bsd.rd\nset tty com0\n"

src, dst = sys.argv[1:3]
shutil.copyfile(src, dst)

with open(dst, "r+b") as image:
    image.seek(16 * SECTOR)
    pvd = image.read(SECTOR)
    if pvd[0] != 1 or pvd[1:6] != b"CD001":
        raise SystemExit("not an ISO9660 image")

    root = pvd[156:190]
    root_extent = struct.unpack_from("<I", root, 2)[0]
    root_size = struct.unpack_from("<I", root, 10)[0]

    def entries(extent, size):
        image.seek(extent * SECTOR)
        data = image.read(size)
        offset = 0
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset = ((offset // SECTOR) + 1) * SECTOR
                continue
            name_len = data[offset + 32]
            name = data[offset + 33 : offset + 33 + name_len]
            if name not in (b"\x00", b"\x01"):
                yield offset, data, name
            offset += length

    etc = None
    for offset, data, name in entries(root_extent, root_size):
        if name in (b"ETC", b"etc"):
            etc = (
                struct.unpack_from("<I", data, offset + 2)[0],
                struct.unpack_from("<I", data, offset + 10)[0],
            )
            break
    if etc is None:
        raise SystemExit("ETC directory not found")

    boot = None
    for offset, data, name in entries(etc[0], etc[1]):
        if name in (b"BOOT.CONF;1", b"BOOT.CONF", b"boot.conf"):
            boot = (
                etc[0] * SECTOR + offset,
                struct.unpack_from("<I", data, offset + 2)[0],
                struct.unpack_from("<I", data, offset + 10)[0],
            )
            break
    if boot is None:
        raise SystemExit("boot.conf not found")

    record_abs, file_extent, old_size = boot
    if len(NEW_CONF) > SECTOR:
        raise SystemExit("boot.conf does not fit in one sector")

    image.seek(record_abs + 10)
    image.write(struct.pack("<I", len(NEW_CONF)) + struct.pack(">I", len(NEW_CONF)))
    image.seek(file_extent * SECTOR)
    image.write(NEW_CONF)
    print(
        "patched boot.conf: old=%d new=%d extent=%d"
        % (old_size, len(NEW_CONF), file_extent)
    )
