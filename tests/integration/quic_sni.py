#!/usr/bin/env python3
"""Send a hand-crafted QUIC Initial packet to exercise rfor's QUIC SNI
sniffing end to end.

This is intentionally independent of rfor's rustls-based parser: the
Initial secrets, AEAD and header protection are derived here with
python-cryptography, following RFC 9001 Section 5 and RFC 9001
Appendix A.1 (AES header protection sample). QUIC v2 support follows
RFC 9369 / draft-ietf-quic-v2 Section 3 (own initial salt and HKDF
labels).

Usage: quic_sni.py <target-ip> <target-port> <sni-host> [v1|v2]
"""

import socket
import sys

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# RFC 9001 Section 5.2 / RFC 9369 Section 3 (draft-ietf-quic-v2).
INITIAL_SALT = {
    1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
WIRE_VERSION = {1: 0x00000001, 2: 0x6B3343CF}
# rustls and RFC 9369 both still wrap these labels with the "tls13 "
# prefix inside hkdf_expand_label.
KEY_LABELS = {1: b"quic key", 2: b"quicv2 key"}
IV_LABELS = {1: b"quic iv", 2: b"quicv2 iv"}
HP_LABELS = {1: b"quic hp", 2: b"quicv2 hp"}
AES_GCM_TAG_LEN = 16
MIN_INITIAL_DATAGRAM = 1200


def hkdf_expand_label(secret, label, context, length):
    full_label = b"tls13 " + label
    hkdf_label = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label).derive(secret)


def initial_keys(dcid, version):
    # HKDF-Extract only (RFC 5869 Section 2.2): PRK = HMAC-Hash(salt, IKM).
    # cryptography's HKDF would also apply the expand step, which RFC 9001
    # does not want here.
    extract = hmac.HMAC(INITIAL_SALT[version], hashes.SHA256())
    extract.update(dcid)
    initial_secret = extract.finalize()
    client_secret = hkdf_expand_label(
        initial_secret, b"client in", b"", hashes.SHA256.digest_size
    )
    return (
        hkdf_expand_label(client_secret, KEY_LABELS[version], b"", 16),
        hkdf_expand_label(client_secret, IV_LABELS[version], b"", 12),
        hkdf_expand_label(client_secret, HP_LABELS[version], b"", 16),
    )


def varint(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def client_hello(host):
    name = host.encode()
    name_list = bytes([0]) + len(name).to_bytes(2, "big") + name
    sni_ext = (
        (0).to_bytes(2, "big")
        + (len(name_list) + 2).to_bytes(2, "big")
        + len(name_list).to_bytes(2, "big")
        + name_list
    )
    versions_ext = (43).to_bytes(2, "big") + (3).to_bytes(2, "big") + bytes([2, 3, 4])
    exts = sni_ext + versions_ext
    body = (
        bytes([3, 3])  # legacy_version
        + bytes(range(32))  # random
        + bytes([0])  # session id
        + (2).to_bytes(2, "big")
        + bytes([0x13, 0x01])  # TLS_AES_128_GCM_SHA256
        + bytes([1, 0])  # null compression
        + len(exts).to_bytes(2, "big")
        + exts
    )
    return bytes([1]) + len(body).to_bytes(3, "big") + body


def build_initial(dcid, scid, hello, version=1):
    key, iv, hp = initial_keys(dcid, version)

    # CRYPTO frame: type 0x06, offset 0, length, data.
    payload = bytes([0x06]) + varint(0) + varint(len(hello)) + hello

    packet_number = 0
    pn = packet_number.to_bytes(4, "big")
    header = (
        bytes([0xC3])  # long header, fixed bit, Initial type, pn_len - 1 = 3
        + WIRE_VERSION[version].to_bytes(4, "big")
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + varint(0)  # token length
    )
    # The length field is a 2-byte varint for these sizes (< 16384).
    hdr_len = len(header) + 2

    # Clients must pad Initial datagrams to 1200 bytes (RFC 9000 Sect. 14.1).
    min_payload = MIN_INITIAL_DATAGRAM - hdr_len - len(pn) - AES_GCM_TAG_LEN
    if len(payload) < min_payload:
        payload += bytes(min_payload - len(payload))  # PADDING frames

    header += varint(len(pn) + len(payload) + AES_GCM_TAG_LEN)

    nonce = bytes(a ^ b for a, b in zip(iv, pn.rjust(12, b"\0")))
    ciphertext = AESGCM(key).encrypt(nonce, payload, header + pn)
    packet = bytearray(header + pn + ciphertext)

    sample = bytes(packet[hdr_len + 4 : hdr_len + 20])
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    packet[0] ^= mask[0] & 0x0F
    for i in range(4):
        packet[hdr_len + i] ^= mask[1 + i]
    return bytes(packet)


def main():
    target, port, host = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    version = int(sys.argv[4][1]) if len(sys.argv) > 4 else 1
    packet = build_initial(b"rfor-e2e-dcid", b"e2e", client_hello(host), version)
    assert len(packet) >= MIN_INITIAL_DATAGRAM
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (target, port))
    print(f"sent QUIC v{version} Initial for {host} to {target}:{port} ({len(packet)} bytes)")


if __name__ == "__main__":
    main()
