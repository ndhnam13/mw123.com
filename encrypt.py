#!/usr/bin/env python3
"""Create a CTF container from a PE file.

Pipeline:
  1. XOR everything after the PE section table with a byte derived from
     DOS.e_cblp and DOS.e_cp.
  2. RC4-encrypt the complete transformed PE.
  3. Store the RC4 key in a config blob XOR-obfuscated with 0x67.

This tool only transforms files; it does not execute the PE.
"""

from __future__ import annotations

import argparse
import secrets
import struct
import sys
from pathlib import Path


CONFIG_XOR_KEY = 0x67
RC4_KEY = b"12345678"
RC4_KEY_LENGTH = len(RC4_KEY)
CONFIG_SIZE = 128
KEY_OFFSET = 0x69


def rc4(data: bytes, key: bytes) -> bytes:
    if len(key) != RC4_KEY_LENGTH:
        raise ValueError("RC4 key must be exactly 8 bytes")

    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray(len(data))
    i = j = 0
    for n, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = value ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def patch_dos_fields(pe: bytes) -> bytes:
    if len(pe) < 0x40 or pe[:2] != b"MZ":
        raise ValueError("input is not a valid DOS/PE image")
    patched = bytearray(pe)
    # IMAGE_DOS_HEADER: e_cblp, e_cp and e_crlc.
    struct.pack_into("<HHH", patched, 0x02, 0x00AE, 0x0099, KEY_OFFSET)
    return bytes(patched)


def pe_metadata(pe: bytes) -> tuple[int, int]:
    if len(pe) < 0x40 or pe[:2] != b"MZ":
        raise ValueError("input is not a valid DOS/PE image")

    e_cblp, e_cp = struct.unpack_from("<HH", pe, 0x02)
    xor_key = (e_cblp ^ e_cp) & 0xFF
    pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]

    if pe_offset + 24 > len(pe) or pe[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature or e_lfanew")

    number_of_sections = struct.unpack_from("<H", pe, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", pe, pe_offset + 20)[0]
    section_table_end = pe_offset + 24 + optional_header_size + number_of_sections * 40
    if number_of_sections == 0 or section_table_end > len(pe):
        raise ValueError("invalid PE section table")

    return xor_key, section_table_end


def xor_tail(pe: bytes, start: int, key: int) -> bytes:
    transformed = bytearray(pe)
    for i in range(start, len(transformed)):
        transformed[i] ^= key
    return bytes(transformed)


def build_container(pe: bytes) -> bytes:
    pe = patch_dos_fields(pe)
    xor_key, section_table_end = pe_metadata(pe)
    stage_one = xor_tail(pe, section_table_end, xor_key)
    encrypted_pe = rc4(stage_one, RC4_KEY)

    # The blob is random noise except for the 8-byte RC4 key at DOS.e_crlc.
    config = bytearray(secrets.token_bytes(CONFIG_SIZE))
    config[KEY_OFFSET : KEY_OFFSET + RC4_KEY_LENGTH] = RC4_KEY
    encrypted_config = bytes(value ^ CONFIG_XOR_KEY for value in config)

    return encrypted_config + encrypted_pe


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt a PE")
    parser.add_argument("input", type=Path, help="input PE file")
    parser.add_argument("output", type=Path, help="output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pe = args.input.read_bytes()
        args.output.write_bytes(build_container(pe))
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
