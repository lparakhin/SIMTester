"""Port of de.srlabs.simlib.InnerTLV.

TS 101 220, Section 7.1.2 length encoding for BER-TLV / COMPREHENSION-TLV.
"""

from __future__ import annotations


def get_inner_tlv(tag: int, data: bytes) -> bytes:
    length = len(data)

    if 0 <= length <= 127:
        header = bytes([tag & 0xFF, length])
    elif 128 <= length <= 255:
        header = bytes([tag & 0xFF, 0x81, length])
    elif 256 <= length <= 65535:
        header = bytes([tag & 0xFF, 0x82, (length >> 8) & 0xFF, length & 0xFF])
    elif 65536 <= length <= 16777215:
        header = bytes([tag & 0xFF, 0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    else:
        raise ValueError("length of data entered is not supported!")

    return header + data
