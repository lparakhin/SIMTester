"""Port of de.srlabs.simlib.TLVToolkit."""

from __future__ import annotations

from . import debug as _debug
from .logging_utils import format_debug_message
from . import hex_toolkit as hx

DEBUG = _debug.DEBUG


def get_tlv(tlv: bytes, tag: int, start_tlv: int | None = None) -> bytes | None:
    """Find a (tag, len, value) TLV entry inside a flat TLV byte stream.

    Mirrors TLVToolkit.getTLV(byte[] tlv, byte tag, byte start_tlv): starting
    from `start_tlv` (defaults to `tag`), walk sibling TLVs until `tag` is
    found (or the stream is exhausted).
    """
    if start_tlv is None:
        start_tlv = tag

    if tlv is None or len(tlv) < 1:
        raise ValueError(f"Invalid TLV. tlv={hx.to_string(tlv)}")

    if _debug.DEBUG:
        print(format_debug_message(f"TLV byte array: {hx.to_string(tlv)}, looking for tag {hx.to_string(tag)}"))

    pos = 0
    result = None

    while pos < len(tlv):
        c = tlv[pos]
        pos += 1

        if c == (start_tlv & 0xFF):
            if _debug.DEBUG:
                print(format_debug_message(f"Reading TLV (tag={hx.to_string(c)})"))

            if pos >= len(tlv):
                break

            length = tlv[pos]
            pos += 1

            result = bytes([start_tlv & 0xFF, length]) + tlv[pos:pos + length]
            pos += length

            if (start_tlv & 0xFF) == (tag & 0xFF):
                break

            if pos >= len(tlv):
                return None

            start_tlv = tlv[pos]
        # on mismatch `pos` was already advanced by 1 above; the Java version
        # just keeps scanning byte-by-byte for the next occurrence of start_tlv

    return result
