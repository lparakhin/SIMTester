"""Port of de.srlabs.simlib.HexToolkit."""

from __future__ import annotations


def from_string(byte_string: str) -> bytes:
    """Parse a hex string (e.g. "A0A4") into bytes."""
    return bytes.fromhex(byte_string)


def from_string_to_single_byte(byte_string: str) -> int:
    return int(byte_string, 16) & 0xFF


def to_string(data, offset: int = None, length: int = None) -> str | None:
    """Mirrors the overloaded HexToolkit.toString() family.

    - to_string(None) -> None
    - to_string(bytes) -> full hex string
    - to_string(bytes, offset, length) -> hex string of a slice
    - to_string(int) -> hex string of a single byte (0-255)
    """
    if data is None:
        return None

    if isinstance(data, int):
        if data > 255 or data < -128:
            raise ValueError("This is not implemented yet, only i < 255 is convertable for now!")
        return to_hex_string(data & 0xFF, 1)

    if offset is None and length is None:
        return data.hex().upper()

    if offset is None:
        offset = 0
    if length is None:
        length = len(data) - offset

    return data[offset:offset + length].hex().upper()


def to_hex_string(value: int, length: int) -> str:
    result = format(value, "x").upper()
    return result.rjust(2 * length, "0")


def to_text(data: bytes) -> str:
    return "".join(chr(b) for b in data)


def swap(value: int) -> int:
    """Nibble swap for a single byte."""
    value &= 0xFF
    return ((value & 0x0F) << 4 | (value & 0xF0) >> 4) & 0xFF


def strip_chars(input_str: str) -> str:
    return "".join(c for c in input_str if c.isdigit())


def is_bit_set(value: int, bitindex: int, startbit: int = 0) -> bool:
    value &= 0xFF
    return (value & (1 << (bitindex - startbit))) != 0


def print_byte_as_bits(value: int) -> str:
    return "".join("1" if is_bit_set(value, i) else "0" for i in range(7, -1, -1))


def is_byte_array_null_bytes_only(bytearray_: bytes) -> bool:
    if bytearray_ is None:
        return False
    return all(b == 0 for b in bytearray_)


def index_of_byte_array_in_byte_array(data: bytes, pattern: bytes) -> int:
    """KMP substring search, returns -1 if not found (mirrors the Java impl)."""
    if len(data) == 0:
        return -1

    failure = _compute_failure(pattern)
    j = 0
    for i in range(len(data)):
        while j > 0 and pattern[j] != data[i]:
            j = failure[j - 1]
        if pattern[j] == data[i]:
            j += 1
        if j == len(pattern):
            return i - len(pattern) + 1
    return -1


def _compute_failure(pattern: bytes):
    failure = [0] * len(pattern)
    j = 0
    for i in range(1, len(pattern)):
        while j > 0 and pattern[j] != pattern[i]:
            j = failure[j - 1]
        if pattern[j] == pattern[i]:
            j += 1
        failure[i] = j
    return failure


def compare_tars(left: bytes, right: bytes) -> int:
    if len(left) > 3 or len(right) > 3:
        raise ValueError("Unable to compare TARs as they're bigger than 3 bytes, this should never happen, report a bug.")
    return byte_array_to_long(left) - byte_array_to_long(right)


def byte_array_to_long(ba: bytes) -> int:
    value = 0
    for b in ba:
        value = (value << 8) + (b & 0xFF)
    return value
