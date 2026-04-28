from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time


def to_hex(data: bytes | bytearray | None) -> str:
    if not data:
        return ""
    return bytes(data).hex().upper()


def from_hex(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)


@dataclass(frozen=True)
class CommandPacketView:
    tar: bytes
    keyset: int
    payload: bytes


@dataclass(frozen=True)
class ResponsePacketView:
    raw: bytes


class CSVWriter:
    def __init__(self, iccid: str, scan_type: str, logging: bool = True) -> None:
        self._logging = logging
        self._header_written = False
        self._path: Path | None = None
        self._fp = None
        if logging:
            self._path = Path(f".{scan_type}_{iccid}_{int(time.time() * 1000)}.csv")
            self._fp = self._path.open("w", encoding="utf-8")

    def write_basic_info(self, **fields: str | None) -> None:
        if not self._logging:
            return
        for k, v in fields.items():
            self._fp.write(f"{k}:{v}\n")
        self._fp.flush()

    def write_line(self, identifier: str, command_data: bytes, response_data: bytes) -> None:
        if not self._logging:
            return
        if not self._header_written:
            self._fp.write("# id,Command data,Response data\n")
            self._header_written = True
        self._fp.write(f"{identifier},{to_hex(command_data)},{to_hex(response_data)}\n")
        self._fp.flush()

    def write_raw_line(self, line_content: str) -> None:
        if self._logging:
            self._fp.write(line_content + "\n")
            self._fp.flush()

    def get_file_name(self) -> str:
        return self._path.name if self._path else ""

    def unhide_file(self) -> bool:
        if not self._logging or not self._path:
            return True
        if self._path.name.startswith("."):
            target = self._path.with_name(self._path.name[1:])
            self._fp.close()
            self._path.rename(target)
            self._path = target
            self._fp = self._path.open("a", encoding="utf-8")
        return True
