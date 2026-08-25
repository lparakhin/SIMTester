"""Port of de.srlabs.simlib.SMSTPDU."""

from __future__ import annotations

from . import config

_TAG_GSM = 0x0B
_TAG_3G = 0x8B


class SMSTPDU:
    def __init__(self, tpdu: bytes | None = None):
        self._tpdu = b""
        if tpdu is not None:
            self.set_tpdu(tpdu)

    def get_length(self) -> int:
        return len(self._tpdu)

    def get_tpdu(self) -> bytes:
        return self._tpdu

    def set_tpdu(self, tpdu: bytes):
        self._tpdu = bytes(tpdu)

    def get_bytes(self) -> bytes:
        tag = _TAG_3G if config.third_gen_apdu else _TAG_GSM
        return bytes([tag, len(self._tpdu) & 0xFF]) + self._tpdu
