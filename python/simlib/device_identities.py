"""Port of de.srlabs.simlib.DeviceIdentities."""

from __future__ import annotations


class DeviceIdentities:
    TYPE_GSM = 0x02
    TYPE_3G = 0x82
    DI_UICC = 0x81
    DI_TERMINAL = 0x82
    DI_NETWORK = 0x83

    _LENGTH = 0x02

    def __init__(self, source: int, destination: int, type_: int = TYPE_GSM):
        self._type = type_
        self._source = source
        self._destination = destination

    def get_bytes(self) -> bytes:
        return bytes([self._type & 0xFF, self._LENGTH, self._source & 0xFF, self._destination & 0xFF])

    def get_source(self) -> int:
        return self._source

    def get_destination(self) -> int:
        return self._destination

    def get_length(self) -> int:
        return self._LENGTH
