"""Port of de.srlabs.simlib.Address (only the raw-bytes constructor is implemented
upstream, TON/NPI/dialing-number based construction raises "not yet implemented")."""

from __future__ import annotations


class Address:
    TYPE_GSM = 0x06
    TYPE_3G = 0x86

    def __init__(self, raw_data: bytes):
        self._type = self.TYPE_GSM
        if len(raw_data) <= 4:
            raise ValueError("rawData are shorter than TAG+LENGTH+TON_NPI+DIALINGSTRING")

        if raw_data[0] not in (self.TYPE_GSM, self.TYPE_3G):
            raise ValueError("rawData don't start with a correct tag!")

        self._type = raw_data[0]

        if raw_data[1] != len(raw_data) - 2:
            raise ValueError("rawData don't correspond with a length entered as 2nd byte!")

        self._length = raw_data[1]
        self._ton_npi = raw_data[2]
        self._dialing_string = raw_data[3:]

    def get_dialing_string(self) -> bytes:
        return self._dialing_string

    def get_bytes(self) -> bytes:
        return bytes([self._type, self._length, self._ton_npi]) + self._dialing_string

    def get_length(self) -> int:
        return self._length
