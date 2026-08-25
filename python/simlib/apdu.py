"""Minimal re-implementation of javax.smartcardio.CommandAPDU / ResponseAPDU
on top of plain `bytes`, so the rest of the port can stay close to the
original Java call sites."""

from __future__ import annotations


class CommandAPDU:
    def __init__(self, *args):
        """Supports the constructor overloads actually used by SIMTester:

        - CommandAPDU(bytes_or_list)
        - CommandAPDU(cla, ins, p1, p2)
        - CommandAPDU(cla, ins, p1, p2, data_or_length)
        """
        if len(args) == 1:
            data = args[0]
            self._bytes = bytes(data)
            return

        cla, ins, p1, p2 = (int(a) & 0xFF for a in args[:4])

        if len(args) == 4:
            self._bytes = bytes([cla, ins, p1, p2])
            return

        payload = args[4]

        if isinstance(payload, int):
            # CommandAPDU(cla, ins, p1, p2, Ne) - a "case 2" APDU (no data,
            # expects `Ne` bytes back)
            ne = payload & 0xFF
            self._bytes = bytes([cla, ins, p1, p2, ne])
        else:
            data = bytes(payload)
            self._bytes = bytes([cla, ins, p1, p2, len(data) & 0xFF]) + data

    def get_bytes(self) -> bytes:
        return self._bytes

    def __repr__(self):
        return f"CommandAPDU({self._bytes.hex().upper()})"


class ResponseAPDU:
    def __init__(self, data):
        self._bytes = bytes(data)
        if len(self._bytes) < 2:
            raise ValueError("ResponseAPDU must be at least 2 bytes (SW1 SW2)")

    def get_bytes(self) -> bytes:
        return self._bytes

    def get_data(self) -> bytes:
        return self._bytes[:-2]

    def get_sw1(self) -> int:
        return self._bytes[-2]

    def get_sw2(self) -> int:
        return self._bytes[-1]

    def get_sw(self) -> int:
        return (self.get_sw1() << 8) | self.get_sw2()

    def __repr__(self):
        return f"ResponseAPDU({self._bytes.hex().upper()})"
