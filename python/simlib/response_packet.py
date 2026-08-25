"""Port of de.srlabs.simlib.ResponsePacket (TS 03.48 / TS 102.225 Response Packet)."""

from __future__ import annotations

import sys

from . import debug as _debug
from . import hex_toolkit as hx
from .logging_utils import format_debug_message

RPH = bytes([0x02, 0x71, 0x00])   # standard Response Packet Header
RPH2 = bytes([0x02, 0x7F, 0x00])  # proprietary Response Packet Header


class ResponsePacketParseError(ValueError):
    pass


def find_response_packet(data: bytes) -> bytes | None:
    offset = 0
    if len(data) > 2 and data[-2] == 0x90 and data[-1] == 0x00:
        offset = 2

    index = hx.index_of_byte_array_in_byte_array(data, RPH)
    if index != -1:
        return data[index:len(data) - offset]

    index = hx.index_of_byte_array_in_byte_array(data, RPH2)
    if index != -1:
        return data[index:len(data) - offset]

    return None


class Helpers:
    find_response_packet = staticmethod(find_response_packet)


class ResponsePacket:
    def __init__(self):
        self._rpl = bytearray(2)
        self._rhl = 0
        self._tar: bytes | None = None
        self._cntr: bytes | None = None
        self._pcntr = 0
        self._rsc = 0
        self._cc: bytes | None = None
        self._ard: bytes | None = None
        self._enc: bytes | None = None
        self._cc_present = False
        self._ard_present = False
        self._is_encrypted = False
        self._bytes: bytes | None = None
        self._original_counter = -1

    def parse(self, data: bytes, original_counter: int = -1, strict: bool = False):
        # Ignore processing if data is a Proactive command
        if len(data) > 0 and data[0] == 0xD0:
            self._bytes = data
            return

        if len(data) < 16:
            msg = (f"Data provided don't seem to be valid, data should be at least 16 bytes long for a "
                   f"valid ResponsePacket ({hx.to_string(data)})")
            if strict:
                raise ResponsePacketParseError(msg)
            print(format_debug_message(msg), file=sys.stderr)

        self._bytes = data
        self._original_counter = original_counter

        if data[0:3] == RPH2:
            if strict:
                raise ResponsePacketParseError("Proprietary RP found (0x027F00) -> SKIPPING for strict parsing..")
            self._rsc = data[18]
            print(format_debug_message(f"Proprietary RP found (0x027F00), bypassing everything, setting PoR code only: 0x{hx.to_string(self._rsc)}"))
            return
        elif data[0:3] == RPH:
            pass  # all good, standard PoR code
        else:
            possible_rp = find_response_packet(data)

            if possible_rp is not None:
                self._bytes = data = possible_rp
                if data[0:3] == RPH2 and strict:
                    raise ResponsePacketParseError("Proprietary RP found (0x027F00) -> SKIPPING for strict parsing..")
            else:
                msg = f"Response Packet Header (RPH) not found in the data provided! Your RPH is: {hx.to_string(data[0:3])}"
                if strict:
                    raise ResponsePacketParseError(msg)
                print(format_debug_message(msg), file=sys.stderr)

        rp_length = len(data) - len(RPH) - len(self._rpl)
        rpl_data_length = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF)

        if rp_length > rpl_data_length:
            msg = (f"Response packet length (RPL) doesn't correspond with the actual data length; "
                   f"real length = {rp_length}; RPL = {rpl_data_length}; cutting according to RPL.")
            if strict:
                if _debug.DEBUG:
                    print(format_debug_message(msg))
            else:
                print(format_debug_message(msg), file=sys.stderr)
            self._bytes = data = self._bytes[0:rpl_data_length + len(RPH) + len(self._rpl)]
        elif rp_length < rpl_data_length:
            msg = f"Not enough data! RPL = {rpl_data_length}, real data length: {rp_length}"
            if strict:
                raise ResponsePacketParseError(msg)
            print(format_debug_message(msg + ", trying to set RPL and RPH based on real length and continue, this may get ugly"), file=sys.stderr)
            self._rpl[0] = (rp_length >> 8) & 0xFF
            self._rpl[1] = rp_length & 0xFF
            rpl_data_length = rp_length
            self._rhl = (rp_length - 1) & 0xFF
        else:
            self._rpl[0] = data[3]
            self._rpl[1] = data[4]
            self._rhl = data[5]

        if self._rhl > (rpl_data_length - 1):
            msg = "RHL is more than RPL-1 .. something is really weird with this ResponsePacket, skipping further parsing!"
            if strict:
                raise ResponsePacketParseError(msg)
            print(format_debug_message(msg), file=sys.stderr)
            return

        if self._rhl in (10, 18):
            self._tar = data[6:9]
            self._cntr = data[9:14]
            self._pcntr = data[14]
            self._rsc = data[15]
            if self._rhl == 18:
                self._cc = data[16:24]
                self._cc_present = True
        else:
            msg = (f"Unexpected Response Header Length (RHL), should be 10 bytes without a CC or 18 bytes "
                   f"with a CC, current value: {self._rhl}")
            if strict:
                raise ResponsePacketParseError(msg)
            print(format_debug_message(msg), file=sys.stderr)

        if self._pcntr > (rpl_data_length - self._rhl - 1):
            self._pcntr = 0  # PCNTR is probably encrypted and therefore bullshit
        else:
            padding_bytes_are_zeros = all(data[16 + i] == 0x00 for i in range(self._pcntr))
            if not padding_bytes_are_zeros:
                self._pcntr = 0  # padding does not fit the padding counter (PCNTR)

        if (rpl_data_length - self._pcntr - self._rhl) > 1:
            self._ard_present = True
            additional_data_length = rpl_data_length - self._pcntr - self._rhl - 1
            start = 24 if self._cc_present else 16
            self._ard = data[start:start + additional_data_length]

        if original_counter != -1:
            # ARD must be present because otherwise CNTR might not equal origCNTR if
            # encryption was used on the command packet
            if original_counter != self.get_counter() and self.are_additional_data_present():
                self._is_encrypted = True
                self._ard = None
                self._enc = data[9:]

    def get_bytes(self) -> bytes | None:
        return self._bytes

    def is_cryptographic_checksum_present(self) -> bool:
        return self._cc_present

    def get_cryptographic_checksum(self) -> bytes:
        if not self.is_cryptographic_checksum_present():
            raise RuntimeError("Cryptographic checksum is not present, you can't get it!")
        return self._cc

    def get_encrypted_payload(self) -> bytes:
        if not self.is_encrypted():
            raise RuntimeError("ResponsePacket is not encrypted, no encrypted payload present!")
        return self._enc

    def get_status_code(self) -> int:
        return self._rsc

    def get_tar(self) -> bytes | None:
        return self._tar

    def is_encrypted(self) -> bool:
        if self._original_counter == -1:
            raise RuntimeError("Cannot determine if ResponsePacket is encrypted as original counter from CP was not provided, fix your code!")
        return self._is_encrypted

    def get_counter(self) -> int:
        return hx.byte_array_to_long(self._cntr)

    def get_padding_counter(self) -> int:
        return self._pcntr

    def are_additional_data_present(self) -> bool:
        return self._ard_present

    def get_additional_data(self) -> bytes | None:
        return self._ard

    def is_decrypted_counter(self) -> bool:
        response_counter = self.get_counter()
        status_code = self.get_status_code()

        if response_counter in (0, 1):
            return False  # these counter values indicate no decryption was performed

        # the response is encrypted, this should not be confused with a decrypted counter
        if len(self._bytes) == 17 or self._pcntr != 0x00 or status_code < 0 or status_code > 0x0D:
            return False

        return True
