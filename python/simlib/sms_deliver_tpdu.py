"""Port of de.srlabs.simlib.SMSDeliverTPDU (TS 23.040, 9.2.2.1 SMS-DELIVER)."""

from __future__ import annotations

from . import debug as _debug
from . import hex_toolkit as hx
from .logging_utils import format_debug_message


class SMSDeliverTPDU:
    _TPMTI = 0x0
    _TPMTI_MASK = 0x3

    _TPMMS_MASK = 0x4
    _TPLP_MASK = 0x8
    _TPSRI_MASK = 0x20
    _TPUDHI_MASK = 0x40
    _TPRP_MASK = 0x80

    def __init__(self):
        self._tpmms = 0x4  # no more messages waiting, by default
        self._tplp = 0x0
        self._tpsri = 0x0
        self._tpudhi = 0x0
        self._tprp = 0x0

        # number of nibbles, TON_NPI byte, nibbles data
        self._tpoa = bytes([0x05, 0x00, 0x21, 0x43, 0xF5])
        self._tppid = 0x7F  # (U)SIM Data download
        self._tpdcs = 0xF6
        self._tpscts = bytes(7)
        self._tpudl = 0x00
        self._tpud = b""

    def get_tpmms(self) -> bool:
        return not hx.is_bit_set(self._tpmms, 2)

    def set_tpmms(self, more_messages_waiting: bool):
        self._tpmms = 0x0 if more_messages_waiting else 0x4

    def get_tplp(self) -> bool:
        return not hx.is_bit_set(self._tplp, 3)

    def set_tplp(self, has_been_forwarded: bool):
        self._tplp = 0x8 if has_been_forwarded else 0x0

    def get_tpsri(self) -> bool:
        return not hx.is_bit_set(self._tpsri, 5)

    def set_tpsri(self, status_report_shall_be_returned: bool):
        self._tpsri = 0x20 if status_report_shall_be_returned else 0x0

    def get_tpudhi(self) -> bool:
        return hx.is_bit_set(self._tpudhi, 6)

    def set_tpudhi(self, contains_user_data_header: bool):
        self._tpudhi = 0x40 if contains_user_data_header else 0x0

    def get_tprp(self) -> bool:
        # NOTE: mirrors a pre-existing bug in the Java source, which checks
        # TPLP instead of TPRP here.
        return hx.is_bit_set(self._tplp, 7)

    def set_tprp(self, reply_path_is_set: bool):
        self._tprp = 0x80 if reply_path_is_set else 0x0

    def get_first_octet(self) -> int:
        return ((self._TPMTI & self._TPMTI_MASK)
                | (self._tpmms & self._TPMMS_MASK)
                | (self._tplp & self._TPLP_MASK)
                | (self._tpsri & self._TPSRI_MASK)
                | (self._tpudhi & self._TPUDHI_MASK)
                | (self._tprp & self._TPRP_MASK)) & 0xFF

    def set_first_octet(self, first_octet: int):
        self._tpmms = first_octet & self._TPMMS_MASK
        self._tplp = first_octet & self._TPLP_MASK
        self._tpsri = first_octet & self._TPSRI_MASK
        self._tpudhi = first_octet & self._TPUDHI_MASK
        self._tprp = first_octet & self._TPRP_MASK

    def get_tpoa(self) -> bytes:
        return self._tpoa

    def get_pid(self) -> int:
        return self._tppid

    def set_pid(self, pid: int):
        self._tppid = pid & 0xFF

    def get_dcs(self) -> int:
        return self._tpdcs

    def set_dcs(self, dcs: int):
        self._tpdcs = dcs & 0xFF

    def get_tpudl(self) -> int:
        return self._tpudl

    def set_fake_tpudl(self, length: int):
        self._tpudl = length & 0xFF

    def set_tpud(self, user_data: bytes):
        if _debug.DEBUG:
            print(format_debug_message(f"raw data: {hx.to_string(user_data)}"))
        self._tpud = bytes(user_data)
        self._tpudl = len(user_data) & 0xFF

    def get_bytes(self) -> bytes:
        return (bytes([self.get_first_octet()]) + self._tpoa
                + bytes([self._tppid, self._tpdcs]) + self._tpscts
                + bytes([self._tpudl]) + self._tpud)
