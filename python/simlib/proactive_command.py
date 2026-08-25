"""Port of de.srlabs.simlib.ProactiveCommand."""

from __future__ import annotations

from . import debug as _debug
from . import hex_toolkit as hx
from . import tlv_toolkit
from .logging_utils import format_debug_message

_TYPE_NAMES = {
    0x03: "POLL INTERVAL",
    0x05: "SET UP EVENT LIST",
    0x10: "SETUP CALL",
    0x11: "SEND SS",
    0x12: "SEND USSD",
    0x13: "SEND SHORT MESSAGE",
    0x20: "PLAY TONE",
    0x21: "DISPLAY TEXT",
    0x23: "GET INPUT",
    0x25: "SET UP MENU",
    0x26: "PROVIDE LOCAL INFORMATION",
}


class ProactiveCommand:
    def __init__(self, data):
        if hasattr(data, "get_data"):
            data = data.get_data()

        self._bytes = bytes(data)

        if self._bytes[0] != 0xD0:
            raise ValueError("data don't look like a valid Proactive command")

        if len(self._bytes) < (2 + 5 + 4):
            raise ValueError("Not enough data for mandatory fields")

        offset = 1 if self._bytes[1] == 0x81 else 2

        if (len(self._bytes) - offset) != self._bytes[1]:
            raise ValueError(f"data don't correspont with length (2nd byte); data dump -> {hx.to_string(self._bytes)}")

        if _debug.DEBUG:
            print(format_debug_message(f"Raw ProactiveCommand: {hx.to_string(self._bytes)} offset: {offset}"))

        if (self._bytes[offset] & 0x7F) != 0x01:
            raise ValueError(f"Unable to find COMMAND DETAILS TAG (0x81) at position {offset}, data: {hx.to_string(self._bytes)}")

        self._command_details = self._bytes[offset:offset + 5]

        if _debug.DEBUG:
            print(format_debug_message(f"Found Command details tag: {hx.to_string(self._command_details)}"))

        if (self._bytes[offset + 5] & 0x7F) != 0x02:
            raise ValueError(f"Unable to find DEVICE IDENTITIES TAG (0x82) at position {offset + 5}, data: {hx.to_string(self._bytes)}")

        self._device_identities = self._bytes[offset + 5:offset + 5 + 4]

        if _debug.DEBUG:
            print(format_debug_message(f"Found Device identities tag: {hx.to_string(self._device_identities)}"))
            print(format_debug_message(f"ProactiveCommand: {identify_proactive_command(self._command_details)}"))

    def get_command_details(self) -> bytes:
        return self._command_details

    def get_device_identities(self) -> bytes:
        return self._device_identities

    def get_bytes(self) -> bytes:
        return self._bytes

    def get_type(self) -> str:
        return identify_proactive_command(self._command_details)

    def get_summary(self) -> str:
        type_ = identify_proactive_command(self._command_details)
        summary = ""

        try:
            if type_ == "SEND SHORT MESSAGE":
                sms_tlv = tlv_toolkit.get_tlv(self._bytes, 0x8B, 0x81)
                if sms_tlv is None:
                    sms_tlv = tlv_toolkit.get_tlv(self._bytes, 0x0B, 0x81)
                sms_msg = sms_tlv[2:]
                summary = '"' + hx.to_string(sms_msg) + '"'
            elif type_ == "DISPLAY TEXT":
                dt_tlv = tlv_toolkit.get_tlv(self._bytes, 0x8D, 0x81)
                if dt_tlv is None:
                    dt_tlv = tlv_toolkit.get_tlv(self._bytes, 0x0D, 0x81)
                dt_data = dt_tlv[2:]
                dt_msg = dt_data[1:]  # strip the encoding byte
                summary = '"' + hx.to_text(dt_msg) + '"'
        except Exception:
            summary = "___ERROR DECODING PROACTIVE COMMAND___"

        return summary


def identify_proactive_command(command_details: bytes) -> str:
    if (command_details[0] & 0x7F) == 0x01 and len(command_details) == 5:
        return _TYPE_NAMES.get(command_details[3], f"NOT IDENTIFIED ({hx.to_string(command_details[3])})")
    return "NOT IDENTIFIED"
