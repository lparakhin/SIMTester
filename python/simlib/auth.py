"""Port of de.srlabs.simlib.Auth."""

from __future__ import annotations

import sys

from . import config
from . import debug as _debug
from . import hex_toolkit as hx
from .apdu import CommandAPDU
from .channel_handler import ChannelHandler
from .file_management import FileManagement, FileNotFoundOnCard
from .logging_utils import format_debug_message


class CardAuthError(RuntimeError):
    pass


def _pin_data(pin: str) -> bytes:
    data = bytearray([0xFF] * 8)
    for i, c in enumerate(pin[:8]):
        data[i] = ord(c)
    return bytes(data)


def is_chv1_enabled() -> bool:
    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)

    try:
        file = FileManagement.select_path("3f00")
    except FileNotFoundOnCard:
        file = None

    if file is None:
        raise CardAuthError("Unable to read file 3F00, wtf?")

    return not hx.is_bit_set(file.get_raw_select_response_data()[13], 8)


def verify_chv(offset: int, pin: str) -> bool:
    if _debug.DEBUG:
        print()
        print(format_debug_message(f"verifyCHV: Verifying PIN/CHV; offset = {offset}; key/pin = {pin}"))

    pin_data = _pin_data(pin)
    cla = 0x00 if config.third_gen_apdu else 0xA0
    verify = CommandAPDU(cla, 0x20, 0x00, offset, pin_data)
    response = ChannelHandler.transmit_on_default_channel(verify)

    sw = response.get_sw()
    if sw == 0x9000:
        if _debug.DEBUG:
            print(format_debug_message("verifyCHV: verification successful"))
        return True
    if sw == 0x9804:
        raise CardAuthError("verifyCHV: Unsuccessful CHV verification at least one attempt left")
    if sw == 0x9840:
        raise CardAuthError("verifyCHV: PIN/CHV verification is unsuccessful, no further verification attempt allowed (PIN/CHV is BLOCKED)")
    if sw in (0x9808, 0x6984):
        print("verifyCHV: PIN/CHV is disabled, we don't need to authenticate on this card")
        return True
    raise CardAuthError(f"verifyCHV: something not expected has happened, SW = {sw:04x}")


def enable_chv1(pin: str) -> bool:
    if _debug.DEBUG:
        print(format_debug_message(f"enableCHV1: Enable PIN1/CHV1; key/pin = {pin}"))

    pin_data = _pin_data(pin)
    cla = 0x00 if config.third_gen_apdu else 0xA0
    enable = CommandAPDU(cla, 0x28, 0x00, 0x01, pin_data)
    response = ChannelHandler.transmit_on_default_channel(enable)

    sw = response.get_sw()
    if sw == 0x9000:
        if _debug.DEBUG:
            print(format_debug_message("enableCHV1: verification successful"))
        return True
    if sw == 0x9804:
        raise CardAuthError("enableCHV1: Unsuccessful CHV verification at least one attempt left")
    if sw == 0x9840:
        raise CardAuthError("enableCHV1: PIN/CHV verification is unsuccessful, no further verification attempt allowed (PIN/CHV is BLOCKED)")
    if sw == 0x9808:
        print("enableCHV1: PIN/CHV is already disabled, we can't disable it again")
        return True
    raise CardAuthError(f"enableCHV1: something not expected has happened, SW = {sw:04x}")


def disable_chv(offset: int, pin: str) -> bool:
    if _debug.DEBUG:
        print(format_debug_message(f"disableCHV: Disabling PIN/CHV; offset = {offset}; key/pin = {pin}"))

    pin_data = _pin_data(pin)
    cla = 0x00 if config.third_gen_apdu else 0xA0
    disable = CommandAPDU(cla, 0x26, 0x00, offset, pin_data)
    response = ChannelHandler.transmit_on_default_channel(disable)

    sw = response.get_sw()
    if sw == 0x9000:
        if _debug.DEBUG:
            print(format_debug_message("disableCHV: verification successful"))
        return True
    if sw == 0x9804:
        raise CardAuthError("disableCHV: Unsuccessful CHV verification at least one attempt left")
    if sw == 0x9840:
        raise CardAuthError("disableCHV: PIN/CHV verification is unsuccessful, no further verification attempt allowed (PIN/CHV is BLOCKED)")
    if sw == 0x9808:
        print("disableCHV: PIN/CHV is already disabled, we can't disable it again")
        return True
    raise CardAuthError(f"disableCHV: something not expected has happened, SW = {sw:04x}")
