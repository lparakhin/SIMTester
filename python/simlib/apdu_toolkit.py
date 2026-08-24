"""Port of de.srlabs.simlib.APDUToolkit."""

from __future__ import annotations

import sys

from . import debug as _debug
from . import hex_toolkit as hx
from .apdu import CommandAPDU, ResponseAPDU
from .channel_handler import ChannelHandler
from .logging_utils import format_debug_message

APPLET_INSTALL_LOAD = 0x2
APPLET_INSTALL_INSTALL = 0x4
APPLET_INSTALL_MAKE_SELECTABLE = 0x8
APPLET_INSTALL_INSTALL_AND_MAKE_SELECTABLE = 0xC
APPLET_DELETE_PACKAGE = 0x0
APPLET_DELETE_INSTANCE = 0x1
APPLET_DELETE_PACKAGE_AND_ALL_INSTANCES = 0x2


def perform_fetch(count: int) -> ResponseAPDU:
    from . import config

    if _debug.DEBUG:
        print(format_debug_message(f"Fetching {count} bytes"))

    cla = 0x80 if config.third_gen_apdu else 0xA0
    fetch_apdu = CommandAPDU(cla, 0x12, 0x00, 0x00, count)

    r = ChannelHandler.transmit_on_default_channel(fetch_apdu)
    if _debug.DEBUG:
        print(format_debug_message(f"Fetched: {hx.to_string(r.get_bytes())}"))
    return r


def get_response(count: int) -> ResponseAPDU:
    from . import config

    if _debug.DEBUG:
        print(format_debug_message(f"Getting response: {count} bytes"))

    cla = 0x00 if config.third_gen_apdu else 0xA0
    get_response_apdu = CommandAPDU(cla, 0xC0, 0x00, 0x00, count)

    r = ChannelHandler.transmit_on_default_channel(get_response_apdu)
    if _debug.DEBUG:
        print(format_debug_message(f"Got response: {hx.to_string(r.get_bytes())}"))
    return r


def run_gsm_algo_2g(rand: bytes) -> ResponseAPDU:
    from .file_management import FileManagement

    FileManagement.select_path("3F007F20")
    cmd = CommandAPDU(0xA0, 0x88, 0x00, 0x00, rand)
    return ChannelHandler.transmit_on_default_channel(cmd)


def authenticate(gsm: bool, challenge: bytes) -> ResponseAPDU:
    p2 = 0x80  # specific reference data (DF specific / application dependent key)
    p2 |= 0x00 if gsm else 0x01  # GSM context vs 3G context (requires AUTN in challenge)
    cmd = CommandAPDU(0x00, 0x88, 0x00, p2, challenge)
    return ChannelHandler.transmit_on_default_channel(cmd)


def send_status() -> ResponseAPDU:
    from . import config

    cla = 0x00 if config.third_gen_apdu else 0xA0
    status_apdu = CommandAPDU(cla, 0xF2, 0x00, 0x00, 0x00)
    response = ChannelHandler.transmit_on_default_channel(status_apdu)

    if response.get_sw1() == 0x67:
        status_apdu = CommandAPDU(cla, 0xF2, 0x00, 0x00, response.get_sw2())
        response = ChannelHandler.transmit_on_default_channel(status_apdu)

    return response


def generate_applet_install(type_: int, package_aid: str, instance_aid: str, tar: str | None) -> bytes:
    from . import config

    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)

    apdu_header = bytes([0x80, 0xE6, type_ & 0xFF, 0x00])

    if type_ == APPLET_INSTALL_LOAD:
        strdata = hx.to_string(len(package_aid) // 2) + package_aid
        strdata += "00000" "6EF04C6020000" "00".replace(" ", "")
        strdata_bytes = hx.from_string(strdata)
        data = apdu_header + bytes([len(strdata_bytes) & 0xFF]) + strdata_bytes

    elif type_ == APPLET_INSTALL_INSTALL_AND_MAKE_SELECTABLE:
        system_parameters = "C80200" "00C70200" "00".replace(" ", "")
        system_parameters += "CA0601" "00FF00" "0000".replace(" ", "")
        end = "C900".replace(" ", "")  # last 00 is length of the (absent) install token

        aids = hx.to_string(len(package_aid) // 2) + package_aid
        if tar and len(tar) == 6:  # hex-encoded 3-byte TAR
            aids += hx.to_string(len(instance_aid) // 2 + 3) + instance_aid + tar
        else:
            aids += hx.to_string(len(instance_aid) // 2) + instance_aid
        aids += "0100".replace(" ", "")

        strdata = aids + hx.to_string(2 + len(system_parameters) // 2 + len(end) // 2) + "EF"
        strdata += hx.to_string(len(system_parameters) // 2) + system_parameters + end + "00"

        strdata_bytes = hx.from_string(strdata)
        data = apdu_header + bytes([len(strdata_bytes) & 0xFF]) + strdata_bytes

    else:
        raise ValueError(f"Unsupported install APDU type: {type_}")

    if _debug.DEBUG:
        print(format_debug_message(f"generated data: {hx.to_string(data)}"))

    return data


def generate_applet_delete(type_: int, package_aid: str, instance_aid: str, tar: str | None) -> bytes:
    from . import config

    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)

    apdu_header = bytes([0x80, 0xE4, 0x00])

    if type_ == APPLET_DELETE_PACKAGE:
        strdata = "00"  # P2 - 00h: delete object
        strdata += hx.to_string(len(package_aid) // 2 + 2)
        strdata += "4F"
        strdata += hx.to_string(len(package_aid) // 2)
        strdata += package_aid

    elif type_ == APPLET_DELETE_INSTANCE:
        strdata = "00"
        if tar and len(tar) == 6:
            strdata += hx.to_string(len(instance_aid) // 2 + 2 + 3)
            strdata += "4F"
            strdata += hx.to_string(len(instance_aid) // 2 + 3)
            strdata += instance_aid + tar
        else:
            strdata += hx.to_string(len(instance_aid) // 2 + 2)
            strdata += "4F"
            strdata += hx.to_string(len(instance_aid) // 2)
            strdata += instance_aid

    elif type_ == APPLET_DELETE_PACKAGE_AND_ALL_INSTANCES:
        strdata = "80"  # P2 - 80h: delete object and related object(s)
        strdata += hx.to_string(len(package_aid) // 2 + 2)
        strdata += "4F"
        strdata += hx.to_string(len(package_aid) // 2)
        strdata += package_aid

    else:
        raise ValueError(f"Unsupported delete APDU type: {type_}")

    data = apdu_header + hx.from_string(strdata)

    if _debug.DEBUG:
        print(format_debug_message(f"generated data: {hx.to_string(data)}"))

    return data


def generate_applet_load(cap_file_path: str) -> list[str]:
    from . import config

    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)

    with open(cap_file_path, "rb") as f:
        cap_data = f.read()

    number_bytes = len(cap_data)
    if _debug.DEBUG:
        print(format_debug_message(f"reading {number_bytes} bytes from {cap_file_path}"))
        print(format_debug_message(f"file read: {hx.to_string(cap_data)}"))

    one_part = 60
    parts = (number_bytes + one_part - 1) // one_part

    if _debug.DEBUG:
        print(format_debug_message(f"total bytes: {number_bytes}; one_part: {one_part}; parts: {parts}"))

    output = []
    used_data = 0

    for i in range(parts):
        is_last = (i + 1 == parts)

        header = bytearray(5)
        header[0] = 0x80
        header[1] = 0xE8
        header[2] = 0x80 if is_last else 0x00
        header[3] = i & 0xFF

        if i == 0:
            if number_bytes <= 127:
                lv = bytes([0xC4, number_bytes])
                take = one_part - 2
            elif number_bytes <= 255:
                lv = bytes([0xC4, 0x81, number_bytes])
                take = one_part - 3
            else:
                lv = bytes([0xC4, 0x82, (number_bytes >> 8) & 0xFF, number_bytes & 0xFF])
                take = one_part - 4
            chunk = lv + cap_data[used_data:used_data + take]
            used_data += take
        elif is_last:
            chunk = cap_data[used_data:]
            used_data += len(chunk)
        else:
            chunk = cap_data[used_data:used_data + one_part]
            used_data += one_part

        header[4] = len(chunk) & 0xFF
        apdu = bytes(header) + chunk

        if _debug.DEBUG:
            print(format_debug_message(f"data generated: {hx.to_string(apdu)}"))

        output.append(hx.to_string(apdu))

    return output
