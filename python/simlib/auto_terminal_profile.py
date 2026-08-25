"""Port of de.srlabs.simlib.AutoTerminalProfile."""

from __future__ import annotations

import sys

from . import config
from . import debug as _debug
from . import hex_toolkit as hx
from .apdu import CommandAPDU
from .channel_handler import ChannelHandler
from .logging_utils import format_debug_message


class AutoTerminalProfile:
    @staticmethod
    def auto_terminal_profile() -> bool:
        if _debug.DEBUG:
            print()
            print(format_debug_message("Starting automatic Terminal Profile initialization"))
            print()

        prefix = "80" if config.third_gen_apdu else "A0"
        ba_command_apdu = hx.from_string(prefix + "10000011FF9FFFFFFF0F1FFF7F0300002008200000")

        if _debug.DEBUG:
            print(format_debug_message(f"Sending TERMINAL PROFILE APDU: {hx.to_string(ba_command_apdu)}"))
            print()

        r = ChannelHandler.transmit_on_default_channel(CommandAPDU(ba_command_apdu))

        while (r.get_sw1() != 0x90 and r.get_sw2() != 0x00) or len(r.get_data()) > 0:
            r = AutoTerminalProfile.handle_response(r)

        return True

    @staticmethod
    def handle_response(response):
        from . import apdu_toolkit

        if response.get_sw1() == 0x91:
            return apdu_toolkit.perform_fetch(response.get_sw2())
        if len(response.get_data()) > 0 and response.get_data()[0] == 0xD0:
            return AutoTerminalProfile.handle_proactive_command(response)

        raise RuntimeError(f"There was a problem while doing automatic Terminal Profile; Unidentifiable response was: {hx.to_string(response.get_bytes())}")

    @staticmethod
    def handle_proactive_command(response):
        from .proactive_command import ProactiveCommand

        try:
            pc = ProactiveCommand(response)
        except ValueError:
            print("Unable to parse ProactiveCommand, sending fake (zero length) TERMINAL RESPONSE, this may get ugly!", file=sys.stderr)

            cla = 0x80 if config.third_gen_apdu else 0xA0
            tr_apdu = CommandAPDU(cla, 0x14, 0x00, 0x00, hx.from_string("810301000082028281830100"))
            return ChannelHandler.transmit_on_default_channel(tr_apdu)

        pc_command_details = pc.get_command_details()
        data = pc.get_bytes()

        tr_device_identities = bytes([0x82, 0x02, 0x82, 0x81])
        tr_result_successful = bytes([0x83, 0x01, 0x00])

        tr_data = bytearray(pc_command_details + tr_device_identities + tr_result_successful)

        from . import tlv_toolkit

        if pc_command_details[0] == 0x81 and len(pc_command_details) == 5 and pc_command_details[3] == 0x03:
            # POLL INTERVAL detected
            poll_interval = tlv_toolkit.get_tlv(data, 0x84)
            if poll_interval is None:
                poll_interval = tlv_toolkit.get_tlv(data, 0x04)
                if poll_interval is None:
                    raise RuntimeError("handleProactiveCommand: failure during POLL INTERVAL proactive command handling, DEBUG THIS!")
            if len(poll_interval) == 4:
                tr_data = bytearray(pc_command_details + tr_device_identities + tr_result_successful + poll_interval)

        # debug loc info
        if pc_command_details[0] == 0x81 and len(pc_command_details) == 5 and pc_command_details[3] == 0x26:
            if pc_command_details[4] == 0x00:
                loc_info = bytes([0x13, 0x4, 0x11, 0x22, 0x33, 0x44])
                tr_data = bytearray(pc_command_details + tr_device_identities + tr_result_successful + loc_info)
            elif pc_command_details[4] == 0x01:
                imei = bytes([0x14, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
                tr_data = bytearray(pc_command_details + tr_device_identities + tr_result_successful + imei)

        cla = 0x80 if config.third_gen_apdu else 0xA0
        tr_apdu = CommandAPDU(cla, 0x14, 0x00, 0x00, bytes(tr_data))

        if _debug.DEBUG:
            print(format_debug_message(f"handleProactiveCommand: terminal response complete APDU: {hx.to_string(tr_apdu.get_bytes())}"))
            print()

        return ChannelHandler.transmit_on_default_channel(tr_apdu)
