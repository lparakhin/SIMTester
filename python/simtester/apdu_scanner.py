"""Port of de.srlabs.simtester.APDUScanner."""

from __future__ import annotations

import threading

from simlib import apdu_toolkit
from simlib import config
from simlib import hex_toolkit as hx
from simlib.apdu import CommandAPDU
from simlib.auto_terminal_profile import AutoTerminalProfile
from simlib.channel_handler import ChannelHandler
from simlib.command_packet import CommandPacket
from simlib.logging_utils import format_debug_message
from simlib.ota_sms import OTASMS
from simlib.response_packet import ResponsePacket, ResponsePacketParseError, find_response_packet


def run(ep, writer, via_ota: bool, level2: bool, stop_event: threading.Event | None = None):
    stop_event = stop_event or threading.Event()

    print()
    if ep is not None:
        print(f"Performing a {'LEVEL 2' if level2 else 'LEVEL 1'} APDU scan" + ("." if level2 else f" for TAR {hx.to_string(ep.tar)}."))
    else:
        print(f"Performing a {'LEVEL 2' if level2 else 'LEVEL 1'} APDU scan.")
    print()

    cp = ep.command_packet if via_ota else CommandPacket()
    otasms = OTASMS()

    for cla in range(0x100):
        if stop_event.is_set():
            break

        response_data = None

        if via_ota:
            cla_apdu = bytes([cla, 0x00, 0x00, 0x00, 0x00])
            cp.set_user_data(cla_apdu)
            otasms.set_command_packet(cp)
            cla_res = otasms.send()
            response_data = _get_response_data(cla_res)

            if not level2:
                writer.write_line(hx.to_string(ep.tar), cp.get_bytes(), response_data)

            if response_data is None:
                continue

            cla_sw = _get_sw_from_response_data(response_data)
            if cla_sw == 0xBAAD:
                continue
        else:
            cla_apdu = CommandAPDU(cla, 0x00, 0x00, 0x00, 0x00)
            cla_res = ChannelHandler.transmit_on_default_channel(cla_apdu)

            if not level2:
                writer.write_line("I/O", cla_apdu.get_bytes(), cla_res.get_bytes())

            cla_sw = cla_res.get_sw()

        if cla_sw in (0x6E00, 0x6881, 0x6882):
            continue

        print(f"Valid CLA found: {hx.to_string(cla)}, response was: 0x{cla_sw:04X}, response_data: {hx.to_string(response_data)}")

        if level2:
            for ins in range(0x100):
                if stop_event.is_set():
                    break

                ins_res = None
                response_data = None

                if via_ota:
                    ins_apdu = bytes([cla, ins, 0x00, 0x00, 0x00])
                    cp.set_user_data(ins_apdu)
                    otasms.set_command_packet(cp)
                    ins_res = otasms.send()
                    response_data = _get_response_data(ins_res)
                    writer.write_line(hx.to_string(ep.tar), cp.get_bytes(), response_data)
                    if response_data is None:
                        continue
                    ins_sw = _get_sw_from_response_data(response_data)
                    if ins_sw == 0xBAAD:
                        continue
                else:
                    ins_apdu = CommandAPDU(cla, ins, 0x00, 0x00, 0x00)
                    try:
                        ins_res = ChannelHandler.transmit_on_default_channel(ins_apdu)
                    except Exception:
                        writer.write_line("I/O", ins_apdu.get_bytes(), b"")
                        continue
                    writer.write_line("I/O", ins_apdu.get_bytes(), ins_res.get_bytes())

                if ins_res is None:
                    print(format_debug_message("ins_res is null -> This should never happened, report a bug!"))
                    continue

                ins_sw = ins_res.get_sw()

                if ins_sw == 0x6D00:
                    continue

                print(f"Valid APDU found: CLA({hx.to_string(cla)}), INS({hx.to_string(ins)}), response: 0x{ins_sw:04X}, response_data: {hx.to_string(response_data)}")

    print()
    if ep is not None:
        print("APDU scan has finished" + ("." if level2 else f" on TAR {hx.to_string(ep.tar)}."))
    else:
        print("APDU scan has finished.")


def _get_response_data(response) -> bytes | None:
    sw1 = response.get_sw1()

    if sw1 in (0x9E, 0x9F) or (config.third_gen_apdu and sw1 in (0x62, 0x61)):
        return apdu_toolkit.get_response(response.get_sw2()).get_data()

    if sw1 == 0x91:
        fetch_response = apdu_toolkit.perform_fetch(response.get_sw2())
        fetched_data = fetch_response.get_data()
        print(f"card responded with FETCH, fetched_data = {hx.to_string(fetched_data)}")

        if fetched_data and fetched_data[0] == 0xD0:
            print("first byte of fetch data is 0xD0, trying to handle the proactive command we fetched.. ")
            AutoTerminalProfile.handle_proactive_command(fetch_response)

        response_data = find_response_packet(fetched_data)
        if response_data is None:
            print("Unable to locate Response Packet Header in fetched data, skipping..")
            return None
        return response_data

    return None


def _get_sw_from_response_data(response_data: bytes | None) -> int:
    if response_data is None:
        return 0xBAAD

    rp = ResponsePacket()
    try:
        rp.parse(response_data)
    except ResponsePacketParseError as e:
        print("Parse exception while parsing response packet, skipping it! details:")
        print(e)
        return 0xBAAD

    if rp.get_status_code() == 0:
        if rp.are_additional_data_present():
            additional_data = rp.get_additional_data()
            if len(additional_data) == 3:
                return ((additional_data[1] << 8) | additional_data[2]) & 0xFFFF
            return 0xBAAD
        return 0xBAAD

    return 0xBAAD
