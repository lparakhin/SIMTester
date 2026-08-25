"""Port of de.srlabs.simtester.OTAFuzzer."""

from __future__ import annotations

import datetime
import time

from simlib import debug as _debug
from simlib import hex_toolkit as hx
from simlib.auto_terminal_profile import AutoTerminalProfile
from simlib.helpers import handle_sim_response
from simlib.logging_utils import format_debug_message
from simlib.ota_sms import OTASMS

from . import fuzzer as fuzzer_module

_CPH_FUZZ_COUNT = 2


def fuzz_ota(keyset: int, tar: str, fuzzer, writer, bruteforce: bool):
    print()
    print("Starting OTA passthrough fuzzing (PID, DCS, UDHI, IEI/CPH)")
    print()
    print(f"Using the following values in packets: TAR = {tar}, keyset = {keyset}, fuzzer = {fuzzer.name}")
    print()

    if AutoTerminalProfile.auto_terminal_profile():
        if _debug.DEBUG:
            print(format_debug_message("Automatic Terminal profile initialization SUCCESSFUL!"))
    else:
        if _debug.DEBUG:
            print(format_debug_message("Automatic Terminal profile initialization FAILED!"))

    if bruteforce:
        pid_values = list(range(256))
        dcs_values = list(range(256))
    else:
        pid_values = [0, 65, 124, 127]
        dcs_values = [0, 22, 54, 86, 118, 150, 182, 214, 246]

    cph_values: list[str] = []
    for i in range(_CPH_FUZZ_COUNT + 1):
        cph_values.append(f"{2 + i:02X}{0x70:02X}{i:02X}" + "00" * i)

    cph_values.append("027100")  # standard security header for OTA response
    cph_values.append("027F00")  # non-standard security header
    cph_values.append("")        # no security header

    udhi_values = [False, True]

    loop_until = len(pid_values) * len(dcs_values) * len(cph_values) * len(udhi_values)
    start_time = time.time()
    loop = 0

    print(f"This scan will go over {loop_until} PID, DCS, UDHI, IEI/CPH.")
    print()

    writer.write_raw_line("# pid,dcs,udhi,cph,response")
    writer.write_raw_line(f"# msgs: {loop_until}")

    for pid in pid_values:
        for dcs in dcs_values:
            for cph in cph_values:
                for udhi in udhi_values:

                    if loop == loop_until or loop % 100 == 0:
                        current_time = time.time()
                        if loop != 0:
                            time_passed = current_time - start_time
                            diff_time = (time_passed / loop) * (loop_until - loop)
                            duration = datetime.timedelta(seconds=diff_time)
                            days = duration.days
                            hours, rem = divmod(duration.seconds, 3600)
                            minutes, seconds = divmod(rem, 60)
                            print(f"already processed: {loop} msgs, to process: {loop_until - loop} msgs, "
                                  f"approximate remaining time: {days} days, {hours} hours, {minutes} minutes, {seconds} seconds")

                    from .fuzzer import Fuzzer

                    cp = Fuzzer.generate_command_packet(keyset, fuzzer.counter, fuzzer.kic, fuzzer.kid, tar, fuzzer.request_por, fuzzer.cipher_por)

                    from simlib.sms_deliver_tpdu import SMSDeliverTPDU

                    tpdu = SMSDeliverTPDU()
                    tpdu.set_pid(pid)
                    tpdu.set_dcs(dcs)
                    tpdu.set_tpudhi(udhi)
                    cp.set_cph(hx.from_string(cph))
                    tpdu.set_tpud(cp.get_bytes())

                    sms = OTASMS()
                    sms.set_sms_deliver_tpdu(tpdu)
                    response = sms.send()

                    handled_response = handle_sim_response(response, False)

                    if len(handled_response.get_bytes()) > 2:
                        cph_padded = cph.ljust((1 + _CPH_FUZZ_COUNT + 2) * 2)
                        output = (f"Message PID = {pid:02X}, DCS = {dcs:02X}, UDHI = {'1' if udhi else '0'}, "
                                  f"CPH = {cph_padded} -> response: {hx.to_string(handled_response.get_bytes())}")

                        try:
                            fuzzer_module.get_ota_response(handled_response, cp, writer, fuzzer, tar, keyset)
                        except Exception as e:
                            print(f"Parsing of responsePacket data failed: {hx.to_string(handled_response.get_bytes())}\n with exception: {e}")

                        print(output)

                        writer.write_raw_line(f"{pid:02X},{dcs:02X},{'1' if udhi else '0'},{cph},{hx.to_string(handled_response.get_bytes())}")

                    loop += 1
