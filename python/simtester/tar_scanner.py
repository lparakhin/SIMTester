"""Port of de.srlabs.simtester.TARScanner."""

from __future__ import annotations

import datetime
import itertools
import re
import threading
import time

from simlib import debug as _debug
from simlib import hex_toolkit as hx
from simlib.auto_terminal_profile import AutoTerminalProfile
from simlib.command_packet import CommandPacket
from simlib.helpers import handle_sim_response, sort_by_values_desc
from simlib.logging_utils import format_debug_message
from simlib.ota_sms import OTASMS
from simlib.response_packet import ResponsePacket, ResponsePacketParseError, find_response_packet

HIGHEST_TAR = 0xFFFFFF
_SMART_COUNT = 20


class TARScanner(threading.Thread):
    use_sms_submit = True

    def __init__(self, mode: str, keyset: int, writer, try_being_smart: bool = False, regexp_to_match_response: str | None = None):
        super().__init__()

        if mode not in ("scanAllTARs", "scanRangesOfTARs"):
            raise ValueError("Unsupported mode")

        if writer is None:
            raise ValueError("writer cannot be None!")

        if not (0 <= keyset <= 15):
            raise ValueError("invalid keyset!")

        self._mode = mode
        self._writer = writer
        self._keyset = keyset
        self._try_being_smart = try_being_smart
        self._starting_tar: str | None = None
        self._skip_responses: list[bytes] = []
        self._stop_event = threading.Event()

        self._regexp_to_match_response_pattern = None
        if regexp_to_match_response is not None:
            try:
                self._regexp_to_match_response_pattern = re.compile(regexp_to_match_response)
            except re.error as e:
                raise SystemExit(f"Unable to compile Pattern from input specified ({regexp_to_match_response}), exiting..\n{e}")

        self._status_last_tar_scanned: str | None = None
        self._status_remaining_tars = 0

    def interrupt(self):
        self._stop_event.set()

    def set_starting_tar(self, starting_tar: str):
        if not re.fullmatch("[0-9A-F]+", starting_tar) or len(starting_tar) != 6:
            raise ValueError(f"TAR value has to be hexadecimal value, 3 bytes long, yours is NOT! value = {starting_tar}")
        self._starting_tar = starting_tar

    def run(self):
        try:
            if self._mode == "scanAllTARs":
                self._scan_all_tars()
            elif self._mode == "scanRangesOfTARs":
                self._scan_ranges_of_tars()
        except Exception:
            import traceback
            traceback.print_exc()

    def _init_scan(self, amount_of_tars: int):
        if AutoTerminalProfile.auto_terminal_profile():
            if _debug.DEBUG:
                print(format_debug_message("Automatic Terminal profile initialization SUCCESSFUL!"))
        else:
            if _debug.DEBUG:
                print(format_debug_message("Automatic Terminal profile initialization FAILED!"))

        if self._try_being_smart:
            print()
            self._try_being_smart_scan()

        print()
        print(f"Starting TAR scanning ({self._mode}), going to go over {amount_of_tars} TARs, go get a (few) coffee(s) ..")
        print()

        self._writer.write_raw_line(f"# {self._mode},{amount_of_tars}")

    def scan_exit(self):
        if self._status_remaining_tars > 0:
            self._writer.write_raw_line(f"# exit,{self._mode},last_scanned:{self._status_last_tar_scanned},remaining:{self._status_remaining_tars}")

    def _scan_all_tars(self):
        starting_tar = self._starting_tar or "000000"
        starting_tar_int = int(starting_tar, 16)
        loop_until = HIGHEST_TAR - starting_tar_int

        self._init_scan(loop_until)

        start_time = time.time()
        i = 0
        has_card_exception = False  # allow just one single CardException

        while i <= loop_until and not self._stop_event.is_set():
            int_tar = i + starting_tar_int
            current_tar = bytes([(int_tar >> 16) & 0xFF, (int_tar >> 8) & 0xFF, int_tar & 0xFF])

            if i == loop_until or i % 100 == 0:
                self._print_progress(i, loop_until, start_time, current_tar)

            cp = CommandPacket()
            response = self._test_tar(current_tar, cp)

            try:
                self._analyse_response(current_tar, cp, response)
                has_card_exception = False
            except Exception as e:
                if not has_card_exception:
                    print(e)
                    has_card_exception = True
                else:
                    raise

            self._status_last_tar_scanned = hx.to_string(current_tar)
            self._status_remaining_tars = loop_until - i - 1

            i += 1

    def _scan_ranges_of_tars(self):
        tar_list = self._prepare_tar_list()
        loop_until = len(tar_list)
        start_index = 0

        if self._starting_tar is not None:
            starting_bytes = hx.from_string(self._starting_tar)
            if starting_bytes in tar_list:
                start_index = tar_list.index(starting_bytes)
            else:
                raise ValueError(f"Starting TAR {self._starting_tar} is not contained in range generated, specify a valid starting TAR")

        self._init_scan(loop_until)

        start_time = time.time()

        for i in range(start_index, loop_until):
            if self._stop_event.is_set():
                break

            current_tar = tar_list[i]

            if i == loop_until - 1 or i % 100 == 0:
                self._print_progress(i, loop_until, start_time, current_tar)

            cp = CommandPacket()
            response = self._test_tar(current_tar, cp)
            self._analyse_response(current_tar, cp, response)

            self._status_last_tar_scanned = hx.to_string(current_tar)
            self._status_remaining_tars = loop_until - i - 1

    @staticmethod
    def _print_progress(i: int, loop_until: int, start_time: float, current_tar: bytes):
        if i == 0:
            return
        time_passed = time.time() - start_time
        diff_time = (time_passed / i) * (loop_until - i)
        duration = datetime.timedelta(seconds=diff_time)
        days = duration.days
        hours, rem = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        print(f"Processing TAR: {hx.to_string(current_tar)}, already processed: {i} TARs, to process: {loop_until - i} TARs, "
              f"approximate remaining time: {days} days, {hours} hours, {minutes} minutes, {seconds} seconds")

    def _test_tar(self, tar: bytes, cp: CommandPacket):
        cp.set_keyset(self._keyset)
        cp.set_counter_management(CommandPacket.CNTR_NO_CNTR_AVAILABLE)
        cp.set_counter(1)
        cp.set_por(True)
        cp.set_por_security(CommandPacket.POR_SECURITY_CC)
        if TARScanner.use_sms_submit:
            cp.set_por_mode(CommandPacket.POR_MODE_SMS_SUBMIT)
        else:
            cp.set_por_mode(CommandPacket.POR_MODE_SMS_DELIVER_REPORT)
        cp.set_user_data(hx.from_string("A0A40000023F00"))

        otasms = OTASMS()
        cp.set_tar(tar)
        otasms.set_command_packet(cp)
        response = otasms.send()

        if _debug.DEBUG:
            print(format_debug_message(f"ResponseAPDU bytes: {hx.to_string(response.get_bytes())}"))

        return response

    def _analyse_response(self, tar: bytes, command: CommandPacket, response):
        handled_response = handle_sim_response(response, False)
        current_response = handled_response.get_bytes()

        if self._regexp_to_match_response_pattern is not None:
            if self._regexp_to_match_response_pattern.search(hx.to_string(current_response)):
                if _debug.DEBUG:
                    print(format_debug_message(f"Response {hx.to_string(current_response)} skipped as it matches the regular expression pattern specified."))
                return

        possible_rp = find_response_packet(handled_response.get_data())

        if possible_rp is not None:
            rp = ResponsePacket()

            try:
                rp.parse(possible_rp)
            except ResponsePacketParseError as e:
                print("Parse exception while parsing response packet, skipping it! details:")
                print(e)
                return
            except IndexError as e:
                raise RuntimeError(str(e))

            status_code = rp.get_status_code()

            if self._try_being_smart:
                if bytes([rp.get_status_code()]) in self._skip_responses:
                    if _debug.DEBUG:
                        print(format_debug_message(f"Response {hx.to_string(current_response)} skipped as it's being considered a false response (by tryBeingSmart)."))
                    return

            if status_code != 9:
                print(f"GOT VALID TAR!! ({hx.to_string(tar)}), PoR status code: {hx.to_string(status_code)}")
                self._writer.write_line(hx.to_string(tar), command.get_bytes(), handled_response.get_bytes())
        else:
            if self._try_being_smart:
                if current_response in self._skip_responses:
                    if _debug.DEBUG:
                        print(format_debug_message(f"Response {hx.to_string(current_response)} skipped as it's being considered a false response (by tryBeingSmart)."))
                    return

            print(f"RESPONSE OTHER THAN ERROR!! ({hx.to_string(tar)}), response: {hx.to_string(current_response)}")
            self._writer.write_line(hx.to_string(tar), command.get_bytes(), current_response)

    def _try_being_smart_scan(self):
        import random

        print(f"Trying to be smart. Scanning {_SMART_COUNT} random TARs to determine a false response other than standard.")

        random_responses: list[bytes] = []

        for _ in range(_SMART_COUNT):
            int_tar = random.randint(0, 0xFFFFFF)
            current_tar = bytes([(int_tar >> 16) & 0xFF, (int_tar >> 8) & 0xFF, int_tar & 0xFF])
            cp = CommandPacket()
            response = self._test_tar(current_tar, cp)
            handled_response = handle_sim_response(response)

            rp = ResponsePacket()
            try:
                rp.parse(handled_response.get_data(), strict=True)
                random_responses.append(bytes([rp.get_status_code()]))
                print(f"Generated TAR {hx.to_string(current_tar)} returned {hx.to_string(handled_response.get_bytes())}; "
                      f"added PoR status code: {rp.get_status_code():02X}")
                continue
            except ResponsePacketParseError:
                pass

            random_responses.append(handled_response.get_bytes())
            print(f"Generated TAR {hx.to_string(current_tar)} returned {hx.to_string(handled_response.get_bytes())}")

        counts: dict[bytes, int] = {}
        for one in set(random_responses):
            counts[one] = random_responses.count(one)

        counts = sort_by_values_desc(counts)
        most_common = next(iter(counts.keys()))

        print(f"Response {hx.to_string(most_common)} determined as most common - therefore considered a false response.")

        self._skip_responses.append(most_common)

    def _prepare_tar_list(self) -> list[bytes]:
        tar_list: list[bytes] = []

        punct_etc_chars = [chr(c) for c in range(0x21, 0x41)] + [chr(c) for c in range(0x5B, 0x61)] + [chr(c) for c in range(0x7B, 0x7F)]
        lower_case_chars = [chr(c) for c in range(0x61, 0x7B)]
        upper_case_chars = [chr(c) for c in range(0x41, 0x5B)]

        lower_case_and_punct = lower_case_chars + punct_etc_chars
        upper_case_and_punct = upper_case_chars + punct_etc_chars

        for combo in itertools.product(lower_case_and_punct, repeat=3):
            tar_list.append(bytes(ord(c) for c in combo))

        for combo in itertools.product(upper_case_and_punct, repeat=3):
            tar_list.append(bytes(ord(c) for c in combo))

        ranges = [
            (0x000000, 0x0000FF), (0x000100, 0x00010F), (0x000200, 0x00020F),
            (0x000300, 0x00030F), (0x000400, 0x00040F), (0x000500, 0x00050F),
            (0x3F0000, 0x3F003F), (0x800000, 0x8000FF), (0xA00000, 0xA000FF),
            (0xB00000, 0xB000FF), (0xBFFF00, 0xBFFFFF), (0xC00000, 0xC000FF),
            (0xD00000, 0xD000FF), (0xEED000, 0xEEEFFF), (0xFFFF00, 0xFFFFFF),
        ]
        for start, stop in ranges:
            for int_tar in range(start, stop + 1):
                tar_list.append(bytes([(int_tar >> 16) & 0xFF, (int_tar >> 8) & 0xFF, int_tar & 0xFF]))

        # de-duplicate (punctuation-only TARs get generated twice, once via the
        # lowercase+punct permutation and once via uppercase+punct) and sort
        unique_sorted = sorted(set(tar_list), key=hx.byte_array_to_long)

        return unique_sorted
