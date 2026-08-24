"""Port of de.srlabs.simtester.CSVWriter."""

from __future__ import annotations

import os
import sys
import time

from simlib import config as simlib_config
from simlib import hex_toolkit as hx
from simlib.logging_utils import format_debug_message


class CSVWriter:
    def __init__(self, iccid: str | None, type_: str, logging: bool):
        self._logging = logging
        self._header_written = False
        self._file = None
        self._path = None

        if self._logging:
            self._path = f".{type_}_{iccid}_{int(time.time() * 1000)}.csv"
            try:
                self._file = open(self._path, "w", newline="")
            except OSError as e:
                print(format_debug_message(f"Unable to create file {self._path}, exiting.."), file=sys.stderr)
                print(e, file=sys.stderr)
                sys.exit(1)

            from .simtester import SIMTester  # local import to avoid a cycle

            self._file.write("# " + SIMTester.get_version() + "\n")
            self._file.write("# " + simlib_config.VERSION + "\n")

    def unhide_file(self) -> bool:
        if self._path is None:
            return True
        base = os.path.basename(self._path)
        if base.startswith("."):
            new_name = os.path.join(os.path.dirname(self._path), base[1:])
            try:
                if self._file is not None:
                    self._file.flush()
                os.rename(self._path, new_name)
            except OSError:
                return False
            self._path = new_name
            return True
        return True  # assuming it's already not hidden

    def get_file_name(self) -> str | None:
        if self._path is None:
            return None
        return os.path.basename(self._path)

    def _write_header(self):
        if self._logging:
            self._file.write("# id,Command data,Response data\n")
            self._file.flush()

    def write_basic_info(self, atr, iccid, imsi, msisdn, ef_manuarea, ef_dir, auth, app_deselect):
        if self._logging:
            try:
                self._file.write(f"ATR:{atr}\n")
                self._file.write(f"ICCID:{iccid}\n")
                self._file.write(f"IMSI:{imsi}\n")
                self._file.write(f"MSISDN:{msisdn}\n")
                self._file.write(f"EF_MANUAREA:{ef_manuarea}\n")
                self._file.write(f"EF_DIR:{ef_dir}\n")
                self._file.write(f"AUTH:{auth}\n")
                self._file.write(f"AppDeSelect:{app_deselect}\n")
                self._file.flush()
            except OSError as e:
                print(format_debug_message("Unable to write basic info into the CSV file, something's wrooooong, panic, panic, exit."), file=sys.stderr)
                print(e, file=sys.stderr)
                sys.exit(1)

    def write_line(self, identificator: str, command_data: bytes, response_data: bytes | None):
        if self._logging:
            try:
                if not self._header_written:
                    self._write_header()
                    self._header_written = True
                self._file.write(f"{identificator},{hx.to_string(command_data)},{hx.to_string(response_data)}\n")
                self._file.flush()
            except OSError as e:
                print(format_debug_message("Unable to write line into the CSV file, something's wrooooong, panic, panic, exit."), file=sys.stderr)
                print(e, file=sys.stderr)
                sys.exit(1)

    def write_raw_line(self, line_content: str):
        if self._logging:
            try:
                self._file.write(line_content + "\n")
                self._file.flush()
            except OSError as e:
                print(format_debug_message("Unable to write line into the CSV file, something's wrooooong, panic, panic, exit."), file=sys.stderr)
                print(e, file=sys.stderr)
                sys.exit(1)
