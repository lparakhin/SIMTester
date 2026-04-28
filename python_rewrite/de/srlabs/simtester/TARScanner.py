"""Python TAR scanner with pluggable TAR test callback."""

from collections.abc import Callable
import re
from ._utils import CSVWriter, to_hex

TarTester = Callable[[bytes, int], bytes]


class TARScanner:
    HIGHEST_TAR = 0xFFFFFF

    def __init__(self, mode: str, keyset: int, writer: CSVWriter, try_being_smart: bool = False, regexp_to_match_response: str | None = None):
        if mode not in {"scanAllTARs", "scanRangesOfTARs"}:
            raise ValueError("Unsupported mode")
        if not 0 <= keyset <= 15:
            raise ValueError("invalid keyset")
        self.mode = mode
        self.keyset = keyset
        self.writer = writer
        self.try_being_smart = try_being_smart
        self.response_regex = re.compile(regexp_to_match_response) if regexp_to_match_response else None
        self.starting_tar = "000000"
        self.last_scanned = None
        self.remaining = 0

    def set_starting_tar(self, starting_tar: str) -> None:
        if not re.fullmatch(r"[0-9A-F]{6}", starting_tar):
            raise ValueError("TAR has to be 3-byte hex")
        self.starting_tar = starting_tar

    def scan_exit(self) -> None:
        if self.remaining > 0 and self.last_scanned:
            self.writer.write_raw_line(f"# exit,{self.mode},last_scanned:{self.last_scanned},remaining:{self.remaining}")

    def scan(self, test_tar: TarTester) -> None:
        if self.mode == "scanAllTARs":
            self._scan_all(test_tar)
        else:
            self._scan_ranges(test_tar)

    def _analyse(self, tar: bytes, response: bytes) -> None:
        tar_hex = to_hex(tar)
        resp_hex = to_hex(response)
        if self.response_regex and not self.response_regex.search(resp_hex):
            return
        self.writer.write_raw_line(f"{tar_hex},{resp_hex}")

    def _scan_all(self, test_tar: TarTester) -> None:
        start = int(self.starting_tar, 16)
        loop_until = self.HIGHEST_TAR - start
        self.writer.write_raw_line(f"# {self.mode},{loop_until}")
        for i in range(loop_until + 1):
            value = i + start
            tar = value.to_bytes(3, "big")
            response = test_tar(tar, self.keyset)
            self._analyse(tar, response)
            self.last_scanned = to_hex(tar)
            self.remaining = loop_until - i - 1

    def _scan_ranges(self, test_tar: TarTester) -> None:
        # practical reduced range set: 00xxxx/3Fxxxx/7Fxxxx/BFxxxx
        prefixes = [0x00, 0x3F, 0x7F, 0xBF]
        values = [bytes((p, b1, b2)) for p in prefixes for b1 in range(256) for b2 in range(256)]
        self.writer.write_raw_line(f"# {self.mode},{len(values)}")
        start_idx = next((i for i, v in enumerate(values) if to_hex(v) == self.starting_tar), 0)
        for i in range(start_idx, len(values)):
            tar = values[i]
            response = test_tar(tar, self.keyset)
            self._analyse(tar, response)
            self.last_scanned = to_hex(tar)
            self.remaining = len(values) - i - 1
