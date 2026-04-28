"""Python OTA fuzzing logic with pluggable sender."""

from collections.abc import Callable
from .FuzzerData import FuzzerData
from ._utils import CSVWriter, to_hex

OtaSender = Callable[[int, int, bool, bytes, int, str, FuzzerData], bytes]


def fuzz_ota(keyset: int, tar: str, fuzzer: FuzzerData, writer: CSVWriter, bruteforce: bool, send_ota: OtaSender) -> None:
    pid_values = list(range(256)) if bruteforce else [0, 65, 124, 127]
    dcs_values = list(range(256)) if bruteforce else [0, 22, 54, 86, 118, 150, 182, 214, 246]
    udhi_values = [False, True]

    cph_values = [bytes.fromhex(f"{2+i:02X}70{i:02X}" + ("00" * i)) for i in range(3)] + [bytes.fromhex("027100"), bytes.fromhex("027F00"), b""]

    total = len(pid_values) * len(dcs_values) * len(udhi_values) * len(cph_values)
    writer.write_raw_line("# pid,dcs,udhi,cph,response")
    writer.write_raw_line(f"# msgs: {total}")

    loop = 0
    for pid in pid_values:
        for dcs in dcs_values:
            for cph in cph_values:
                for udhi in udhi_values:
                    response = send_ota(pid, dcs, udhi, cph, keyset, tar, fuzzer)
                    if len(response) > 2:
                        writer.write_raw_line(f"{pid:02X},{dcs:02X},{1 if udhi else 0},{to_hex(cph)},{to_hex(response)}")
                    loop += 1
                    if loop % 1000 == 0:
                        print(f"processed {loop}/{total} OTA combinations")
