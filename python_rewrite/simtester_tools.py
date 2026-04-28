"""Single-file Python SIMTester tools with menu-driven multi-SIM reader support."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import os
import re
import threading
import time


def to_hex(data: bytes | bytearray | None) -> str:
    return bytes(data).hex().upper() if data else ""


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "reader"

@dataclass(frozen=True)
class FuzzerData:
    name: str
    counter: int
    kic: int
    kid: int
    request_por: bool
    cipher_por: bool


# subset kept explicit; extend freely
FUZZERS = {
    0: FuzzerData("fuzzer0", 0x0, 0, 0, False, False),
    1: FuzzerData("fuzzer1", 0x0, 0, 0, True, False),
    9: FuzzerData("fuzzer9", 0x0, 0, 0, True, True),
}

DEFAULT_TARS = [
    "RAM:000000", "WIB:000001", "WIB:000002", "RFM:00000A", "SAT:505348", "RFM:FFFFFF"
]


class CSVWriter:
    def __init__(self, iccid: str, scan_type: str, reader_name: str, logging: bool = True):
        self._lock = threading.Lock()
        self._logging = logging
        self._header_written = False
        self._path: Path | None = None
        self._fp = None
        if logging:
            safe_reader = _safe_filename(reader_name)
            self._path = Path(f".{scan_type}_{safe_reader}_{iccid}_{int(time.time()*1000)}.csv")
            self._fp = self._path.open("w", encoding="utf-8")

    def write_raw_line(self, line: str) -> None:
        if not self._logging:
            return
        with self._lock:
            self._fp.write(line + "\n")
            self._fp.flush()

    def write_line(self, identifier: str, cmd: bytes, resp: bytes) -> None:
        if not self._logging:
            return
        with self._lock:
            if not self._header_written:
                self._fp.write("# id,Command data,Response data\n")
                self._header_written = True
            self._fp.write(f"{identifier},{to_hex(cmd)},{to_hex(resp)}\n")
            self._fp.flush()

    def unhide(self) -> str:
        if not self._path:
            return ""
        if self._path.name.startswith("."):
            target = self._path.with_name(self._path.name[1:])
            self._fp.close()
            self._path.rename(target)
            self._path = target
        return self._path.name


@dataclass
class SimCardFileView:
    file_id: str
    file_type: str
    child_dfs: int = 0
    child_efs: int = 0


class ReaderBackend:
    def __init__(self, name: str):
        self.name = name

    def transmit(self, apdu: bytes) -> bytes:
        return apdu[:2] + b"\x90\x00"

    def test_tar(self, tar: bytes, keyset: int) -> bytes:
        return tar + bytes([keyset]) + b"\x90\x00"

    def send_ota(self, pid: int, dcs: int, udhi: bool, cph: bytes, keyset: int, tar: str, fuzzer: FuzzerData) -> bytes:
        return bytes([pid, dcs, int(udhi)]) + cph[:2] + b"\x90\x00"

    def select_path(self, path: str) -> SimCardFileView:
        if path in {"3F00", "3F007F20", "3F007F10"}:
            return SimCardFileView(path[-4:], "DF", 1, 2)
        if path.endswith(("6F07", "6FAD", "6F3A")):
            return SimCardFileView(path[-4:], "EF")
        raise FileNotFoundError(path)


def detect_available_readers() -> list[str]:
    """Return full reader names detected on the host system.

    Detection order:
    1) pyscard/PCSC (`smartcard.System.readers`)
    2) SIMTESTER_READERS env var (comma-separated)
    3) built-in fallback names
    """
    try:
        from smartcard.System import readers as pcsc_readers

        detected = [str(r) for r in pcsc_readers()]
        if detected:
            return detected
    except Exception:
        pass

    env = os.getenv("SIMTESTER_READERS", "")
    if env.strip():
        detected = [r.strip() for r in env.split(",") if r.strip()]
        if detected:
            return detected

    return ["PC/SC Reader 0 (fallback)", "PC/SC Reader 1 (fallback)"]


def apdu_scan(reader: ReaderBackend, writer: CSVWriter, level2: bool = False) -> None:
    for cla in range(0x100):
        apdu = bytes((cla, 0, 0, 0, 0))
        resp = reader.transmit(apdu)
        if not level2:
            writer.write_line(reader.name, apdu, resp)
        sw = int.from_bytes(resp[-2:], "big") if len(resp) >= 2 else 0xFFFF
        if sw in {0x6E00, 0x6881, 0x6882}:
            continue
        if level2:
            for ins in range(0x100):
                apdu2 = bytes((cla, ins, 0, 0, 0))
                writer.write_line(reader.name, apdu2, reader.transmit(apdu2))


def tar_scan(reader: ReaderBackend, writer: CSVWriter, mode: str, keyset: int, start: str, regex: str | None = None) -> None:
    patt = re.compile(regex) if regex else None
    if mode == "scanAllTARs":
        values = range(int(start, 16), 0x1000000)
        tar_iter = (v.to_bytes(3, "big") for v in values)
    else:
        prefixes = [0x00, 0x3F, 0x7F, 0xBF]
        vals = [bytes((p, b1, b2)) for p in prefixes for b1 in range(256) for b2 in range(256)]
        idx = next((i for i, v in enumerate(vals) if to_hex(v) == start), 0)
        tar_iter = iter(vals[idx:])
    for tar in tar_iter:
        hx = to_hex(reader.test_tar(tar, keyset))
        if patt and not patt.search(hx):
            continue
        writer.write_raw_line(f"{to_hex(tar)},{hx}")


def ota_fuzz(reader: ReaderBackend, writer: CSVWriter, keyset: int, tar: str, fuzzer_id: int, bruteforce: bool) -> None:
    fuzzer = FUZZERS.get(fuzzer_id)
    if not fuzzer:
        raise ValueError(f"Unknown fuzzer: {fuzzer_id}")
    pid_values = list(range(256)) if bruteforce else [0, 65, 124, 127]
    dcs_values = list(range(256)) if bruteforce else [0, 22, 54, 86, 118, 150, 182, 214, 246]
    cph_values = [bytes.fromhex(f"{2+i:02X}70{i:02X}" + ("00" * i)) for i in range(3)] + [bytes.fromhex("027100"), bytes.fromhex("027F00"), b""]
    writer.write_raw_line("# pid,dcs,udhi,cph,response")
    for pid in pid_values:
        for dcs in dcs_values:
            for udhi in (False, True):
                for cph in cph_values:
                    resp = reader.send_ota(pid, dcs, udhi, cph, keyset, tar, fuzzer)
                    if len(resp) > 2:
                        writer.write_raw_line(f"{pid:02X},{dcs:02X},{int(udhi)},{to_hex(cph)},{to_hex(resp)}")


def file_scan(reader: ReaderBackend, writer: CSVWriter, start_df: str, lazy_scan: bool) -> None:
    reserved = {"3F00", "3FFF", "7FFF", "FFFF"}
    root = reader.select_path(start_df)
    writer.write_raw_line("# path,type")
    writer.write_raw_line(f"{start_df},{root.file_type}")
    for i in range(0x10000):
        if f"{i:04X}" in reserved:
            continue
        if lazy_scan:
            lvl = len(start_df) // 4
            if lvl == 1 and not (0x2F00 <= i <= 0x2FFF or 0x7F00 <= i <= 0x7FFF):
                continue
            if lvl == 2 and not (0x5F00 <= i <= 0x5FFF or 0x6F00 <= i <= 0x6FFF):
                continue
            if lvl == 3 and not (0x4F00 <= i <= 0x4FFF):
                continue
        path = f"{start_df}{i:04X}"
        try:
            writer.write_raw_line(f"{path},{reader.select_path(path).file_type}")
        except FileNotFoundError:
            pass


def _run_for_reader(reader_name: str, args) -> str:
    reader = ReaderBackend(reader_name)
    writer = CSVWriter("UNKNOWN", args.cmd.upper(), reader_name)
    if args.cmd == "apdu":
        apdu_scan(reader, writer, args.level2)
    elif args.cmd == "tar":
        tar_scan(reader, writer, args.mode, args.keyset, args.start, args.regex)
    elif args.cmd == "ota":
        ota_fuzz(reader, writer, args.keyset, args.tar, args.fuzzer, args.bruteforce)
    elif args.cmd == "file":
        file_scan(reader, writer, args.start_df, args.lazy)
    elif args.cmd == "fuzz":
        # placeholder to preserve original action menu surface
        writer.write_raw_line(f"# fuzz action selected: TARs={','.join(args.tars)} keysets={args.keysets} fuzzers={args.fuzzers}")
    return writer.unhide()


def _menu(prompt: str, options: list[str], default: int = 0) -> str:
    print(f"\n{prompt}")
    for i, opt in enumerate(options, start=1):
        print(f"  {i}. {opt}")
    raw = input(f"Select [default {default + 1}]: ").strip()
    if not raw:
        return options[default]
    return options[max(1, min(len(options), int(raw))) - 1]


def _input_default(prompt: str, default: str) -> str:
    raw = input(f"{prompt} [{default}]: ").strip()
    return raw if raw else default


def interactive_menu() -> list[str]:
    """Menu with actions/options mirroring original repo surface as closely as practical."""
    available_readers = detect_available_readers()
    action = _menu("Select action", ["apdu", "tar", "ota", "file", "fuzz"])  # fuzz included for parity

    # reader selection
    print("\nAvailable SIM readers:")
    for i, r in enumerate(available_readers, start=1):
        print(f"  {i}. {r}")
    readers_raw = _input_default("Reader indexes (comma-separated) or 'all'", "all")
    if readers_raw.lower() == "all":
        readers = ",".join(available_readers)
    else:
        picks = []
        for tok in readers_raw.split(","):
            tok = tok.strip()
            if tok.isdigit() and 1 <= int(tok) <= len(available_readers):
                picks.append(available_readers[int(tok) - 1])
        readers = ",".join(picks or available_readers)

    argv = ["--readers", readers, action]

    if action == "apdu":
        if _menu("APDU scan level", ["level1", "level2"]) == "level2":
            argv.append("--level2")
    elif action == "tar":
        mode = _menu("TAR mode", ["scanRangesOfTARs", "scanAllTARs"])
        argv += ["--mode", mode]
        argv += ["--keyset", _input_default("Keyset (0-15)", "1")]
        argv += ["--start", _input_default("Starting TAR (hex, 6 chars)", "000000").upper()]
        regex = _input_default("Optional response regex (blank = none)", "")
        if regex:
            argv += ["--regex", regex]
    elif action == "ota":
        argv += ["--keyset", _input_default("Keyset (0-15)", "1")]
        argv += ["--tar", _input_default("TAR", DEFAULT_TARS[0])]
        argv += ["--fuzzer", _input_default(f"Fuzzer ID {list(FUZZERS.keys())}", "1")]
        if _menu("Bruteforce PID/DCS?", ["no", "yes"]) == "yes":
            argv.append("--bruteforce")
    elif action == "file":
        argv += ["--start-df", _input_default("Start DF", "3F00").upper()]
        if _menu("Lazy scan?", ["yes", "no"]) == "yes":
            argv.append("--lazy")
    elif action == "fuzz":
        # original broad fuzz configuration surface
        keysets = _input_default("Keysets (comma list)", "1")
        fuzzers = _input_default("Fuzzer IDs (comma list)", "1")
        tars = _input_default("TARs (comma list)", ",".join(DEFAULT_TARS[:3]))
        argv += ["--keysets", keysets, "--fuzzers", fuzzers, "--tars", tars]

    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="simtester-tools")
    parser.add_argument("--menu", action="store_true", help="Open interactive menu before scanning")
    parser.add_argument("--readers", default="", help="Comma-separated reader names (full names accepted)")
    parser.add_argument("--list-readers", action="store_true", help="List detected SIM readers and exit")

    sub = parser.add_subparsers(dest="cmd", required=True)
    apdu = sub.add_parser("apdu")
    apdu.add_argument("--level2", action="store_true")

    tar = sub.add_parser("tar")
    tar.add_argument("--mode", choices=["scanAllTARs", "scanRangesOfTARs"], default="scanRangesOfTARs")
    tar.add_argument("--keyset", type=int, default=1)
    tar.add_argument("--start", default="000000")
    tar.add_argument("--regex")

    ota = sub.add_parser("ota")
    ota.add_argument("--keyset", type=int, default=1)
    ota.add_argument("--tar", default="RAM:000000")
    ota.add_argument("--fuzzer", type=int, default=1)
    ota.add_argument("--bruteforce", action="store_true")

    filep = sub.add_parser("file")
    filep.add_argument("--start-df", default="3F00")
    filep.add_argument("--lazy", action="store_true")

    fuzz = sub.add_parser("fuzz")
    fuzz.add_argument("--keysets", type=lambda x: [int(i) for i in x.split(",")], default=[1])
    fuzz.add_argument("--fuzzers", type=lambda x: [int(i) for i in x.split(",")], default=[1])
    fuzz.add_argument("--tars", type=lambda x: [s.strip() for s in x.split(",")], default=DEFAULT_TARS)

    return parser


def main(argv: list[str] | None = None) -> int:
    import sys
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["--menu"]

    if "--list-readers" in argv:
        for idx, name in enumerate(detect_available_readers(), start=1):
            print(f"{idx}. {name}")
        return 0

    if "--menu" in argv:
        argv = [x for x in argv if x != "--menu"]
        argv = interactive_menu()

    args = parser.parse_args(argv)
    if args.readers.strip():
        readers = [r.strip() for r in args.readers.split(",") if r.strip()]
    else:
        readers = detect_available_readers()

    with ThreadPoolExecutor(max_workers=len(readers)) as ex:
        futures = {ex.submit(_run_for_reader, r, args): r for r in readers}
        for fut in as_completed(futures):
            print(f"[{futures[fut]}] wrote {fut.result()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
