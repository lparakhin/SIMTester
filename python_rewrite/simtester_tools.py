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


def decode_sw(sw1: int, sw2: int) -> str:
    sw = (sw1 << 8) | sw2
    exact = {
        0x9000: "Normal ending of command",
        0x9804: "Access condition not fulfilled / security status not satisfied (SIM/USIM)",
        0x9840: "PIN verification required (SIM/USIM)",
        0x9844: "Referenced data not found",
        0x9850: "INCREASE cannot be performed",
        0x6982: "Security status not satisfied",
        0x6985: "Conditions of use not satisfied",
        0x6A82: "File/application not found",
        0x6A86: "Incorrect P1/P2",
        0x6D00: "Instruction code not supported",
        0x6E00: "Class not supported",
    }
    if sw in exact:
        return exact[sw]
    if sw1 == 0x61:
        return f"More response bytes available: {sw2} (GET RESPONSE required)"
    if sw1 == 0x62:
        return "Warning state of non-volatile memory unchanged"
    if sw1 == 0x63:
        return "Warning state of non-volatile memory changed"
    if sw1 == 0x67:
        return "Wrong length"
    if sw1 == 0x6C:
        return f"Wrong Le, correct value is {sw2}"
    if sw1 == 0x91:
        return f"Proactive command pending, FETCH length {sw2}"
    if sw1 == 0x9E or sw1 == 0x9F:
        return f"SIM application response available: {sw2} bytes"
    return f"Unknown status word {sw1:02X}{sw2:02X}"


def _parse_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i + 1 < len(data):
        tag = data[i]
        i += 1
        ln = data[i]
        i += 1
        if ln & 0x80:
            n = ln & 0x7F
            if i + n > len(data):
                break
            ln = int.from_bytes(data[i : i + n], "big")
            i += n
        if i + ln > len(data):
            break
        out.append((tag, data[i : i + ln]))
        i += ln
    return out


def decode_apdu_response(resp: bytes) -> str:
    if len(resp) < 2:
        return "Malformed APDU response"
    sw1, sw2 = resp[-2], resp[-1]
    parts = [decode_sw(sw1, sw2)]
    body = resp[:-2]
    if body and body[0] in {0x62, 0x6F, 0xA5}:  # common FCP/FMD/AID templates
        tlvs = _parse_tlvs(body[1:])
        tag_map = {
            0x80: "File size",
            0x81: "Total file size",
            0x82: "File descriptor",
            0x83: "File Identifier",
            0x84: "DF name / AID",
            0x88: "Short file identifier",
            0x8A: "Life cycle status",
            0x8B: "Security attributes",
        }
        human = "; ".join(f"{tag_map.get(t, f'Tag {t:02X}')}: {to_hex(v)}" for t, v in tlvs[:8])
        if human:
            parts.append("TLV: " + human)
    return " | ".join(parts)


@dataclass(frozen=True)
class FuzzerData:
    name: str
    counter: int
    kic: int
    kid: int
    request_por: bool
    cipher_por: bool


FUZZERS = {
    0: FuzzerData("fuzzer0", 0x0, 0, 0, False, False),
    1: FuzzerData("fuzzer1", 0x0, 0, 0, True, False),
    9: FuzzerData("fuzzer9", 0x0, 0, 0, True, True),
}
DEFAULT_TARS = ["RAM:000000", "WIB:000001", "WIB:000002", "RFM:00000A", "SAT:505348", "RFM:FFFFFF"]


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
        if self._logging:
            with self._lock:
                self._fp.write(line + "\n")
                self._fp.flush()

    def write_line(self, identifier: str, cmd: bytes, resp: bytes, decoded: str = "") -> None:
        if not self._logging:
            return
        with self._lock:
            if not self._header_written:
                self._fp.write("# id,Command data,Response data,Decoded\n")
                self._header_written = True
            self._fp.write(f"{identifier},{to_hex(cmd)},{to_hex(resp)},{decoded.replace(',', ';')}\n")
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
    def __init__(self, name: str, allow_dummy: bool = False):
        self.name = name
        self.allow_dummy = allow_dummy
        self._conn = None
        self._init_real_reader()

    def _init_real_reader(self) -> None:
        last_error = None
        try:
            from smartcard.System import readers as pcsc_readers

            matched = [r for r in pcsc_readers() if str(r) == self.name]
            if not matched:
                last_error = RuntimeError("Reader not found in current PC/SC list")
            else:
                for r in matched:
                    try:
                        conn = r.createConnection()
                        conn.connect()
                        self._conn = conn
                        print(f"[{self.name}] connected to real SIM reader")
                        return
                    except Exception as exc:
                        last_error = exc
        except Exception as exc:
            last_error = exc

        if self.allow_dummy:
            print(f"[{self.name}] WARNING: real reader unavailable ({last_error}); using dummy transport")
            return

        raise RuntimeError(
            f"Unable to initialize real reader '{self.name}'. "
            f"Reason: {last_error}. Insert card or rerun with --allow-dummy to continue."
        )

    def transmit(self, apdu: bytes) -> bytes:
        if self._conn:
            data, sw1, sw2 = self._conn.transmit(list(apdu))
            return bytes(data + [sw1, sw2])
        if self.allow_dummy:
            return apdu[:2] + b"\x90\x00"
        raise RuntimeError(f"No real reader connection for {self.name}")

    def test_tar(self, tar: bytes, keyset: int) -> bytes:
        # conservative probe payload (SELECT MF) wrapped as dummy TAR payload for now
        return self.transmit(bytes.fromhex("00A40000023F00")) + tar[:1] + bytes([keyset])

    def send_ota(self, pid: int, dcs: int, udhi: bool, cph: bytes, keyset: int, tar: str, fuzzer: FuzzerData) -> bytes:
        # placeholder transport-level OTA probe via APDU path
        _ = (pid, dcs, udhi, cph, keyset, tar, fuzzer)
        return self.transmit(bytes.fromhex("00A40000023F00"))

    def select_path(self, path: str) -> SimCardFileView:
        # basic real probe: select by file id on tail
        fid = path[-4:]
        resp = self.transmit(bytes.fromhex(f"00A4000002{fid}"))
        sw = resp[-2:]
        if sw == b"\x90\x00":
            return SimCardFileView(fid, "DF" if fid.startswith("7F") else "EF")
        raise FileNotFoundError(path)


def detect_available_readers() -> list[str]:
    try:
        from smartcard.System import readers as pcsc_readers

        detected = [str(r) for r in pcsc_readers()]
        if detected:
            return detected
    except Exception:
        pass
    env = os.getenv("SIMTESTER_READERS", "")
    if env.strip():
        return [r.strip() for r in env.split(",") if r.strip()]
    return ["PC/SC Reader 0 (fallback)", "PC/SC Reader 1 (fallback)"]


def apdu_scan(reader: ReaderBackend, writer: CSVWriter, level2: bool = False) -> None:
    print(f"[{reader.name}] Starting APDU scan ({'L2' if level2 else 'L1'})")
    for cla in range(0x100):
        apdu = bytes((cla, 0, 0, 0, 0))
        resp = reader.transmit(apdu)
        decoded = decode_apdu_response(resp)
        print(f"[{reader.name}] APDU {to_hex(apdu)} -> {to_hex(resp)} | {decoded}")
        if not level2:
            writer.write_line(reader.name, apdu, resp, decoded)
        sw = int.from_bytes(resp[-2:], "big") if len(resp) >= 2 else 0xFFFF
        if sw in {0x6E00, 0x6881, 0x6882}:
            continue
        if level2:
            for ins in range(0x100):
                apdu2 = bytes((cla, ins, 0, 0, 0))
                resp2 = reader.transmit(apdu2)
                decoded2 = decode_apdu_response(resp2)
                print(f"[{reader.name}] APDU {to_hex(apdu2)} -> {to_hex(resp2)} | {decoded2}")
                writer.write_line(reader.name, apdu2, resp2, decoded2)


def tar_scan(reader: ReaderBackend, writer: CSVWriter, mode: str, keyset: int, start: str, regex: str | None = None) -> None:
    patt = re.compile(regex) if regex else None
    values = range(int(start, 16), 0x1000000) if mode == "scanAllTARs" else range(0x000000, 0x010000)
    for i in values:
        tar = i.to_bytes(3, "big")
        resp = reader.test_tar(tar, keyset)
        hx = to_hex(resp)
        if patt and not patt.search(hx):
            continue
        decoded = decode_apdu_response(resp[:-2] if len(resp) > 2 else resp)
        print(f"[{reader.name}] TAR {to_hex(tar)} -> {hx} | {decoded}")
        writer.write_raw_line(f"{to_hex(tar)},{hx},{decoded}")


def ota_fuzz(reader: ReaderBackend, writer: CSVWriter, keyset: int, tar: str, fuzzer_id: int, bruteforce: bool) -> None:
    fuzzer = FUZZERS.get(fuzzer_id)
    if not fuzzer:
        raise ValueError(f"Unknown fuzzer: {fuzzer_id}")
    pid_values = list(range(256)) if bruteforce else [0, 65, 124, 127]
    dcs_values = list(range(256)) if bruteforce else [0, 22, 54, 86, 118, 150, 182, 214, 246]
    for pid in pid_values:
        for dcs in dcs_values:
            resp = reader.send_ota(pid, dcs, False, b"", keyset, tar, fuzzer)
            decoded = decode_apdu_response(resp)
            print(f"[{reader.name}] OTA pid={pid:02X} dcs={dcs:02X} -> {to_hex(resp)} | {decoded}")
            writer.write_raw_line(f"{pid:02X},{dcs:02X},{to_hex(resp)},{decoded}")


def file_scan(reader: ReaderBackend, writer: CSVWriter, start_df: str, lazy_scan: bool) -> None:
    writer.write_raw_line("# path,type")
    for i in range(0x10000):
        if lazy_scan and not (0x2F00 <= i <= 0x2FFF or 0x7F00 <= i <= 0x7FFF or 0x6F00 <= i <= 0x6FFF):
            continue
        path = f"{start_df}{i:04X}"
        try:
            entry = reader.select_path(path)
            print(f"[{reader.name}] FILE {path} -> {entry.file_type}")
            writer.write_raw_line(f"{path},{entry.file_type}")
        except FileNotFoundError:
            pass


def _run_for_reader(reader_name: str, args) -> str:
    try:
        reader = ReaderBackend(reader_name, allow_dummy=args.allow_dummy)
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
            writer.write_raw_line(f"# fuzz action selected: TARs={','.join(args.tars)} keysets={args.keysets} fuzzers={args.fuzzers}")
        return writer.unhide()
    except Exception as exc:
        return f"ERROR: {exc}"


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
    available_readers = detect_available_readers()
    action = _menu("Select action", ["apdu", "tar", "ota", "file", "fuzz"])
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
    if action == "apdu" and _menu("APDU scan level", ["level1", "level2"]) == "level2":
        argv.append("--level2")
    elif action == "tar":
        argv += ["--mode", _menu("TAR mode", ["scanRangesOfTARs", "scanAllTARs"])]
        argv += ["--keyset", _input_default("Keyset (0-15)", "1")]
        argv += ["--start", _input_default("Starting TAR (hex, 6 chars)", "000000").upper()]
    elif action == "ota":
        argv += ["--keyset", _input_default("Keyset (0-15)", "1")]
        argv += ["--tar", _input_default("TAR", DEFAULT_TARS[0])]
        argv += ["--fuzzer", _input_default(f"Fuzzer ID {list(FUZZERS.keys())}", "1")]
    elif action == "file":
        argv += ["--start-df", _input_default("Start DF", "3F00").upper()]
    elif action == "fuzz":
        argv += ["--keysets", _input_default("Keysets (comma list)", "1")]
        argv += ["--fuzzers", _input_default("Fuzzer IDs (comma list)", "1")]
        argv += ["--tars", _input_default("TARs (comma list)", ",".join(DEFAULT_TARS[:3]))]

    if _menu("Allow dummy reader fallback?", ["no", "yes"]) == "yes":
        argv.append("--allow-dummy")
    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="simtester-tools")
    parser.add_argument("--menu", action="store_true", help="Open interactive menu before scanning")
    parser.add_argument("--readers", default="", help="Comma-separated reader names (full names accepted)")
    parser.add_argument("--list-readers", action="store_true", help="List detected SIM readers and exit")
    parser.add_argument("--allow-dummy", action="store_true", help="Allow dummy transport when real reader init fails")

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
    readers = [r.strip() for r in args.readers.split(",") if r.strip()] if args.readers.strip() else detect_available_readers()

    failures = 0
    with ThreadPoolExecutor(max_workers=len(readers)) as ex:
        futures = {ex.submit(_run_for_reader, r, args): r for r in readers}
        for fut in as_completed(futures):
            res = fut.result()
            reader_name = futures[fut]
            if res.startswith("ERROR:"):
                failures += 1
                print(f"[{reader_name}] {res}")
            else:
                print(f"[{reader_name}] wrote {res}")
    return 1 if failures == len(readers) else 0


if __name__ == "__main__":
    raise SystemExit(main())
