"""Port of de.srlabs.simtester.SIMTester (CLI entry point / orchestration)."""

from __future__ import annotations

import argparse
import atexit
import sys
import time

from simlib import auth as simlib_auth
from simlib import common_file_reader as cfr
from simlib import config
from simlib import debug as _debug
from simlib import hex_toolkit as hx
from simlib.apdu_toolkit import authenticate, get_response, run_gsm_algo_2g
from simlib.auto_terminal_profile import AutoTerminalProfile
from simlib.channel_handler import ChannelHandler
from simlib.file_management import FileManagement

from . import apdu_scanner
from . import file_scanner
from . import fuzzer_factory
from . import gsmmap_uploader
from . import ota_fuzzer
from .csv_writer import CSVWriter
from .fuzzer import Fuzzer
from .fuzzer_result import fuzzer_result_key
from .tar_scanner import TARScanner

_VERSION = "SIMTester (Python port) v2.0.0"


class SIMTester:
    DEBUG = False
    cmdline: argparse.Namespace | None = None

    _action = ""
    _tars: list[str] = list(fuzzer_factory.default_tars)
    _custom_fuzzers: list[int] | None = None
    _custom_keysets: list[int] | None = None
    _custom_tars: list[str] | None = None
    _fuzzing_level = "FULL"
    _gsmmap_upload = False
    _skip_pin = False
    _logging = True

    ATR: str | None = None
    ICCID: str | None = None
    IMSI: str | None = None
    MSISDN: str | None = None
    EF_MANUAREA: str | None = None
    EF_DIR: str | None = None
    AUTH: str | None = None
    AppDeSelect: str | None = None

    _fuzzer: Fuzzer | None = None
    _tarscanner: TARScanner | None = None
    _writer: CSVWriter | None = None
    _start_time: float | None = None

    @staticmethod
    def get_version() -> str:
        return _VERSION

    # -- entry point ----------------------------------------------------

    @staticmethod
    def main(argv: list[str] | None = None):
        print()
        print("########################################")
        print(f"  {_VERSION}")
        print("  Python port of SRLabs SIMTester        ")
        print("  Lukas Kuzmiak, Luca Melette,            ")
        print("  Jonas Schmid, Gabriel Arnautu           ")
        print("  Security Research Labs, Berlin          ")
        print("########################################")
        print()

        SIMTester._start_time = time.time()
        atexit.register(SIMTester._shutdown_hook)

        SIMTester._handle_options(argv if argv is not None else sys.argv[1:])

        if SIMTester._action == "TAR":
            SIMTester.perform_tar_scanning()
        elif SIMTester._action == "APDU":
            SIMTester.perform_apdu_scanning()
        elif SIMTester._action == "OTA":
            SIMTester.perform_ota_fuzzing()
        else:
            SIMTester.perform_standard_fuzzing()

    @staticmethod
    def _shutdown_hook():
        print()
        print("Graceful shutdown initiated. Trying to close all open channels. Please wait... !")

        if SIMTester._fuzzer is not None:
            SIMTester._fuzzer.interrupt()
            SIMTester._fuzzer.join()

        if SIMTester._tarscanner is not None:
            SIMTester._tarscanner.interrupt()
            SIMTester._tarscanner.join()
            SIMTester._tarscanner.scan_exit()

        try:
            ChannelHandler.disconnect_card()
        except Exception:
            pass

        if SIMTester._fuzzer is not None:
            SIMTester._print_summary(SIMTester._fuzzer)

        if SIMTester._writer is not None:
            if not SIMTester._writer.unhide_file():
                print(f"[SIMTester] Unable to unhide file {SIMTester._writer.get_file_name()}, make sure you rename it so it does NOT start with a dot to get processed!", file=sys.stderr)
            elif SIMTester._gsmmap_upload:
                if gsmmap_uploader.upload_file(SIMTester._writer.get_file_name()):
                    print(f"Upload of {SIMTester._writer.get_file_name()} to gsmmap.org successful!")
                else:
                    print("There was a problem uploading the result to gsmmap.org")
                    print("Please use the form at http://gsmmap.org/upload.html to submit the data manually.")

        if SIMTester._start_time is not None:
            minutes = int((time.time() - SIMTester._start_time) // 60)
            print(f"Execution time (minutes): {minutes}")

    # -- top level actions ------------------------------------------------

    @staticmethod
    def perform_standard_fuzzing():
        SIMTester._read_basic_info()
        SIMTester._writer = CSVWriter(SIMTester.ICCID, "FUZZ", SIMTester._logging)
        SIMTester._writer.write_basic_info(SIMTester.ATR, SIMTester.ICCID, SIMTester.IMSI, SIMTester.MSISDN,
                                            SIMTester.EF_MANUAREA, SIMTester.EF_DIR, SIMTester.AUTH, SIMTester.AppDeSelect)
        SIMTester._fuzz()
        SIMTester._writer.unhide_file()

    @staticmethod
    def perform_ota_fuzzing():
        SIMTester._read_basic_info()
        SIMTester._writer = CSVWriter(SIMTester.ICCID, "OTA", SIMTester._logging)
        SIMTester._writer.write_basic_info(SIMTester.ATR, SIMTester.ICCID, SIMTester.IMSI, SIMTester.MSISDN,
                                            SIMTester.EF_MANUAREA, SIMTester.EF_DIR, SIMTester.AUTH, SIMTester.AppDeSelect)

        ota_keyset = SIMTester._custom_keysets[0] if SIMTester._custom_keysets else 1
        fuzzer = fuzzer_factory.get_fuzzer(SIMTester._custom_fuzzers[0] if SIMTester._custom_fuzzers else 1)
        tar = SIMTester._custom_tars[0] if SIMTester._custom_tars else "RAM:000000"

        ota_fuzzer.fuzz_ota(ota_keyset, tar, fuzzer, SIMTester._writer, SIMTester.cmdline.ota_fuzz_bruteforce)
        SIMTester._writer.unhide_file()
        print("done fuzzing OTA passthrough, exiting..")

    @staticmethod
    def perform_apdu_scanning():
        SIMTester._read_basic_info()
        SIMTester._writer = CSVWriter(SIMTester.ICCID, "APDU", SIMTester._logging)
        SIMTester._writer.write_basic_info(SIMTester.ATR, SIMTester.ICCID, SIMTester.IMSI, SIMTester.MSISDN,
                                            SIMTester.EF_MANUAREA, SIMTester.EF_DIR, SIMTester.AUTH, SIMTester.AppDeSelect)
        apdu_scanner.run(None, SIMTester._writer, False, SIMTester.cmdline.scan_apdu_level2)
        SIMTester._writer.unhide_file()
        print("done scanning APDUs, exiting..")

    @staticmethod
    def perform_tar_scanning():
        SIMTester._read_basic_info()
        SIMTester._writer = CSVWriter(SIMTester.ICCID, "TAR", SIMTester._logging)
        SIMTester._writer.write_basic_info(SIMTester.ATR, SIMTester.ICCID, SIMTester.IMSI, SIMTester.MSISDN,
                                            SIMTester.EF_MANUAREA, SIMTester.EF_DIR, SIMTester.AUTH, SIMTester.AppDeSelect)

        keyset = SIMTester._custom_keysets[0] if SIMTester.cmdline.keyset and SIMTester._custom_keysets else 1
        try_being_smart = bool(SIMTester.cmdline.scan_tars_be_smart)
        regexp_to_match_response = SIMTester.cmdline.scan_tars_regexp

        mode = "scanRangesOfTARs" if SIMTester.cmdline.scan_tars_range else "scanAllTARs"
        SIMTester._tarscanner = TARScanner(mode, keyset, SIMTester._writer, try_being_smart, regexp_to_match_response)

        if SIMTester.cmdline.tar and SIMTester._custom_tars:
            starting_tar = SIMTester._custom_tars[0].split(":")[1]
            SIMTester._tarscanner.set_starting_tar(starting_tar)

        SIMTester._tarscanner.start()
        SIMTester._tarscanner.join()

        SIMTester._writer.unhide_file()
        print("done scanning TARs, exiting..")

    # -- shared setup -------------------------------------------------------

    @staticmethod
    def _read_basic_info():
        atr_bytes = ChannelHandler.get_default_channel().getATR()
        SIMTester.ATR = hx.to_string(bytes(atr_bytes))
        print()
        print(f"ATR: {SIMTester.ATR}")

        if AutoTerminalProfile.auto_terminal_profile():
            if SIMTester.DEBUG:
                print("[SIMTester] Automatic Terminal profile initialization SUCCESSFUL!")
        else:
            if SIMTester.DEBUG:
                print("[SIMTester] Automatic Terminal profile initialization FAILED!")

        SIMTester.ICCID = cfr.read_iccid()
        SIMTester.EF_MANUAREA = cfr.read_manuarea()
        print(f"ICCID: {SIMTester.ICCID}")

        dir_records = cfr.read_dir()
        if dir_records:
            SIMTester.EF_DIR = ";".join(hx.to_string(r) for r in dir_records)
            print(f"The EF_DIR has {len(dir_records)} record(s)")
            for i, record in enumerate(dir_records):
                print(f"Record {i}: {hx.to_string(record)}")

        raw_imsi = cfr.read_raw_imsi()
        if raw_imsi is not None:
            SIMTester.IMSI = cfr.swap_imsi(raw_imsi)
        else:
            SIMTester.IMSI = None
            if not SIMTester._skip_pin:
                print("[SIMTester] IMSI couldn't be read (verify the pin?)", file=sys.stderr)
                sys.exit(1)

        print(f"IMSI: {SIMTester.IMSI}")

        msisdn = cfr.read_raw_msisdn()
        SIMTester.MSISDN = cfr.decode_msisdn(msisdn) if msisdn is not None else None

        print(f"MSISDN: {SIMTester.MSISDN}")
        print(f"EF_MANUAREA: {SIMTester.EF_MANUAREA}")
        print(f"EF_DIR: {SIMTester.EF_DIR}")

        if config.third_gen_apdu:
            usim_aid = cfr.get_usim_aid()
            if usim_aid is None:
                raise RuntimeError("There is no USIM available.")

            FileManagement.select_aid(hx.from_string(usim_aid))

            challenge = bytearray(17)
            challenge[0] = 16
            res = authenticate(True, bytes(challenge))  # forced GSM context, we can't provide a valid MAC

            if res.get_sw1() == 0x61:
                res = get_response(res.get_sw2())
                SIMTester.AUTH = "3G_" + hx.to_string(res.get_data())
            elif res.get_sw() == 0x9000:
                SIMTester.AUTH = "3G_" + hx.to_string(res.get_bytes())
            else:
                print(f"\033[96m3G AUTH FAILED, {res.get_sw():04X} returned. Please investigate, fix and try again...\033[0m", file=sys.stderr)
                sys.exit(1)

            ChannelHandler.get_instance().reset()
        else:
            rand = bytes(16)
            res = run_gsm_algo_2g(rand)
            if res.get_sw1() == 0x9F:
                res = get_response(res.get_sw2())
                SIMTester.AUTH = "2G_" + hx.to_string(res.get_data())
            else:
                print(f"\033[96m2G AUTH FAILED, {res.get_sw():04X} returned. Please investigate, fix and try again...\033[0m", file=sys.stderr)
                sys.exit(1)

        print(f"AUTH: {SIMTester.AUTH}")

        deselect_response = Fuzzer.application_de_select()
        SIMTester.AppDeSelect = hx.to_string(deselect_response.get_bytes()) if deselect_response is not None else None
        print(f"AppDeSelect: {SIMTester.AppDeSelect}")

        ChannelHandler.get_instance().reset()

        if AutoTerminalProfile.auto_terminal_profile():
            if SIMTester.DEBUG:
                print("[SIMTester] Automatic Terminal profile initialization SUCCESSFUL!")
        else:
            if SIMTester.DEBUG:
                print("[SIMTester] Automatic Terminal profile initialization FAILED!")

    @staticmethod
    def _fuzz():
        print()
        print("Starting fuzzing!")
        print(f"Fuzzing level: {SIMTester._fuzzing_level}")
        print()

        fuzzers = []
        keysets = None

        if SIMTester._fuzzing_level == "FULL":
            fuzzers.extend(fuzzer_factory.get_all_fuzzers())
            keysets = list(range(16))
        elif SIMTester._fuzzing_level == "QUICK":
            fuzzers = [fuzzer_factory.get_fuzzer(n) for n in (1, 5, 9, 13)]
            keysets = [1, 2, 3, 4, 5, 6]
        elif SIMTester._fuzzing_level == "POKE":
            fuzzers = [fuzzer_factory.get_fuzzer(n) for n in (1, 5, 9, 13)]
            keysets = [1, 2, 3, 4, 5, 6]
            SIMTester._tars = ["RAM:000000", "RFM:B00001", "RFM:B00010"]

        if SIMTester._custom_fuzzers is not None:
            fuzzers = []
            for one_fuzzer in SIMTester._custom_fuzzers:
                if one_fuzzer < 0 or one_fuzzer > fuzzer_factory.get_amount_of_fuzzers():
                    print(f"[SIMTester] Fuzzer(s) you specified does NOT exist, use values 0-{fuzzer_factory.get_amount_of_fuzzers()}!", file=sys.stderr)
                    sys.exit(1)
                fuzzers.append(fuzzer_factory.get_fuzzer(one_fuzzer))

        if SIMTester._custom_keysets is not None:
            keysets = list(SIMTester._custom_keysets)

        if SIMTester._custom_tars is not None:
            SIMTester._tars = list(SIMTester._custom_tars)

        print(f"TAR values to be fuzzed: {SIMTester._tars}")
        print()

        SIMTester._fuzzer = Fuzzer(SIMTester._writer, SIMTester._tars, keysets, fuzzers, sim_tester_module=SIMTester)
        SIMTester._fuzzer.start()
        SIMTester._fuzzer.join()

    @staticmethod
    def _print_summary(fuzzer: Fuzzer):
        print()
        if fuzzer.is_there_a_weakness_found():
            if fuzzer.unprotected_tars_responses or fuzzer.wib_command_executed or fuzzer.sat_command_executed:
                print("\033[91mSIMTester has discovered following weaknesses:\033[0m")
            else:
                print("\033[93mSIMTester has discovered following weaknesses:\033[0m")

            SIMTester._print_result_group(fuzzer.signed_responses, "The following TARs/keysets returned a signed response that may be crackable:",
                                           lambda fr: hx.to_string(fr.response_packet.get_cryptographic_checksum()))
            SIMTester._print_result_group(fuzzer.encrypted_responses, "The following TARs/keysets returned an encrypted response that may be crackable:",
                                           lambda fr: hx.to_string(fr.response_packet.get_bytes()))
            SIMTester._print_result_group(fuzzer.unprotected_tars_responses, "The following TARs/keysets returned a valid response without any security:",
                                           lambda fr: hx.to_string(fr.response_packet.get_bytes()))
            SIMTester._print_result_group(fuzzer.wib_command_executed, "The following TARs/keysets accepted and executed a WIB request without any security:",
                                           lambda fr: hx.to_string(fr.response_packet.get_bytes()))
            SIMTester._print_result_group(fuzzer.sat_command_executed, "The following TARs/keysets accepted and executed a S@T request without any security:",
                                           lambda fr: hx.to_string(fr.response_packet.get_bytes()))
            SIMTester._print_result_group(fuzzer.decryption_oracle_responses, "The following TARs/keysets act as a decryption oracle (decrypted counter value):",
                                           lambda fr: hx.to_string(fr.response_packet.get_bytes()))
        else:
            print("\033[92mSIMTester hasn't detected any weaknesses it tests for.\033[0m")
        print()

    @staticmethod
    def _print_result_group(results, title, value_fn):
        if not results:
            return

        print()
        print(title)
        print(f"{'TAR':<6} {'keyset':>6} {'Response packets' if 'packets' in title or True else ''}")

        results = list(dict.fromkeys(results))  # unique, preserve order
        results.sort(key=fuzzer_result_key)

        previous = None
        for fr in results:
            if previous is not None and previous.command_packet.get_tar() == fr.command_packet.get_tar() and previous.command_packet.get_keyset() == fr.command_packet.get_keyset():
                print(f" {value_fn(fr)}", end="")
            else:
                print(f"\n{hx.to_string(fr.command_packet.get_tar()):<6} {fr.command_packet.get_keyset():>6} {value_fn(fr)}", end="")
            previous = fr
        print()

    # -- misc ---------------------------------------------------------------

    @staticmethod
    def _list_all_cards():
        from smartcard.System import readers as list_readers

        available = list_readers()
        print(f"Terminals connected: {len(available)}")
        for reader in available:
            print(reader)
        print()

        for i, reader in enumerate(available):
            try:
                connection = reader.createConnection()
                connection.connect()
                ChannelHandler.get_instance(i, None)
                print(f"IDX: {i}, ICCID = {cfr.read_iccid()}")
            except Exception:
                pass

    @staticmethod
    def _check_terminal_factory(name: str) -> str | None:
        if name == "PCSC":
            print("Using pcscd daemon to get a SIM card reader")
            return None
        if name == "OsmocomBB":
            raise SystemExit("OsmocomBB support was not ported to Python (no JNI card provider available); use PCSC")
        raise ValueError("Terminal factory (-tf) has to be either PCSC or OsmocomBB!")

    # -- CLI ------------------------------------------------------------

    @staticmethod
    def _build_arg_parser() -> argparse.ArgumentParser:
        p = argparse.ArgumentParser(prog="simtester", add_help=False)
        p.add_argument("-h", "--help", dest="help", action="store_true")
        p.add_argument("-v", "--version", dest="version", action="store_true")
        p.add_argument("-2g", "--2g-cmds", dest="two_g", action="store_true", help="Use 2G APDU format only")
        p.add_argument("-qf", "--quick-fuzz", dest="quick_fuzz", action="store_true")
        p.add_argument("-poke", "--poke-fuzz", dest="poke_fuzz", action="store_true")
        p.add_argument("-d", "--debug", dest="debug", action="store_true")
        p.add_argument("-la", "--list-all", dest="list_all", action="store_true")
        p.add_argument("-of", "--ota-fuzz", dest="ota_fuzz", action="store_true")
        p.add_argument("-ofbf", "--ota-fuzz-bruteforce", dest="ota_fuzz_bruteforce", action="store_true")
        p.add_argument("-nl", "--no-logging", dest="no_logging", action="store_true")
        p.add_argument("-sp", "--skip-pin", dest="skip_pin", action="store_true")
        p.add_argument("-sdr", "--sms-deliver-report", dest="sms_deliver_report", action="store_true")
        p.add_argument("-st", "--scan-tars", dest="scan_tars", action="store_true")
        p.add_argument("-str", "--scan-tars-range", dest="scan_tars_range", action="store_true")
        p.add_argument("-stbs", "--scan-tars-be-smart", dest="scan_tars_be_smart", action="store_true")
        p.add_argument("-stre", "--scan-tars-regexp", dest="scan_tars_regexp", default=None)
        p.add_argument("-sa", "--scan-apdu", dest="scan_apdu", action="store_true")
        p.add_argument("-sal2", "--scan-apdu-level2", dest="scan_apdu_level2", action="store_true")
        p.add_argument("-sfb", "--scan-files-break", dest="scan_files_break", action="store_true")
        p.add_argument("-sffs", "--scan-files-follow-standard", dest="scan_files_follow_standard", action="store_true")
        p.add_argument("-sf", "--scan-files", dest="scan_files", action="store_true")
        p.add_argument("-kic", "--kic", dest="kic", default=None)
        p.add_argument("-kid", "--kid", dest="kid", default=None)
        p.add_argument("-spi1", "--spi1", dest="spi1", default=None)
        p.add_argument("-spi2", "--spi2", dest="spi2", default=None)
        p.add_argument("-vp", "--verify-pin", dest="verify_pin", default=None)
        p.add_argument("-dp", "--disable-pin", dest="disable_pin", default=None)
        p.add_argument("-ri", "--reader-index", dest="reader_index", type=int, default=None)
        p.add_argument("-tf", "--terminal-factory", dest="terminal_factory", default=None)
        p.add_argument("-gsmmap", "--gsmmap", dest="gsmmap", action="store_true")
        p.add_argument("-t", "--tar", dest="tar", nargs="+", metavar="tar", help="TAR(s) to be tested, prefixed with a type, eg. 'RFM:B00010' or 'RAM:000000'")
        p.add_argument("-k", "--keyset", dest="keyset", nargs="+", metavar="keysets", help="keyset(s) to be tested")
        p.add_argument("-f", "--fuzzer", dest="fuzzer", nargs="+", metavar="fuzzers", help="fuzzer(s) to be used")
        p.add_argument("-sfrv", "--sfrv", dest="sfrv", nargs="+", metavar="sfrv", help="File scanning: Add file ID(s) to reserved values")
        return p

    @staticmethod
    def _handle_options(args: list[str]):
        parser = SIMTester._build_arg_parser()
        cmdline = parser.parse_args(args)
        SIMTester.cmdline = cmdline

        if cmdline.help:
            parser.print_help()
            sys.exit(1)

        if cmdline.version:
            print(_VERSION)
            print(config.VERSION)
            sys.exit(0)

        if cmdline.debug:
            SIMTester.DEBUG = True
            _debug.DEBUG = True

        if cmdline.no_logging:
            SIMTester._logging = False

        if cmdline.two_g:
            config.third_gen_apdu = False

        if cmdline.list_all:
            SIMTester._list_all_cards()
            sys.exit(0)

        reader_index = cmdline.reader_index if cmdline.reader_index is not None else 0
        terminal_factory_name = SIMTester._check_terminal_factory(cmdline.terminal_factory) if cmdline.terminal_factory else None
        ChannelHandler.get_instance(reader_index, terminal_factory_name)

        ChannelHandler.get_instance().reset()

        if config.third_gen_apdu:  # auto-detect if the card supports 3G APDUs
            try:
                response = FileManagement.select_file_by_id(bytes([0x3F, 0x00]))
                if response.get_sw() != 0x9000:
                    if response.get_sw() == 0x6E00:
                        print("\033[96m3G APDU FAILED, this card does NOT support 3G, falling back to 2G and auto-retrying..\033[0m", file=sys.stderr)
                        config.third_gen_apdu = False
                    else:
                        print(f"\033[96m3G APDU FAILED, {response.get_sw():04X} returned. Please investigate, fix and try again...\033[0m", file=sys.stderr)
                        sys.exit(1)
                if SIMTester.DEBUG:
                    print(f"[SIMTester] 3G auto-detect returned: {hx.to_string(response.get_bytes())}")
            except Exception as e:
                print(e, file=sys.stderr)
                sys.exit(1)

        ChannelHandler.get_instance().reset()

        if cmdline.disable_pin:
            print("Disabling PIN1/CHV1..")
            simlib_auth.disable_chv(1, cmdline.disable_pin)

        if cmdline.verify_pin:
            print("Verifying PIN1/CHV1..")
            simlib_auth.verify_chv(1, cmdline.verify_pin)

        if cmdline.skip_pin:
            print("Skipping PIN1/CHV1, trying the best we can without it!")
            SIMTester._skip_pin = True

        if cmdline.tar:
            custom_tars = []
            for cmd_tar in cmdline.tar:
                if cmd_tar.startswith(("RFM", "RAM", "WIB", "SAT")):
                    custom_tars.append(cmd_tar)
                else:
                    print(f"[SIMTester] Each TAR has to match a type (RFM, RAM, WIB, SAT), this one does not: {cmd_tar}", file=sys.stderr)
            SIMTester._custom_tars = custom_tars or None

        if cmdline.keyset:
            SIMTester._custom_keysets = SIMTester._get_integer_list(cmdline.keyset)

        if cmdline.scan_files_break and not cmdline.scan_files:
            print("[SIMTester] Option -sfb (scan-files-break) has to be used along with -sf, exiting!", file=sys.stderr)
            sys.exit(1)

        if cmdline.scan_files_follow_standard and not cmdline.scan_files:
            print("[SIMTester] Option -sffs (scan-files-follow-standard) has to be used along with -sf, exiting!", file=sys.stderr)
            sys.exit(1)

        if cmdline.sfrv:
            file_scanner.user_defined_reserved_ids = list(cmdline.sfrv)

        if cmdline.scan_files:
            SIMTester._read_basic_info()

            writer = CSVWriter(SIMTester.ICCID, "FILE", SIMTester._logging)
            writer.write_basic_info(SIMTester.ATR, SIMTester.ICCID, SIMTester.IMSI, SIMTester.MSISDN,
                                     SIMTester.EF_MANUAREA, SIMTester.EF_DIR, SIMTester.AUTH, SIMTester.AppDeSelect)
            file_scanner.scan_sim(cmdline.scan_files_break, cmdline.scan_files_follow_standard, writer)

            writer.unhide_file()
            print("done scanning files, exiting..")
            sys.exit(0)

        if cmdline.scan_tars or cmdline.scan_tars_range:
            SIMTester._action = "TAR"

        if cmdline.scan_apdu:
            SIMTester._action = "APDU"

        if cmdline.ota_fuzz:
            SIMTester._action = "OTA"

        if cmdline.quick_fuzz:
            SIMTester._fuzzing_level = "QUICK"

        if cmdline.poke_fuzz:
            SIMTester._fuzzing_level = "POKE"

        if cmdline.gsmmap:
            SIMTester._gsmmap_upload = True

        if cmdline.fuzzer:
            SIMTester._custom_fuzzers = SIMTester._get_integer_list(cmdline.fuzzer)

        if cmdline.sms_deliver_report:
            Fuzzer.use_sms_submit = False
            TARScanner.use_sms_submit = False

        if cmdline.kic:
            # NOTE: only a single hex nibble is consumed here (matches upstream) -
            # set_fake_kic/kid only ever OR this into the low nibble (the algorithm
            # bits) of KIC/KID, the keyset nibble is untouched.
            Fuzzer.KIC = hx.from_string_to_single_byte(cmdline.kic[0:1])

        if cmdline.kid:
            Fuzzer.KID = hx.from_string_to_single_byte(cmdline.kid[0:1])

        if cmdline.spi1:
            Fuzzer.SPI1 = hx.from_string_to_single_byte(cmdline.spi1[0:2])

        if cmdline.spi2:
            Fuzzer.SPI2 = hx.from_string_to_single_byte(cmdline.spi2[0:2])

    @staticmethod
    def _get_integer_list(strings: list[str]) -> list[int]:
        result = []
        for s in strings:
            try:
                result.append(int(s))
            except ValueError:
                print(f"[SIMTester] Parsing failed! \"{s}\" can not be an converted to an integer, try again!", file=sys.stderr)
                sys.exit(1)
        return result


def main():
    SIMTester.main()


if __name__ == "__main__":
    main()
