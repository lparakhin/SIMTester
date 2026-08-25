"""Port of de.srlabs.simtester.Fuzzer."""

from __future__ import annotations

import threading

from simlib import config
from simlib import debug as _debug
from simlib import hex_toolkit as hx
from simlib.address import Address
from simlib.apdu import CommandAPDU
from simlib.apdu_toolkit import get_response, perform_fetch
from simlib.auto_terminal_profile import AutoTerminalProfile
from simlib.channel_handler import ChannelHandler
from simlib.command_packet import CommandPacket
from simlib.envelope import EnvelopeSMSPPDownload
from simlib.helpers import handle_sim_response
from simlib.logging_utils import format_debug_message
from simlib.proactive_command import ProactiveCommand
from simlib.response_packet import ResponsePacket, ResponsePacketParseError, find_response_packet
from simlib.sms_deliver_tpdu import SMSDeliverTPDU
from simlib.sms_tpdu import SMSTPDU

from .csv_writer import CSVWriter
from .entry_point import EntryPoint
from .fuzzer_result import FuzzerResult


class Fuzzer(threading.Thread):
    _scanned_tar_with_por09 = False
    _skip_tar_on_por09 = False

    KIC: int | None = None
    KID: int | None = None
    SPI1: int | None = None
    SPI2: int | None = None
    use_sms_submit = True

    def __init__(self, writer: CSVWriter, tars: list[str], keysets: list[int], fuzzers: list, sim_tester_module=None):
        super().__init__()
        if writer is None or tars is None or keysets is None or fuzzers is None:
            raise ValueError("writer/TARs/keysets/fuzzers cannot be None!")

        self._writer = writer
        self._tars = tars
        self._keysets = keysets
        self._fuzzers = fuzzers
        self._sim_tester_module = sim_tester_module  # holds ICCID/ATR/etc globals, set by SIMTester
        self._stop_event = threading.Event()

        self.signed_responses: list[FuzzerResult] = []
        self.encrypted_responses: list[FuzzerResult] = []
        self.unprotected_tars_responses: list[FuzzerResult] = []
        self.decryption_oracle_responses: list[FuzzerResult] = []
        self.wib_command_executed: list[FuzzerResult] = []
        self.sat_command_executed: list[FuzzerResult] = []

    def interrupt(self):
        self._stop_event.set()

    def is_interrupted(self) -> bool:
        return self._stop_event.is_set()

    def is_there_a_weakness_found(self) -> bool:
        return (len(self.signed_responses) + len(self.encrypted_responses) + len(self.unprotected_tars_responses)
                + len(self.decryption_oracle_responses) + len(self.wib_command_executed) + len(self.sat_command_executed)) > 0

    def _scan_apdu_on_unprotected_entry_points(self):
        from . import apdu_scanner
        from . import gsmmap_uploader

        st = self._sim_tester_module

        unprotected_entry_points = []
        for fr in self.unprotected_tars_responses:
            # ARD has to be present too, otherwise we're just blind
            if fr.response_packet.get_status_code() == 0x00 and fr.response_packet.are_additional_data_present():
                unprotected_entry_points.append(EntryPoint(fr.command_packet.get_tar(), fr.command_packet.get_keyset(), fr.command_packet, fr.response_packet))

        import functools

        unprotected_entry_points = list(dict.fromkeys(unprotected_entry_points))  # unique, order-preserving
        unprotected_entry_points.sort(key=functools.cmp_to_key(lambda a, b: hx.compare_tars(a.tar, b.tar)))

        if not unprotected_entry_points:
            return

        print()
        print("Going to perform APDU scan on following TARs: ", end="")
        for ep in unprotected_entry_points:
            print(hx.to_string(ep.tar) + " ", end="")
        print()

        writer = CSVWriter(st.ICCID, "APDU", st._logging)
        writer.write_basic_info(st.ATR, st.ICCID, st.IMSI, st.MSISDN, st.EF_MANUAREA, st.EF_DIR, st.AUTH, st.AppDeSelect)

        for ep in unprotected_entry_points:
            try:
                apdu_scanner.run(ep, writer, True, st.cmdline.scan_apdu_level2, self._stop_event)
                if self._stop_event.is_set():
                    break
            except Exception as e:
                print(e)

        if not writer.unhide_file():
            print(format_debug_message(f"Unable to unhide file {writer.get_file_name()}, make sure you rename it so it does NOT start with a dot to get processed!"))
        elif st._gsmmap_upload:
            if gsmmap_uploader.upload_file(writer.get_file_name()):
                print(f"Upload of {writer.get_file_name()} to gsmmap.org successful!")
            else:
                print("There was a problem uploading the result to gsmmap.org")
                print("Please use the form at http://gsmmap.org/upload.html to submit the data manually.")

    def run(self):
        try:
            for tar in self._tars:
                self.logic(tar, self._keysets, self._fuzzers)
                if self._stop_event.is_set():
                    break
            if self.unprotected_tars_responses and not self._stop_event.is_set():
                self._scan_apdu_on_unprotected_entry_points()
        except Exception:
            import traceback
            traceback.print_exc()

    def _fuzz_card(self, cp: CommandPacket):
        smsdeliver = SMSDeliverTPDU()
        smsdeliver.set_tpudhi(True)

        if _debug.DEBUG:
            print(format_debug_message(f"smsdeliver data: {hx.to_string(smsdeliver.get_bytes())}"))

        if Fuzzer.KIC is not None:
            cp.set_fake_kic(Fuzzer.KIC)
        if Fuzzer.KID is not None:
            cp.set_fake_kid(Fuzzer.KID)
        if Fuzzer.SPI1 is not None:
            cp.set_fake_spi1(Fuzzer.SPI1)
        if Fuzzer.SPI2 is not None:
            cp.set_fake_spi2(Fuzzer.SPI2)

        smsdeliver.set_tpud(cp.get_bytes())

        smstpdu = SMSTPDU(smsdeliver.get_bytes())
        addr = Address(hx.from_string("86050021436587" if config.third_gen_apdu else "06050021436587"))

        env = EnvelopeSMSPPDownload(addr, smstpdu)
        envelope = env.get_apdu()

        if _debug.DEBUG:
            print(format_debug_message(f"Envelope content: {hx.to_string(envelope.get_bytes())}"))

        return ChannelHandler.transmit_on_default_channel(envelope)

    @staticmethod
    def generate_command_packet(keyset: int, counter_management: int, kic_algo: int, kid_algo: int, tar: str,
                                 request_por: bool, cipher_por: bool) -> CommandPacket:
        if _debug.DEBUG:
            print(format_debug_message(
                f"called generate_command_packet(keyset={keyset}, counterManagement={counter_management}, "
                f"KICAlgo={kic_algo}, KIDAlgo={kid_algo}, TAR={tar}, requestPoR={request_por}, cipherPoR={cipher_por})"))

        tar_type, tar_hex = tar.split(":")

        cp = CommandPacket()
        cp.set_keyset(keyset)

        cp.set_kid_algo(kid_algo)
        if kid_algo == CommandPacket.KID_ALGO_DES_CBC:
            cp.set_cryptographic_checksum(True, hx.from_string("0000000000000000"))
        elif kid_algo == CommandPacket.KID_ALGO_3DES_CBC_2KEYS:
            cp.set_cryptographic_checksum(True, hx.from_string("00000000000000000000000000000000"))
        elif kid_algo == CommandPacket.KID_ALGO_3DES_CBC_3KEYS:
            cp.set_cryptographic_checksum(True, hx.from_string("000000000000000000000000000000000000000000000000"))

        cp.set_kic_algo(kic_algo)
        if kic_algo == CommandPacket.KIC_ALGO_DES_CBC:
            cp.set_ciphering(True, hx.from_string("0000000000000000"), False)
        elif kic_algo == CommandPacket.KIC_ALGO_3DES_CBC_2KEYS:
            cp.set_ciphering(True, hx.from_string("00000000000000000000000000000000"), False)
        elif kic_algo == CommandPacket.KIC_ALGO_3DES_CBC_3KEYS:
            cp.set_ciphering(True, hx.from_string("000000000000000000000000000000000000000000000000"), False)

        cp.set_counter_management(counter_management)
        if counter_management == CommandPacket.CNTR_NO_CNTR_AVAILABLE:
            cp.set_counter(0)
        else:
            cp.set_counter(1)

        if request_por:
            cp.set_por(True)

            if cipher_por:
                cp.set_por_ciphering(True)
            else:
                cp.set_por_security(CommandPacket.POR_SECURITY_CC)

            if Fuzzer.use_sms_submit:
                cp.set_por_mode(CommandPacket.POR_MODE_SMS_SUBMIT)
            else:
                cp.set_por_mode(CommandPacket.POR_MODE_SMS_DELIVER_REPORT)

        cp.set_tar(hx.from_string(tar_hex))

        if tar_type == "RFM":
            cp.set_user_data(hx.from_string("A0A40000023F00"))  # 2G selectFile MF (MasterFile)
        elif tar_type == "RAM":
            cp.set_user_data(hx.from_string("80E60200160BA000000000123456789010000006EF04C602000000"))  # Install for Load
        elif tar_type == "WIB":
            cp.set_user_data(hx.from_string("0016100102140801912143658709F0200500000001010600"))  # SETUP CALL +12345678900
        elif tar_type == "SAT":
            cp.set_user_data(hx.from_string("42230121020744382E3130353105160604313035312D0C1003830607912143658709F02B00"))  # SETUP CALL +12345678900
        else:
            raise SystemExit(format_debug_message(f"Unsupported TAR type: {tar_type}, exiting.."))

        return cp

    def logic(self, tar: str, keysets: list[int], fuzzers: list):
        for fuzzer in fuzzers:
            if self._stop_event.is_set():
                break

            fuzzer_name = fuzzer.name

            for keyset in keysets:
                if self._stop_event.is_set():
                    break

                cp = self.generate_command_packet(keyset, fuzzer.counter, fuzzer.kic, fuzzer.kid, tar, fuzzer.request_por, fuzzer.cipher_por)

                try:
                    response = self._fuzz_card(cp)
                except Exception:
                    print(format_debug_message("Card probably crashed, skipping keyset.."))
                    continue

                if response.get_sw1() == 0x90 and response.get_sw2() == 0x00:
                    print(f"\033[90mfuzzer: {fuzzer_name}, TAR: {hx.to_string(cp.get_tar())}, keyset: {keyset} - no PoR packet even if requested (SW: 0x9000)\033[0m")
                    self._writer.write_line(fuzzer_name, cp.get_bytes(), response.get_bytes())
                    continue

                response_data = get_ota_response(response, cp, self._writer, fuzzer, tar, keyset)

                if response_data is None:
                    print("Unable to locate Response Packet Header in fetched data, skipping..")
                    continue

                if response_data[0] == 0xD0:
                    rp = ResponsePacket()
                    rp.parse(response_data, strict=False)
                    if tar == "SAT:505348":
                        self.sat_command_executed.append(FuzzerResult(cp, fuzzer, rp))
                    else:
                        self.wib_command_executed.append(FuzzerResult(cp, fuzzer, rp))
                    print(f"\033[91mfuzzer: {fuzzer_name}, TAR: {hx.to_string(cp.get_tar())}, keyset: {cp.get_keyset()}, "
                          f"Command executed, response: {hx.to_string(response_data)} -> CRITICAL WEAKNESS FOUND\033[0m")
                    continue

                if not self.handle_response_data(cp, response_data, fuzzer):
                    return  # skip this TAR completely

        # If we've already scanned a TAR that returned PoR 09, skip all others as they
        # won't show different signatures - unless the card leaks even on PoR 0x09.
        if Fuzzer._scanned_tar_with_por09:
            por09_leaks = False

            for encrypted in self.encrypted_responses:
                if encrypted.response_packet.get_status_code() == 0x09 and encrypted.response_packet.is_encrypted() and encrypted.response_packet.are_additional_data_present():
                    por09_leaks = True

            for signed in self.signed_responses:
                if signed.response_packet.get_status_code() == 0x09 and not signed.response_packet.is_encrypted() and signed.response_packet.is_cryptographic_checksum_present():
                    por09_leaks = True

            if not por09_leaks:
                Fuzzer._skip_tar_on_por09 = True
            else:
                print("Process will not skip PoR 0x09 as card leaks even on PoR 0x09, let's gather all that.")

    def handle_response_data(self, cp: CommandPacket, response_data: bytes, fuzzer) -> bool:
        rp = ResponsePacket()

        try:
            rp.parse(response_data, cp.get_por_counter())
        except ResponsePacketParseError as e:
            print("Parse exception while parsing response packet, skipping it! details:")
            print(e)
            return True

        warning = False
        critical = False
        status_code = rp.get_status_code()

        if rp.is_encrypted():  # pointless to test for PoR if encrypted
            warning = True
            self.encrypted_responses.append(FuzzerResult(cp, fuzzer, rp))
        elif status_code in (0x00, 0x02, 0x03):  # PoR OK / CNTR low / CNTR high
            critical = True
            self.unprotected_tars_responses.append(FuzzerResult(cp, fuzzer, rp))

        por_cc = None
        if rp.is_cryptographic_checksum_present() and not rp.is_encrypted():
            if hx.to_string(rp.get_cryptographic_checksum()) != "0000000000000000":
                warning = True
                self.signed_responses.append(FuzzerResult(cp, fuzzer, rp))
            por_cc = hx.to_string(rp.get_cryptographic_checksum())

        fuzzer_name = fuzzer.name

        if status_code == 0x09 and not rp.is_encrypted():
            Fuzzer._scanned_tar_with_por09 = True
            if Fuzzer._skip_tar_on_por09:
                print(f"\033[90mfuzzer: {fuzzer_name}, TAR: {hx.to_string(cp.get_tar())} -> unknown to card (PoR 0x09), already scanned, skipping..\033[0m")
                return False

        if rp.is_decrypted_counter():  # decryption oracle (decrypted counter from command)
            warning = True
            self.decryption_oracle_responses.append(FuzzerResult(cp, fuzzer, rp))

        prefix = "\033[91m" if critical else ("\033[93m" if warning else "\033[90m")
        line = prefix

        if rp.is_encrypted():
            line += f"fuzzer: {fuzzer_name}, TAR: {hx.to_string(cp.get_tar())}, keyset: {cp.get_keyset()}, ResponsePacket: {hx.to_string(response_data)}"
        else:
            line += f"fuzzer: {fuzzer_name}, TAR: {hx.to_string(cp.get_tar())}, keyset: {cp.get_keyset()}, PoR: {hx.to_string(status_code)}, PoR CC: {por_cc}"
            if rp.are_additional_data_present():
                line += f", ARD: {hx.to_string(rp.get_additional_data())}"

        if critical:
            line += " -> CRITICAL WEAKNESS FOUND\033[0m"
        elif warning:
            line += " -> WEAKNESS FOUND\033[0m"
        else:
            line += "\033[0m"

        print(line)

        return True

    @staticmethod
    def application_de_select():
        # Lc=0, so we build the raw bytes directly (no auto Ne handling)
        sel = CommandAPDU(bytes([0x00, 0xA4, 0x04, 0x00, 0x00]))
        return ChannelHandler.transmit_on_default_channel(sel, retry=False)  # never retry, just skip on failure

    @staticmethod
    def _get_ota_response_impl(response, cp, writer, fuzzer, tar, keyset):
        return get_ota_response(response, cp, writer, fuzzer, tar, keyset)


def get_ota_response(response, cp, writer, fuzzer, tar, keyset) -> bytes | None:
    response_data = None
    fuzzer_name = fuzzer.name

    sw1 = response.get_sw1()

    if sw1 in (0x9E, 0x9F) or (config.third_gen_apdu and sw1 in (0x62, 0x61)):
        getresponse_response = get_response(response.get_sw2())
        response_data = getresponse_response.get_data()
        writer.write_line(fuzzer_name, cp.get_bytes(), getresponse_response.get_bytes())
    elif sw1 == 0x91:
        fetch_response = perform_fetch(response.get_sw2())
        fetched_data = fetch_response.get_data()
        print(f"\033[90mfuzzer: {fuzzer_name}, TAR: {tar}, keyset: {keyset} - card responded with FETCH, "
              f"fetched_data = {hx.to_string(fetched_data)}, response word: {fetch_response.get_sw():04X}\033[0m")
        writer.write_line(fuzzer_name, cp.get_bytes(), fetch_response.get_bytes())

        if fetched_data and fetched_data[0] == 0xD0:
            try:
                pc = ProactiveCommand(fetched_data)

                summary = pc.get_summary()
                if summary:
                    print(f"\033[90mProactive command (\033[95m{pc.get_type()}\033[90m) identified, details: \033[95m{summary}\033[90m; trying to handle it..\033[0m")
                else:
                    print(f"\033[90mProactive command (\033[95m{pc.get_type()}\033[90m) identified, trying to handle it..\033[0m")

                if pc.get_type() == "SETUP CALL":
                    AutoTerminalProfile.handle_proactive_command(fetch_response)
                    return fetched_data
            except ValueError:
                print(format_debug_message("Unable to parse ProactiveCommand, skipping its handling, this may get ugly !!!"))

            handled_response = AutoTerminalProfile.handle_proactive_command(fetch_response)

            limit = 0
            while handled_response.get_sw() != 0x9000 and limit < 10:
                print(f"\033[95mWARNING! Response (SW) to terminal response apdu is not 0x9000: {hx.to_string(handled_response.get_bytes())}\033[0m")
                handled_response = handle_sim_response(handled_response, True)
                limit += 1

            if limit == 10:
                raise SystemExit("FATAL ERROR: endless loop while handling response! SCAN IS INCOMPLETE! FIX THIS!")

        response_data = find_response_packet(fetched_data)

    return response_data
