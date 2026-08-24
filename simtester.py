#!/usr/bin/env python3
# -*- coding: ascii -*-
"""Standalone Python SIMTester: codecs, transports, scanners, CLI, and menu."""
from __future__ import annotations

import argparse
import importlib.util
import json
import time
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Protocol, Sequence

__version__ = "0.2.0"


class PacketError(ValueError):
    """An OTA packet is structurally invalid."""


@dataclass
class CommandPacket:
    """A fuzzer-compatible, non-cryptographic 3GPP TS 03.48 command packet."""

    tar: bytes
    keyset: int = 0
    counter: int = 0
    user_data: bytes = b""
    counter_management: int = 0
    kic_algorithm: int = 0
    kid_algorithm: int = 0
    request_por: bool = True
    cipher_por: bool = False
    por_mode_submit: bool = False
    fake_spi1: int | None = None
    fake_spi2: int | None = None
    fake_kic: int | None = None
    fake_kid: int | None = None

    HEADER = b"\x02\x70\x00"

    def __post_init__(self) -> None:
        if len(self.tar) != 3:
            raise PacketError("TAR must be exactly three bytes")
        if not 0 <= self.keyset <= 15:
            raise PacketError("keyset must be between 0 and 15")
        if not 0 <= self.counter < 1 << 40:
            raise PacketError("counter must fit in five bytes")
        if not 0 <= self.counter_management <= 3:
            raise PacketError("counter management must be between 0 and 3")

    @staticmethod
    def _algorithm_nibble(algorithm: int, *, kic: bool) -> int:
        table = {0: 0, 1: 1, 2: 5, 3: 9}
        if kic:
            table[4] = 13
        if algorithm not in table:
            raise PacketError(f"unsupported {'KIC' if kic else 'KID'} algorithm {algorithm}")
        return table[algorithm]

    @property
    def spi1(self) -> int:
        return (self.counter_management & 3) << 3

    @property
    def spi2(self) -> int:
        return ((1 if self.request_por else 0) | (0x10 if self.cipher_por else 0)
                | (0x20 if self.por_mode_submit else 0))

    @property
    def kic(self) -> int:
        return self.keyset << 4 | self._algorithm_nibble(self.kic_algorithm, kic=True)

    @property
    def kid(self) -> int:
        return self.keyset << 4 | self._algorithm_nibble(self.kid_algorithm, kic=False)

    def to_bytes(self) -> bytes:
        spi1 = self.spi1 if self.fake_spi1 is None else self.fake_spi1
        spi2 = self.spi2 if self.fake_spi2 is None else self.fake_spi2
        kic = self.kic if self.fake_kic is None else self.keyset << 4 | self.fake_kic & 15
        kid = self.kid if self.fake_kid is None else self.keyset << 4 | self.fake_kid & 15
        body = (bytes((13, spi1, spi2, kic, kid)) + self.tar
                + self.counter.to_bytes(5, "big") + b"\0" + self.user_data)
        return self.HEADER + len(body).to_bytes(2, "big") + body

    @classmethod
    def parse(cls, data: bytes) -> CommandPacket:
        if len(data) < 19 or data[:3] != cls.HEADER:
            raise PacketError("command packet header missing or packet too short")
        if int.from_bytes(data[3:5], "big") != len(data) - 5:
            raise PacketError("CPL does not match packet length")
        if data[5] != 13:
            raise PacketError("only non-checksummed command headers are supported")
        spi1, spi2, kic, kid = data[6:10]
        reverse = {0: 0, 1: 1, 5: 2, 9: 3, 13: 4}
        if kic >> 4 != kid >> 4:
            raise PacketError("KIC and KID keysets differ")
        if kic & 15 not in reverse or kid & 15 not in reverse:
            raise PacketError("unknown KIC/KID algorithm")
        return cls(data[10:13], kic >> 4, int.from_bytes(data[13:18], "big"), data[19:],
                   (spi1 >> 3) & 3, reverse[kic & 15], reverse[kid & 15],
                   (spi2 & 3) == 1, bool(spi2 & 0x10), bool(spi2 & 0x20))


# Curated probe corpus retained from SIMTester. "RFM" contains common remote
# file-management and vendor/proprietary applet candidates; a TAR is not proof
# that a specific vendor or application is installed.
KNOWN_TAR_GROUPS: dict[str, tuple[str, ...]] = {
    "RAM": tuple("000000".split()),  # Remote Application Management
    "WIB": tuple("000001 000002 000003 000004 000005 000006 000007 000008 000009 BFFF00\nBFFF01 BFFF02 BFFF03 BFFF04 BFFF05 BFFF15 BFFF22 BFFFBA BFFFEE BFFFFF".split()),  # Wireless Internet Browser
    "SAT": tuple("505348 534054".split()),  # S@T Browser
    "RFM": tuple("00000A 00000B 00000C 00000D 00004F 000057 000070 000076 000080 000092\n0000B6 0000E2 000203 000304 000503 010001 010101 010203 012345 012347\n060504 100000 111212 212223 260500 313131 385300 3F0000 3F0001 3F0002\n3F0010 3F0011 41444E 414C4F 415256 415345 424950 425058 434354 443231\n474341 47534D 484353 49434D 494D45 4C5041 4D4552 4D4C4D 4E4147 4E5550\n4E5553 4E5650 4F4350 504F53 514F43 524144 524648 524A49 54454C 524F4D\n533347 534143 534441 534F44 53534D 535353 564153 64646D 800001 800002\n800040 800041 B00000 B00001 B00002 B00003 B0000F B00010 B00011 B00012\nB00013 B00020 B00021 B00030 B00040 B00041 B00042 B00050 B000F1 B00120\nB00140 B00141 B00142 B00143 B00144 B00145 B11000 B20100 B20102 BAFE02\nC00000 C0013D C001AA C001AB C001AD D00003 EED200 EED201 EEE200 EEE201\nFFFF01 FFFFFF".split()),  # RFM/vendor applet candidates
}


def known_tar_packets(keyset: int = 0, groups: Iterable[str] | None = None) -> Iterator[tuple[str, CommandPacket]]:
    """Yield labeled OTA packets for the curated S@T, WIB, RAM and vendor corpus."""
    selected = tuple(groups) if groups is not None else tuple(KNOWN_TAR_GROUPS)
    for group in selected:
        if group not in KNOWN_TAR_GROUPS:
            raise ValueError(f"unknown TAR group {group}; choose RAM, WIB, SAT or RFM")
        for value in KNOWN_TAR_GROUPS[group]:
            yield group, CommandPacket(bytes.fromhex(value), keyset=keyset, user_data=b"\0" * 5)


def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) <= 0x7F:
        length = bytes((len(value),))
    elif len(value) <= 0xFF:
        length = bytes((0x81, len(value)))
    else:
        length = b"\x82" + len(value).to_bytes(2, "big")
    return bytes((tag,)) + length + value


def build_sms_pp_download_apdu(packet: CommandPacket, *, third_gen: bool = True,
                               pid: int = 0x7F, dcs: int = 0xF6,
                               udhi: bool = True) -> bytes:
    """Wrap an OTA packet in an SMS-PP DOWNLOAD ENVELOPE APDU."""
    command_packet = packet.to_bytes()
    # SMS-DELIVER: UDHI, fixed test originator, SIM data-download PID/DCS.
    first_octet = 0x04 | (0x40 if udhi else 0)
    tpdu = (bytes((first_octet,)) + b"\x05\x00\x21\x43\xF5" + bytes((pid, dcs)) + b"\0" * 7
            + bytes((len(command_packet),)) + command_packet)
    device_identities = bytes((0x82 if third_gen else 0x02, 0x02, 0x83, 0x81))
    address = bytes.fromhex("86050021436587" if third_gen else "06050021436587")
    sms_tpdu = bytes((0x8B if third_gen else 0x0B, len(tpdu))) + tpdu
    envelope = _tlv(0xD1, device_identities + address + sms_tpdu)
    if len(envelope) > 255:
        raise PacketError("SMS-PP envelope exceeds short APDU length")
    return bytes((0x80 if third_gen else 0xA0, 0xC2, 0x00, 0x00, len(envelope))) + envelope


FUZZER_PROFILES = (
    (0, 0, 0, False, False), (0, 0, 0, True, False),
    (1, 0, 0, True, False), (2, 0, 0, True, False),
    (3, 0, 0, True, False), (3, 0, 1, True, False),
    (3, 0, 2, True, False), (3, 0, 3, True, False),
    (3, 3, 3, True, False), (0, 0, 0, True, True),
    (1, 0, 0, True, True), (2, 0, 0, True, True),
    (3, 0, 0, True, True), (3, 1, 0, True, True),
    (3, 2, 0, True, True), (3, 3, 0, True, True),
    (3, 3, 3, True, True),
)


def standard_fuzzer_packets(tars: Iterable[str], keysets: Iterable[int]) -> Iterator[tuple[str, CommandPacket]]:
    """Generate the original 17 standard fuzzing mechanisms."""
    for tar in tars:
        tar_bytes = bytes.fromhex(tar)
        for keyset in keysets:
            for index, (counter, kic, kid, por, cipher_por) in enumerate(FUZZER_PROFILES):
                yield f"F{index:02d}/K{keyset}", CommandPacket(
                    tar_bytes, keyset, user_data=b"\0" * 5,
                    counter_management=counter, kic_algorithm=kic,
                    kid_algorithm=kid, request_por=por, cipher_por=cipher_por,
                )


@dataclass(frozen=True)
class ResponsePacket:
    tar: bytes | None
    counter: int | None
    padding_counter: int
    status_code: int
    checksum: bytes | None
    additional_data: bytes
    raw: bytes
    proprietary: bool = False

    HEADER = b"\x02\x71\x00"
    PROPRIETARY_HEADER = b"\x02\x7f\x00"

    @classmethod
    def parse(cls, source: bytes, *, strict: bool = True) -> ResponsePacket:
        standard_at = source.find(cls.HEADER)
        proprietary_at = source.find(cls.PROPRIETARY_HEADER)
        positions = [(p, proprietary) for p, proprietary in
                     ((standard_at, False), (proprietary_at, True)) if p >= 0]
        if not positions:
            raise PacketError("response packet header not found")
        start, proprietary = min(positions)
        data = source[start:]
        if proprietary:
            if strict:
                raise PacketError("proprietary 027F00 response rejected in strict mode")
            if len(data) < 19:
                raise PacketError("proprietary response is too short")
            return cls(None, None, 0, data[18], None, b"", data, True)
        if len(data) < 16:
            raise PacketError("response packet is too short")
        declared = int.from_bytes(data[3:5], "big")
        actual = len(data) - 5
        if declared > actual:
            raise PacketError("RPL exceeds available data")
        if strict and declared != actual:
            raise PacketError("RPL does not match packet length")
        data = data[:declared + 5]
        rhl = data[5]
        if rhl not in (10, 18):
            raise PacketError("RHL must be 10 or 18")
        checksum = data[16:24] if rhl == 18 else None
        pcounter = data[14]
        if pcounter > declared - rhl - 1:
            raise PacketError("padding counter exceeds payload")
        if pcounter and any(data[-pcounter:]):
            raise PacketError("padding bytes must be zero")
        end = -pcounter if pcounter else None
        payload = data[24 if checksum else 16:end]
        return cls(data[6:9], int.from_bytes(data[9:14], "big"), pcounter,
                   data[15], checksum, payload, data)

    @property
    def has_additional_data(self) -> bool:
        return bool(self.additional_data)


@dataclass(frozen=True)
class APDUResponse:
    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> int:
        return self.sw1 << 8 | self.sw2


@dataclass(frozen=True)
class StatusWordInfo:
    meaning: str
    category: str
    standard: str


def decode_status_word(sw1: int, sw2: int) -> StatusWordInfo:
    """Decode ISO/ETSI/3GPP UICC status words also used by GSMA profiles."""
    sw = sw1 << 8 | sw2
    exact = {
        0x9000: ("Command completed successfully", "success"),
        0x6282: ("End of file or record reached before reading Le bytes", "warning"),
        0x6283: ("Selected file invalidated/deactivated", "warning"),
        0x6285: ("Selected file is in termination state", "warning"),
        0x6700: ("Wrong command length", "error"),
        0x6881: ("Logical channel not supported", "unsupported"),
        0x6882: ("Secure messaging not supported", "unsupported"),
        0x6982: ("Security status not satisfied", "security"),
        0x6983: ("Authentication method blocked", "security"),
        0x6984: ("Referenced data invalidated", "security"),
        0x6985: ("Conditions of use not satisfied", "security"),
        0x6986: ("Command not allowed (no current EF or command context)", "supported-command"),
        0x6988: ("Secure messaging data objects incorrect", "security"),
        0x6A80: ("Incorrect parameters in command data", "supported-command"),
        0x6A81: ("Function not supported", "unsupported"),
        0x6A82: ("File or application not found", "supported-command"),
        0x6A83: ("Record not found", "supported-command"),
        0x6A84: ("Not enough memory space", "error"),
        0x6A86: ("Incorrect P1/P2 parameters", "supported-command"),
        0x6A87: ("Lc inconsistent with P1/P2", "supported-command"),
        0x6A88: ("Referenced data not found", "supported-command"),
        0x6B00: ("Wrong P1/P2 parameters", "supported-command"),
        0x6D00: ("Instruction code (INS) not supported or invalid", "unsupported"),
        0x6E00: ("Class byte (CLA) not supported", "unsupported"),
        0x6F00: ("No precise diagnosis", "error"),
        0x9300: ("SIM Application Toolkit is busy", "warning"),
        0x9400: ("No EF selected", "supported-command"),
        0x9402: ("Out of range or invalid address", "supported-command"),
        0x9404: ("File ID or pattern not found", "supported-command"),
        0x9802: ("No PIN/CHV initialized", "security"),
        0x9804: ("Access condition not fulfilled", "security"),
        0x9808: ("PIN/CHV status contradiction", "security"),
        0x9840: ("PIN/CHV or authentication key blocked", "security"),
    }
    if sw in exact:
        meaning, category = exact[sw]
        standard = "ETSI TS 102 221 / 3GPP TS 31.101"
        if sw1 in (0x93, 0x94, 0x98):
            standard = "3GPP TS 11.11 legacy SIM"
        return StatusWordInfo(meaning, category, standard)
    if sw1 == 0x61:
        return StatusWordInfo(f"{sw2 or 256} response bytes available", "response-available",
                              "ISO/IEC 7816-4 / ETSI TS 102 221")
    if sw1 == 0x91:
        return StatusWordInfo(f"Command successful; {sw2 or 256} proactive command bytes available",
                              "proactive", "ETSI TS 102 223 / 3GPP TS 31.111")
    if sw1 == 0x9F:
        return StatusWordInfo(f"Command successful; {sw2 or 256} GET RESPONSE bytes available",
                              "response-available", "3GPP TS 11.11 legacy SIM")
    if sw1 == 0x62:
        return StatusWordInfo("Warning: non-volatile memory unchanged", "warning",
                              "ISO/IEC 7816-4 / ETSI TS 102 221")
    if sw1 == 0x63:
        retries = sw2 & 0x0F
        meaning = f"Verification failed; {retries} retries remaining" if sw2 & 0xF0 == 0xC0 else "Warning: non-volatile memory changed"
        return StatusWordInfo(meaning, "security" if sw2 & 0xF0 == 0xC0 else "warning",
                              "ISO/IEC 7816-4 / ETSI TS 102 221")
    if sw1 == 0x64:
        return StatusWordInfo("Execution error; non-volatile memory unchanged", "error", "ISO/IEC 7816-4")
    if sw1 == 0x65:
        return StatusWordInfo("Execution error; non-volatile memory changed", "error", "ISO/IEC 7816-4")
    if sw1 == 0x6C:
        return StatusWordInfo(f"Wrong Le; exact length is {sw2 or 256}", "supported-command", "ISO/IEC 7816-4")
    return StatusWordInfo("Unknown or application-specific status word", "unknown",
                          "Consult card application and GSMA profile specification")


class CardTransport(Protocol):
    def transmit(self, apdu: bytes) -> APDUResponse: ...
    def close(self) -> None: ...


class MockTransport:
    def __init__(self, handler: Callable[[bytes], APDUResponse]):
        self.handler = handler

    def transmit(self, apdu: bytes) -> APDUResponse:
        return self.handler(apdu)

    def close(self) -> None:
        pass


class PCSCTransport:
    """Optional pyscard-backed PC/SC transport."""

    @staticmethod
    def _reader_objects() -> list[object]:
        if importlib.util.find_spec("smartcard") is None:
            raise RuntimeError("PC/SC requires the optional 'pyscard' package")
        from smartcard.System import readers
        try:
            return list(readers())
        except Exception as exc:
            raise RuntimeError(f"Unable to list PC/SC readers: {exc}") from exc

    @classmethod
    def readers(cls) -> list[str]:
        return [str(reader) for reader in cls._reader_objects()]

    @staticmethod
    def _connect(connection: object) -> None:
        try:
            connection.connect()
        except Exception as exc:
            raise RuntimeError(
                "Unable to connect to the smart card. Ensure the card is inserted "
                f"and stable in the reader. PC/SC reported: {exc}"
            ) from exc

    def __init__(self, reader_index: int = 0):
        available = self._reader_objects()
        if not 0 <= reader_index < len(available):
            raise RuntimeError(f"reader {reader_index} unavailable; found {len(available)}")
        self.connection = available[reader_index].createConnection()
        self._connect(self.connection)

    def transmit(self, apdu: bytes) -> APDUResponse:
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        return APDUResponse(bytes(data), sw1, sw2)

    def reconnect(self) -> None:
        """Reconnect after a transient PC/SC communication failure."""
        try:
            self.connection.disconnect()
        except Exception:
            pass
        self._connect(self.connection)

    def close(self) -> None:
        self.connection.disconnect()


@dataclass(frozen=True)
class ScanFinding:
    value: int
    response: APDUResponse


APDUTraceValue = APDUResponse | Exception | None
APDUTrace = Callable[[int, int, bytes, APDUTraceValue, bool | None], None]


def scan_apdus(transport: CardTransport, *, level2: bool = False,
               interesting: Callable[[APDUResponse], bool] | None = None,
               trace: APDUTrace | None = None, retries: int = 2,
               max_consecutive_errors: int = 10) -> Iterator[ScanFinding]:
    """Probe CLA/INS values, tracing every exchange and yielding supported ones."""
    if retries < 0 or max_consecutive_errors < 1:
        raise ValueError("retries must be non-negative and max errors must be positive")
    predicate = interesting or (lambda response: response.sw not in {0x6E00, 0x6D00, 0x6881, 0x6882})
    total = 256 * 256 if level2 else 256
    sequence = 0
    consecutive_errors = 0

    def transmit(command: bytes, sequence: int) -> tuple[APDUResponse | None, Exception | None]:
        last_error = None
        for attempt in range(retries + 1):
            if trace is not None:
                trace(sequence, total, command, None, None)
            try:
                return transport.transmit(command), None
            except Exception as exc:
                last_error = exc
                will_retry = attempt < retries
                if trace is not None:
                    trace(sequence, total, command, exc, will_retry)
                if will_retry:
                    reconnect = getattr(transport, "reconnect", None)
                    if reconnect is not None:
                        try:
                            reconnect()
                        except Exception:
                            pass
                    time.sleep(0.1)
        return None, last_error

    for cla in range(256):
        for instruction in range(256) if level2 else (0,):
            sequence += 1
            command = bytes((cla, instruction, 0, 0))
            response, last_error = transmit(command, sequence)
            if response is None:
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    raise RuntimeError(
                        f"scan stopped after {consecutive_errors} consecutive communication errors; "
                        f"last error: {last_error}"
                    )
                continue
            consecutive_errors = 0
            combined_data = response.data
            followups = 0
            response_traced = False
            while response.sw1 == 0x61 and followups < 8:
                if trace is not None and followups == 0:
                    trace(sequence, total, command, response, None)
                # ISO/IEC 7816-4 GET RESPONSE. SW2=00 encodes the maximum short Le.
                get_response = bytes((command[0], 0xC0, 0x00, 0x00, response.sw2))
                followup, last_error = transmit(get_response, sequence)
                if followup is None:
                    response = APDUResponse(combined_data, response.sw1, response.sw2)
                    break
                combined_data += followup.data
                response = APDUResponse(combined_data, followup.sw1, followup.sw2)
                followups += 1
                if trace is not None:
                    trace(sequence, total, get_response, followup,
                          predicate(response) if response.sw1 != 0x61 else None)
                response_traced = True
            is_interesting = predicate(response)
            if trace is not None and not response_traced:
                trace(sequence, total, command, response, is_interesting)
            if is_interesting:
                yield ScanFinding(cla << 8 | instruction, response)


def tar_values(ranges: Iterable[tuple[int, int]], start: int = 0) -> Iterator[int]:
    for low, high in ranges:
        if not 0 <= low <= high <= 0xFFFFFF:
            raise ValueError("TAR range must fit in three bytes")
        yield from range(max(low, start), high + 1)


def build_tar_packets(ranges: Iterable[tuple[int, int]], *, keyset: int = 0,
                      start: int = 0, user_data: bytes = b"\0" * 5) -> Iterator[CommandPacket]:
    for value in tar_values(ranges, start):
        yield CommandPacket(value.to_bytes(3, "big"), keyset=keyset, user_data=user_data)


def _hex(prompt: str, *, length: int | None = None, default: str = "") -> bytes:
    value = input(prompt).strip() or default
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise PacketError("enter hexadecimal bytes, for example B00010") from exc
    if length is not None and len(result) != length:
        raise PacketError(f"value must be exactly {length} bytes")
    return result


def _read_int(prompt: str, default: int = 0, base: int = 10) -> int:
    value = input(prompt).strip()
    return default if not value else int(value, base)


def _select_reader(reader_names: Sequence[str] | None = None,
                   input_fn: Callable[[str], str] = input) -> int:
    """Display available PC/SC readers and return a validated selection."""
    names = list(PCSCTransport.readers() if reader_names is None else reader_names)
    if not names:
        raise RuntimeError("No PC/SC smart-card readers were found")
    print("\nAvailable SIM readers:")
    for index, name in enumerate(names):
        print(f"  {index}. {name}")
    while True:
        value = input_fn("Select reader [0]: ").strip()
        try:
            selected = 0 if not value else int(value)
        except ValueError:
            print("Enter a numeric reader index.")
            continue
        if 0 <= selected < len(names):
            print(f"Selected reader {selected}: {names[selected]}")
            return selected
        print(f"Reader index must be between 0 and {len(names) - 1}.")


def _print_response(packet: ResponsePacket) -> None:
    print(json.dumps({"tar": packet.tar.hex().upper() if packet.tar else None,
                      "counter": packet.counter, "padding_counter": packet.padding_counter,
                      "status_code": packet.status_code,
                      "checksum": packet.checksum.hex().upper() if packet.checksum else None,
                      "additional_data": packet.additional_data.hex().upper(),
                      "proprietary": packet.proprietary}, indent=2))


def _run_scan(reader: int, level2: bool) -> None:
    mode = "level 2 (CLA and INS)" if level2 else "level 1 (CLA)"
    reader_names = PCSCTransport.readers()
    if not 0 <= reader < len(reader_names):
        raise RuntimeError(f"reader {reader} unavailable; found {len(reader_names)}")
    print(f"SCAN START: {mode}; reader {reader}: {reader_names[reader]}", flush=True)
    status_counts: Counter[int] = Counter()
    category_counts: Counter[str] = Counter()
    error_count = 0

    def screen_trace(sequence: int, total: int, command: bytes,
                     response: APDUTraceValue, found: bool | None) -> None:
        nonlocal error_count
        if response is None:
            print(f"[{sequence:05d}/{total:05d}] TX APDU={command.hex().upper()}", flush=True)
            return
        if isinstance(response, Exception):
            error_count += 1
            action = "retrying" if found else "SKIPPED"
            print(f"[{sequence:05d}/{total:05d}] ERROR {type(response).__name__}: "
                  f"{response} - {action}", flush=True)
            return
        data = response.data.hex().upper() or "<empty>"
        info = decode_status_word(response.sw1, response.sw2)
        status_counts[response.sw] += 1
        category_counts[info.category] += 1
        result = "follow-up" if found is None else ("FOUND" if found else "filtered")
        print(f"[{sequence:05d}/{total:05d}] RX DATA={data} SW={response.sw:04X} "
              f"{result} - {info.meaning} [{info.standard}]", flush=True)

    transport = PCSCTransport(reader)
    findings: list[ScanFinding] = []
    aborted = False
    try:
        for finding in scan_apdus(transport, level2=level2, trace=screen_trace):
            findings.append(finding)
            response = finding.response
            print(f"FINDING VALUE={finding.value:04X} SW={response.sw:04X} "
                  f"DATA={response.data.hex().upper() or '<empty>'}", flush=True)
    except RuntimeError as exc:
        aborted = True
        print(f"SCAN ABORTED: {exc}", flush=True)
    finally:
        try:
            transport.close()
        except Exception as exc:
            print(f"CARD CLOSE ERROR: {exc}", flush=True)
        print("\n========== APDU SCAN SUMMARY ==========", flush=True)
        print(f"Result: {'ABORTED' if aborted else 'COMPLETED'}", flush=True)
        print(f"Responses received: {sum(status_counts.values())}", flush=True)
        print(f"Communication errors/retries: {error_count}", flush=True)
        print(f"Potentially supported APDU values: {len(findings)}", flush=True)
        print("Status words:", flush=True)
        for sw, count in status_counts.most_common():
            info = decode_status_word(sw >> 8, sw & 0xFF)
            print(f"  SW={sw:04X} COUNT={count} CATEGORY={info.category} - {info.meaning}", flush=True)
        print("Categories:", flush=True)
        for category, count in category_counts.most_common():
            print(f"  {category}: {count}", flush=True)
        print("Findings:", flush=True)
        if findings:
            for finding in findings:
                response = finding.response
                info = decode_status_word(response.sw1, response.sw2)
                print(f"  CLA={finding.value >> 8:02X} INS={finding.value & 0xFF:02X} "
                      f"APDU={finding.value:04X}0000 SW={response.sw:04X} "
                      f"DATA={response.data.hex().upper() or '<empty>'} - {info.meaning}", flush=True)
        else:
            print("  None", flush=True)
        print("Standards basis: ISO/IEC 7816-4, ETSI TS 102 221/102 223, "
              "3GPP TS 31.101/31.111 and legacy TS 11.11; GSMA UICC/eSIM "
              "profiles use these card status conventions unless profile-specific.", flush=True)
        print("=======================================", flush=True)


def _run_known_tar_scan(reader: int, keyset: int,
                        groups: Iterable[str] | None = None,
                        probes: Iterable[tuple[str, CommandPacket]] | None = None,
                        title: str = "KNOWN TAR SCAN") -> None:
    """Deliver the known TAR corpus over SMS-PP and summarize card responses."""
    reader_names = PCSCTransport.readers()
    if not 0 <= reader < len(reader_names):
        raise RuntimeError(f"reader {reader} unavailable; found {len(reader_names)}")
    probe_list = list(known_tar_packets(keyset, groups) if probes is None else probes)
    transport = PCSCTransport(reader)
    results: list[tuple[str, str, APDUResponse, ResponsePacket | None]] = []
    errors = 0
    print(f"{title} START: {len(probe_list)} probes; reader {reader}: "
          f"{reader_names[reader]}; keyset {keyset}", flush=True)
    try:
        for index, (group, packet) in enumerate(probe_list, 1):
            tar = packet.tar.hex().upper()
            command = build_sms_pp_download_apdu(packet)
            print(f"[{index:03d}/{len(probe_list):03d}] {group}:{tar} TX APDU={command.hex().upper()}", flush=True)
            response = None
            for attempt in range(3):
                try:
                    response = transport.transmit(command)
                    break
                except Exception as exc:
                    errors += 1
                    print(f"[{index:03d}/{len(probe_list):03d}] ERROR {exc} - "
                          f"{'retrying' if attempt < 2 else 'SKIPPED'}", flush=True)
                    if attempt < 2:
                        try:
                            transport.reconnect()
                        except Exception:
                            pass
                        time.sleep(0.1)
            if response is None:
                continue
            data = response.data
            while response.sw1 == 0x61:
                followup_apdu = bytes((command[0], 0xC0, 0, 0, response.sw2))
                print(f"[{index:03d}/{len(probe_list):03d}] {group}:{tar} "
                      f"TX GET RESPONSE={followup_apdu.hex().upper()}", flush=True)
                try:
                    response = transport.transmit(followup_apdu)
                except Exception as exc:
                    errors += 1
                    print(f"[{index:03d}/{len(probe_list):03d}] GET RESPONSE ERROR: {exc}", flush=True)
                    break
                data += response.data
            response = APDUResponse(data, response.sw1, response.sw2)
            info = decode_status_word(response.sw1, response.sw2)
            parsed = None
            try:
                parsed = ResponsePacket.parse(response.data, strict=False)
            except PacketError:
                pass
            ota = f" OTA-RSC={parsed.status_code:02X}" if parsed is not None else ""
            print(f"[{index:03d}/{len(probe_list):03d}] {group}:{tar} RX "
                  f"DATA={data.hex().upper() or '<empty>'} SW={response.sw:04X}{ota} "
                  f"- {info.meaning}", flush=True)
            results.append((group, tar, response, parsed))
    finally:
        try:
            transport.close()
        except Exception:
            pass
    parsed_results = [result for result in results if result[3] is not None]
    print(f"\n========== {title} SUMMARY ==========", flush=True)
    print(f"Probes attempted: {len(probe_list)}", flush=True)
    print(f"Card responses: {len(results)}", flush=True)
    print(f"Communication errors/retries: {errors}", flush=True)
    print(f"Parsed OTA response packets: {len(parsed_results)}", flush=True)
    for group, tar, response, parsed in results:
        info = decode_status_word(response.sw1, response.sw2)
        ota = f" OTA-RSC={parsed.status_code:02X}" if parsed is not None else ""
        print(f"  {group}:{tar} SW={response.sw:04X}{ota} "
              f"DATA={response.data.hex().upper() or '<empty>'} - {info.meaning}", flush=True)
    print("============================================", flush=True)


def _run_ota_fuzzing(reader: int, tar: str, keyset: int,
                     bruteforce: bool = False) -> None:
    """Fuzz SMS PID, DCS, and UDHI around one OTA command packet."""
    pids = range(256) if bruteforce else (0x00, 0x40, 0x7F)
    dcss = range(256) if bruteforce else (0x00, 0x04, 0xF6)
    combinations = [(pid, dcs, udhi) for pid in pids for dcs in dcss for udhi in (False, True)]
    packet = CommandPacket(bytes.fromhex(tar), keyset=keyset, user_data=b"\0" * 5)
    transport = PCSCTransport(reader)
    counts: Counter[int] = Counter()
    try:
        for index, (pid, dcs, udhi) in enumerate(combinations, 1):
            command = build_sms_pp_download_apdu(packet, pid=pid, dcs=dcs, udhi=udhi)
            print(f"[{index:05d}/{len(combinations):05d}] PID={pid:02X} DCS={dcs:02X} "
                  f"UDHI={int(udhi)} TX={command.hex().upper()}", flush=True)
            try:
                response = transport.transmit(command)
            except Exception as exc:
                print(f"  ERROR: {exc}", flush=True)
                try:
                    transport.reconnect()
                except Exception:
                    pass
                continue
            counts[response.sw] += 1
            info = decode_status_word(response.sw1, response.sw2)
            print(f"  RX={response.data.hex().upper() or '<empty>'} SW={response.sw:04X} "
                  f"- {info.meaning}", flush=True)
    finally:
        try:
            transport.close()
        except Exception:
            pass
    print("\n========== OTA FUZZING SUMMARY ==========", flush=True)
    print(f"Combinations attempted: {len(combinations)}", flush=True)
    for sw, count in counts.most_common():
        print(f"  SW={sw:04X} COUNT={count} - {decode_status_word(sw >> 8, sw & 255).meaning}", flush=True)
    print("=========================================", flush=True)


def run_self_tests() -> int:
    """Run dependency-free checks bundled into this standalone script."""
    checks: list[tuple[str, Callable[[], None]]] = []

    def check(name: str) -> Callable[[Callable[[], None]], Callable[[], None]]:
        def register(function: Callable[[], None]) -> Callable[[], None]:
            checks.append((name, function))
            return function
        return register

    @check("command packet known layout and round trip")
    def _command_round_trip() -> None:
        packet = CommandPacket(bytes.fromhex("B00010"), keyset=2, counter=1,
                               user_data=bytes.fromhex("A0A40000023F00"),
                               counter_management=3, kid_algorithm=2, cipher_por=True)
        expected = "02700000150D18112025B00010000000000100A0A40000023F00"
        assert packet.to_bytes().hex().upper() == expected
        assert CommandPacket.parse(packet.to_bytes()) == packet

    @check("standard and embedded response parsing")
    def _response_parse() -> None:
        raw = b"prefix" + bytes.fromhex("027100000D0AB0001000000000010000AABB")
        response = ResponsePacket.parse(raw, strict=False)
        assert response.tar == bytes.fromhex("B00010")
        assert response.counter == 1 and response.additional_data == bytes.fromhex("AABB")

    @check("ETSI and 3GPP status word decoding")
    def _status_words() -> None:
        assert decode_status_word(0x90, 0x00).category == "success"
        assert "Instruction" in decode_status_word(0x6D, 0x00).meaning
        assert decode_status_word(0x69, 0x86).category == "supported-command"
        assert "3 retries" in decode_status_word(0x63, 0xC3).meaning
        assert "256" in decode_status_word(0x61, 0x00).meaning

    @check("61xx automatically issues GET RESPONSE")
    def _get_response() -> None:
        commands: list[bytes] = []

        def handler(apdu: bytes) -> APDUResponse:
            commands.append(apdu)
            if apdu == bytes.fromhex("00000000"):
                return APDUResponse(b"", 0x61, 0x03)
            if apdu == bytes.fromhex("00C0000003"):
                return APDUResponse(b"XYZ", 0x90, 0x00)
            return APDUResponse(b"", 0x6E, 0x00)

        findings = list(scan_apdus(MockTransport(handler)))
        assert commands[:2] == [bytes.fromhex("00000000"), bytes.fromhex("00C0000003")]
        assert findings[0].response.data == b"XYZ"
        assert findings[0].response.sw == 0x9000

    @check("TAR generation is inclusive and resumable")
    def _tar_generation() -> None:
        assert list(tar_values([(1, 3), (10, 11)], start=2)) == [2, 3, 10, 11]

    @check("known S@T, WIB and vendor TAR corpus")
    def _known_tars() -> None:
        assert len(KNOWN_TAR_GROUPS["SAT"]) == 2
        assert len(KNOWN_TAR_GROUPS["WIB"]) == 20
        assert sum(map(len, KNOWN_TAR_GROUPS.values())) == 135
        packet = next(known_tar_packets(groups=("SAT",)))[1]
        assert packet.tar == bytes.fromhex("505348")
        envelope = build_sms_pp_download_apdu(packet)
        assert envelope[:5] == bytes((0x80, 0xC2, 0, 0, len(envelope) - 5))
        assert packet.to_bytes() in envelope

    @check("standard fuzzer matrix and OTA envelope variants")
    def _fuzzing_modes() -> None:
        packets = list(standard_fuzzer_packets(("B00010",), (1,)))
        assert len(packets) == 17
        assert packets[0][0] == "F00/K1" and packets[-1][0] == "F16/K1"
        plain = build_sms_pp_download_apdu(packets[0][1], pid=0, dcs=4, udhi=False)
        assert packets[0][1].to_bytes() in plain
        assert bytes.fromhex("0405002143F50004") in plain

    @check("APDU scan filters unsupported classes")
    def _apdu_scan() -> None:
        trace_log: list[tuple[int, int, bytes, APDUTraceValue, bool | None]] = []
        transport = MockTransport(
            lambda apdu: APDUResponse(b"ok", 0x90, 0) if apdu[0] == 7
            else APDUResponse(b"", 0x6E, 0)
        )
        findings = list(scan_apdus(
            transport, trace=lambda *exchange: trace_log.append(exchange)
        ))
        assert len(findings) == 1 and findings[0].value == 0x0700
        assert len(trace_log) == 512
        assert trace_log[14][2] == bytes.fromhex("07000000")
        assert trace_log[14][3] is None
        assert trace_log[15][4] is True

    @check("APDU scan retries and skips communication errors")
    def _apdu_retry() -> None:
        calls = 0

        def flaky_handler(apdu: bytes) -> APDUResponse:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("temporary reader error")
            return APDUResponse(b"", 0x6E, 0)

        scanner = scan_apdus(MockTransport(flaky_handler), retries=1)
        assert list(scanner) == []
        assert calls == 257

    @check("missing card connection has a friendly error")
    def _missing_card() -> None:
        class RemovedCardConnection:
            def connect(self) -> None:
                raise OSError("smart card removed (0x80100069)")

        try:
            PCSCTransport._connect(RemovedCardConnection())
        except RuntimeError as exc:
            assert "Ensure the card is inserted" in str(exc)
            assert "0x80100069" in str(exc)
        else:
            raise AssertionError("missing card connection should fail")

    @check("reader selection validates and returns the chosen reader")
    def _reader_selection() -> None:
        answers = iter(("x", "9", "1"))
        selected = _select_reader(("Reader A", "Reader B"), lambda _prompt: next(answers))
        assert selected == 1

    failures = 0
    for name, function in checks:
        try:
            function()
            print(f"PASS: {name}")
        except Exception as exc:  # report every bundled check rather than stopping early
            failures += 1
            print(f"FAIL: {name}: {exc}")
    print(f"{len(checks) - failures}/{len(checks)} self-tests passed")
    return 1 if failures else 0


def interactive_menu() -> int:
    """Run all available tools from one interactive menu."""
    actions = {
        "1": "Standard fuzzing", "2": "TAR scanning",
        "3": "APDU scanning", "4": "OTA fuzzing",
        "0": "Exit",
    }
    while True:
        print("\nSIMTester Python - authorized test cards only")
        for key, label in actions.items():
            print(f"  {key}. {label}")
        choice = input("Choose an option: ").strip()
        try:
            if choice == "0":
                return 0
            if choice == "1":
                tars = input("TARs comma-separated [000000,B00001,B00010]: ").strip()
                tar_list = [value.strip().upper() for value in (tars or "000000,B00001,B00010").split(",")]
                keysets = input("Keysets comma-separated [1,2,3,4,5,6]: ").strip()
                keyset_list = [int(value) for value in (keysets or "1,2,3,4,5,6").split(",")]
                reader = _select_reader()
                _run_known_tar_scan(reader, 0, probes=standard_fuzzer_packets(tar_list, keyset_list),
                                    title="STANDARD FUZZING")
            elif choice == "2":
                mode = input("Known corpus or hexadecimal range? [known/range]: ").strip().lower() or "known"
                keyset = _read_int("Keyset [0]: ")
                if mode == "range":
                    low = _read_int("First TAR hex [000000]: ", base=16)
                    high = _read_int("Last TAR hex [0000FF]: ", 0xFF, 16)
                    reader = _select_reader()
                    probes = (("RANGE", packet) for packet in build_tar_packets([(low, high)], keyset=keyset))
                    _run_known_tar_scan(reader, keyset, probes=probes, title="TAR RANGE SCAN")
                else:
                    groups = input("Groups [RAM,WIB,SAT,RFM or ALL]: ").strip().upper() or "ALL"
                    selected = None if groups == "ALL" else tuple(part.strip() for part in groups.split(","))
                    reader = _select_reader()
                    _run_known_tar_scan(reader, keyset, selected)
            elif choice == "3":
                level = _read_int("APDU scan level [1]: ", 1)
                _run_scan(_select_reader(), level == 2)
            elif choice == "4":
                tar = input("TAR [B00010]: ").strip().upper() or "B00010"
                keyset = _read_int("Keyset [0]: ")
                reader = _select_reader()
                bruteforce = input("Bruteforce all PID/DCS values? [y/N]: ").strip().lower() == "y"
                _run_ota_fuzzing(reader, tar, keyset, bruteforce)
            else:
                print("Unknown option. Choose 0 through 4.")
        except (PacketError, RuntimeError, ValueError) as exc:
            print(f"Error: {exc}")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    build = commands.add_parser("build-ota")
    build.add_argument("tar"); build.add_argument("--keyset", type=int, default=0)
    build.add_argument("--counter", type=int, default=0); build.add_argument("--data", default="")
    parse = commands.add_parser("parse-response")
    parse.add_argument("hex"); parse.add_argument("--lenient", action="store_true")
    scan = commands.add_parser("scan-apdu")
    scan.add_argument("--reader", type=int, default=0); scan.add_argument("--level2", action="store_true")
    known = commands.add_parser("known-tars")
    known.add_argument("--keyset", type=int, default=0)
    known.add_argument("--groups", default="ALL", help="comma-separated RAM,WIB,SAT,RFM")
    known_scan = commands.add_parser("scan-known-tars")
    known_scan.add_argument("--reader", type=int, default=0)
    known_scan.add_argument("--keyset", type=int, default=0)
    known_scan.add_argument("--groups", default="ALL", help="comma-separated RAM,WIB,SAT,RFM")
    commands.add_parser("menu")
    commands.add_parser("self-test")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.command in {None, "menu"}:
        return interactive_menu()
    if args.command == "self-test":
        return run_self_tests()
    if args.command == "build-ota":
        print(CommandPacket(bytes.fromhex(args.tar), args.keyset, args.counter,
                            bytes.fromhex(args.data)).to_bytes().hex().upper())
    elif args.command == "parse-response":
        _print_response(ResponsePacket.parse(bytes.fromhex(args.hex), strict=not args.lenient))
    elif args.command == "scan-apdu":
        _run_scan(args.reader, args.level2)
    elif args.command == "known-tars":
        selected = None if args.groups.upper() == "ALL" else tuple(
            group.strip().upper() for group in args.groups.split(",")
        )
        for group, packet in known_tar_packets(args.keyset, selected):
            print(f"{group}:{packet.tar.hex().upper()} {packet.to_bytes().hex().upper()}")
    elif args.command == "scan-known-tars":
        selected = None if args.groups.upper() == "ALL" else tuple(
            group.strip().upper() for group in args.groups.split(",")
        )
        _run_known_tar_scan(args.reader, args.keyset, selected)
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except (PacketError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}")
        exit_code = 1
    raise SystemExit(exit_code)
