#!/usr/bin/env python3
# -*- coding: ascii -*-
"""Standalone Python SIMTester: codecs, transports, scanners, CLI, and menu."""
from __future__ import annotations

import argparse
import html
import importlib.util
import json
import os
import re
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass, replace
from typing import Callable, Iterable, Iterator, Protocol, Sequence

__version__ = "0.3.4"
BUILD_ID = "uicc-compact-expanded-v5"


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
    cryptographic_checksum: bool = False
    ciphering: bool = False

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
        return ((self.counter_management & 3) << 3
                | (0x02 if self.cryptographic_checksum else 0)
                | (0x04 if self.ciphering else 0))

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
        checksum = b"\0" * 8 if self.cryptographic_checksum else b""
        header_length = 13 + len(checksum)
        body = (bytes((header_length, spi1, spi2, kic, kid)) + self.tar
                + self.counter.to_bytes(5, "big") + b"\0" + checksum + self.user_data)
        return self.HEADER + len(body).to_bytes(2, "big") + body

    @classmethod
    def parse(cls, data: bytes) -> CommandPacket:
        if len(data) < 19 or data[:3] != cls.HEADER:
            raise PacketError("command packet header missing or packet too short")
        if int.from_bytes(data[3:5], "big") != len(data) - 5:
            raise PacketError("CPL does not match packet length")
        if data[5] not in (13, 21):
            raise PacketError("command header length must be 13 or 21")
        spi1, spi2, kic, kid = data[6:10]
        reverse = {0: 0, 1: 1, 5: 2, 9: 3, 13: 4}
        if kic >> 4 != kid >> 4:
            raise PacketError("KIC and KID keysets differ")
        if kic & 15 not in reverse or kid & 15 not in reverse:
            raise PacketError("unknown KIC/KID algorithm")
        checksum_present = data[5] == 21
        user_offset = 27 if checksum_present else 19
        return cls(data[10:13], kic >> 4, int.from_bytes(data[13:18], "big"), data[user_offset:],
                   (spi1 >> 3) & 3, reverse[kic & 15], reverse[kid & 15],
                   (spi2 & 3) == 1, bool(spi2 & 0x10), bool(spi2 & 0x20),
                   cryptographic_checksum=checksum_present or bool(spi1 & 2),
                   ciphering=bool(spi1 & 4))


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
                    tar_bytes, keyset, counter=0 if counter == 0 else 1, user_data=b"\0" * 5,
                    counter_management=counter, kic_algorithm=kic,
                    kid_algorithm=kid, request_por=por, cipher_por=cipher_por,
                    cryptographic_checksum=kid != 0, ciphering=kic != 0,
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


def requested_msl(packet: CommandPacket) -> str:
    protections = []
    if packet.cryptographic_checksum:
        protections.append("CC")
    if packet.ciphering:
        protections.append("ciphering")
    if packet.counter_management:
        protections.append(f"counter-mode-{packet.counter_management}")
    return "MSL=0 (no command security)" if not protections else "MSL>0 (" + ", ".join(protections) + ")"


def decode_por_status(status: int) -> str:
    meanings = {
        0x00: "PoR success", 0x01: "RC/CC/DS failed", 0x02: "counter too low",
        0x03: "counter too high", 0x04: "counter blocked", 0x05: "ciphering error",
        0x06: "unidentified security error", 0x07: "insufficient memory",
        0x08: "more time needed", 0x09: "unknown TAR", 0x0A: "insufficient security",
        0x0B: "application data format error", 0x0C: "application error",
        0x0D: "unknown error",
    }
    return meanings.get(status, "vendor-specific PoR status")


@dataclass(frozen=True)
class APDUResponse:
    data: bytes
    sw1: int
    sw2: int

    def __post_init__(self) -> None:
        if not 0 <= self.sw1 <= 0xFF or not 0 <= self.sw2 <= 0xFF:
            raise ValueError("status-word bytes must be between 00 and FF")

    @property
    def sw(self) -> int:
        return self.sw1 << 8 | self.sw2


@dataclass(frozen=True)
class StatusWordInfo:
    meaning: str
    category: str
    standard: str


@dataclass(frozen=True)
class ResponseAnalysis:
    interesting: bool
    severity: str
    conclusion: str
    next_step: str


def analyze_apdu_response(command: bytes, response: APDUResponse) -> ResponseAnalysis:
    """Add command-context intelligence to a raw status-word interpretation."""
    sw = response.sw
    if sw == 0x9000:
        return ResponseAnalysis(True, "high", "CLA and INS accepted; command succeeded",
                                "Inspect returned data and verify whether authorization was expected")
    if response.sw1 in (0x61, 0x9F):
        return ResponseAnalysis(True, "high", "Command accepted and response bytes are available",
                                f"Issue GET RESPONSE with Le={response.sw2 or 256}")
    if response.sw1 == 0x6C:
        return ResponseAnalysis(True, "high", "INS is recognized; only Le is wrong",
                                f"Retry with Le={response.sw2 or 256}")
    if response.sw1 == 0x62:
        return ResponseAnalysis(True, "medium", "Command completed with a warning and non-volatile memory unchanged",
                                "Compare this parameter set with 9000 variants; do not infer OTA execution without PoR")
    if sw in (0x6700, 0x6A80, 0x6A86, 0x6A87, 0x6A88, 0x6B00):
        return ResponseAnalysis(True, "medium", "CLA/INS likely recognized; parameters or data are invalid",
                                "Refine P1/P2, Lc, data, and Le without treating this as unsupported")
    if response.sw1 == 0x69 or sw in (0x9804, 0x9840):
        return ResponseAnalysis(True, "high", "Command recognized but blocked by security or card state",
                                "Review PIN, access rules, selected file/application, and secure messaging")
    if response.sw1 == 0x63 and response.sw2 & 0xF0 == 0xC0:
        return ResponseAnalysis(True, "critical", f"Credential check failed; {response.sw2 & 15} tries remain",
                                "Do not retry credentials automatically")
    if sw == 0x6D00:
        return ResponseAnalysis(False, "none", "INS unsupported for this CLA", "Continue with the next INS")
    if sw == 0x6E00:
        return ResponseAnalysis(False, "none", "CLA unsupported", "Skip the remaining INS values for this CLA")
    if sw in (0x6881, 0x6882):
        if sw == 0x6881:
            return ResponseAnalysis(False, "low", "CLA understood, but the current logical channel is unsupported",
                                    "Open and probe UICC logical channels 1 through 19")
        return ResponseAnalysis(False, "low", "CLA understood, but secure messaging is unsupported",
                                "Try the basic channel without secure messaging")
    if response.data:
        return ResponseAnalysis(True, "medium", "Application-specific status returned data",
                                "Decode response data using the selected application specification")
    return ResponseAnalysis(True, "low", "Non-generic or application-specific status",
                            "Correlate with card state and application documentation")


def decode_status_word(sw1: int, sw2: int) -> StatusWordInfo:
    """Decode ISO/ETSI/3GPP UICC status words also used by GSMA profiles."""
    if not 0 <= sw1 <= 0xFF or not 0 <= sw2 <= 0xFF:
        raise ValueError("status-word bytes must be between 00 and FF")
    sw = sw1 << 8 | sw2
    exact = {
        0x9000: ("Command completed successfully", "success"),
        0x6200: ("Warning: non-volatile memory unchanged; no further information", "warning"),
        0x6282: ("End of file or record reached before reading Le bytes", "warning"),
        0x6283: ("Selected file invalidated/deactivated", "warning"),
        0x6285: ("Selected file is in termination state", "warning"),
        0x62F1: ("More data available", "response-available"),
        0x62F2: ("More data available and proactive command pending", "proactive"),
        0x62F3: ("Response data may be corrupted", "warning"),
        0x62F5: ("Default agent locked", "warning"),
        0x62F7: ("Card/application life-cycle state does not permit the command", "warning"),
        0x62F8: ("Referenced data not found", "warning"),
        0x62F9: ("Application selection failed", "warning"),
        0x63F1: ("More data expected", "warning"),
        0x63F2: ("More data expected and proactive command pending", "proactive"),
        0x6400: ("Execution error; non-volatile memory unchanged", "error"),
        0x6401: ("Immediate response required by the card", "error"),
        0x6500: ("Execution error; non-volatile memory changed", "error"),
        0x6581: ("Memory failure", "error"),
        0x6600: ("Security-related issue", "security"),
        0x6700: ("Wrong command length", "error"),
        0x6881: ("Logical channel not supported", "unsupported"),
        0x6882: ("Secure messaging not supported", "unsupported"),
        0x6982: ("Security status not satisfied", "security"),
        0x6983: ("Authentication method blocked", "security"),
        0x6984: ("Referenced data invalidated", "security"),
        0x6985: ("Conditions of use not satisfied", "security"),
        0x6986: ("Command not allowed (no current EF or command context)", "supported-command"),
        0x6987: ("Expected secure-messaging data objects missing", "security"),
        0x6988: ("Secure messaging data objects incorrect", "security"),
        0x6A80: ("Incorrect parameters in command data", "supported-command"),
        0x6A81: ("Function not supported", "unsupported"),
        0x6A82: ("File or application not found", "supported-command"),
        0x6A83: ("Record not found", "supported-command"),
        0x6A84: ("Not enough memory space", "error"),
        0x6A85: ("Lc inconsistent with TLV structure", "supported-command"),
        0x6A86: ("Incorrect P1/P2 parameters", "supported-command"),
        0x6A87: ("Lc inconsistent with P1/P2", "supported-command"),
        0x6A88: ("Referenced data not found", "supported-command"),
        0x6B00: ("Wrong P1/P2 parameters", "supported-command"),
        0x6D00: ("Instruction code (INS) not supported or invalid", "unsupported"),
        0x6E00: ("Class byte (CLA) not supported", "unsupported"),
        0x6F00: ("No precise diagnosis", "error"),
        0x9300: ("SIM Application Toolkit is busy", "warning"),
        0x9200: ("Command successful after internal update retry", "warning"),
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
    if sw1 == 0x92:
        return StatusWordInfo(f"Command successful after {sw2 & 0x0F} internal update retries",
                              "warning", "3GPP TS 11.11 legacy SIM")
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

    def atr(self) -> bytes:
        return bytes(self.connection.getATR())


@dataclass(frozen=True)
class APDUFormat:
    name: str
    third_gen: bool
    select_cla: int
    envelope_cla: int


def detect_apdu_format(transport: CardTransport) -> APDUFormat:
    """Detect UICC (3G) versus classic SIM (2G) APDU command formatting."""
    probes = (
        (APDUFormat("3G/UICC", True, 0x00, 0x80), bytes.fromhex("00A40004023F00")),
        (APDUFormat("2G SIM", False, 0xA0, 0xA0), bytes.fromhex("A0A40000023F00")),
    )
    observations: list[str] = []
    for apdu_format, command in probes:
        try:
            response = transport.transmit(command)
        except Exception as exc:
            observations.append(f"{apdu_format.name}: error {exc}")
            continue
        observations.append(f"{apdu_format.name}: SW={response.sw:04X}")
        # 6E00 explicitly rejects CLA. Other status words show that the CLA and
        # command format reached the card, even if selection itself was denied.
        if response.sw not in (0x6E00, 0x6D00):
            print(f"APDU format detected: {apdu_format.name} "
                  f"(probe {command.hex().upper()} -> SW={response.sw:04X})", flush=True)
            return apdu_format
    raise RuntimeError("Unable to detect 2G/3G APDU format; " + "; ".join(observations))


def _decode_bcd(data: bytes) -> str:
    digits = "".join(f"{byte & 15:X}{byte >> 4:X}" for byte in data)
    return digits.rstrip("F")


def decode_atr(atr: bytes) -> dict[str, str]:
    """Decode the ISO/IEC 7816-3 ATR structure into summary fields."""
    if len(atr) < 2 or atr[0] not in (0x3B, 0x3F):
        return {"ATR decode": "invalid or unsupported ATR"}
    result = {"ATR convention": "direct" if atr[0] == 0x3B else "inverse"}
    t0 = atr[1]
    historical_length = t0 & 0x0F
    present = t0 >> 4
    offset = 2
    group = 1
    interface: list[str] = []
    ta1: int | None = None
    protocols: set[int] = set()
    while present and offset < len(atr):
        for mask, name in ((1, "TA"), (2, "TB"), (4, "TC")):
            if present & mask and offset < len(atr):
                if name == "TA" and group == 1:
                    ta1 = atr[offset]
                interface.append(f"{name}{group}={atr[offset]:02X}")
                offset += 1
        if present & 8 and offset < len(atr):
            td = atr[offset]
            interface.append(f"TD{group}={td:02X}")
            protocols.add(td & 0x0F)
            present = td >> 4
            offset += 1
            group += 1
        else:
            present = 0
    historical = atr[offset:offset + historical_length]
    if not protocols:
        protocols.add(0)
    result["ATR protocols"] = ", ".join(f"T={protocol}" for protocol in sorted(protocols))
    result["ATR interface bytes"] = " ".join(interface) or "none"
    result["ATR historical bytes"] = historical.hex().upper() or "none"
    printable = "".join(chr(value) if 32 <= value < 127 else "." for value in historical)
    result["ATR historical text"] = printable or "none"
    tck_offset = offset + historical_length
    if any(protocol != 0 for protocol in protocols):
        result["ATR TCK"] = f"{atr[tck_offset]:02X}" if tck_offset < len(atr) else "missing"
    ta1 = 0x11 if ta1 is None else ta1
    fi_table = {1: (372, 5.0), 2: (558, 6.0), 3: (744, 8.0), 4: (1116, 12.0),
                5: (1488, 16.0), 6: (1860, 20.0), 9: (512, 5.0),
                10: (768, 7.5), 11: (1024, 10.0), 12: (1536, 15.0), 13: (2048, 20.0)}
    di_table = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 8: 12, 9: 20}
    fi = fi_table.get(ta1 >> 4)
    di = di_table.get(ta1 & 15)
    if fi and di:
        factor, max_clock = fi
        baud = int(max_clock * 1_000_000 * di / factor)
        result["ATR PPS speed"] = (f"TA1={ta1:02X}, Fi={factor}, Di={di}, "
                                   f"ETU={factor / di:g} clocks, max {baud} bit/s at {max_clock:g} MHz")
        if ta1 == 0x11:
            result["ATR PPS request"] = "default parameters; PPS not required"
        else:
            pps = bytes((0xFF, 0x10, ta1, 0xFF ^ 0x10 ^ ta1))
            result["ATR PPS request"] = pps.hex().upper()
    else:
        result["ATR PPS speed"] = f"TA1={ta1:02X}, reserved/unsupported Fi or Di"
    return result


VENDOR_MARKERS = (
    (b"GEMPLUS", "Gemplus/Gemalto"), (b"GEMALTO", "Gemalto/Thales"),
    (b"THALES", "Thales"), (b"OBERTHUR", "Oberthur/IDEMIA"),
    (b"IDEMIA", "IDEMIA"), (b"MORPHO", "Morpho/IDEMIA"),
    (b"GIESECKE", "Giesecke+Devrient"), (b"G&D", "Giesecke+Devrient"),
    (b"WATCHDATA", "Watchdata"), (b"EASTCOM", "Eastcompeace"),
    (b"VALID", "Valid"), (b"KONA", "KONA I"),
    (b"TIANYU", "Wuhan Tianyu"), (b"DATANG", "Datang"),
)

# Embedded major-vendor metadata keeps useful attribution available offline;
# external ATR sources are still used for card-specific matching.
MAJOR_SIM_VENDOR_INFO = {
    "Gemplus/Gemalto": "France; Gemplus merged into Gemalto, now part of Thales DIS",
    "Gemalto/Thales": "Global; Gemalto is now Thales Digital Identity and Security",
    "Thales": "Global; Thales Digital Identity and Security SIM/eSIM portfolio",
    "Oberthur/IDEMIA": "France; Oberthur Technologies became IDEMIA",
    "IDEMIA": "Global; physical SIM, eSIM, and secure connectivity vendor",
    "Morpho/IDEMIA": "France; Morpho combined with Oberthur to form IDEMIA",
    "Giesecke+Devrient": "Germany; G+D Mobile Security SIM/eSIM vendor",
    "Watchdata": "China/Singapore; telecom smart-card and SIM vendor",
    "Eastcompeace": "China; SIM, eSIM, and telecom smart-card vendor",
    "Valid": "Global; SIM/eSIM and mobile identity vendor",
    "KONA I": "South Korea; USIM, eSIM, and secure-element vendor",
    "Wuhan Tianyu": "China; telecom smart-card and SIM vendor",
    "Datang": "China; telecom smart-card and SIM vendor",
}

TELECOM_CARD_MARKERS = (
    "SIM", "UICC", "USIM", "ISIM", "ESIM", "TELECOM", "MOBILE",
    "GSM", "UMTS", "LTE", "3G", "4G", "5G", "OPERATOR", "TELEPHONY",
)

ATR_DATABASE_URL = "https://pcsc-tools.apdu.fr/smartcard_list.txt"
EFTLAB_ATR_URL = "https://www.eftlab.com/knowledge-base/complete-list-of-atrs"
_ATR_DATABASE_CACHE: tuple[str | None, str] | None = None
_EFTLAB_ATR_CACHE: tuple[str | None, str] | None = None
_COMBINED_ATR_CACHE: tuple[str | None, str] | None = None


def load_atr_database() -> tuple[str | None, str]:
    """Load Ludovic Rousseau's public pcsc-tools ATR database or a local copy."""
    global _ATR_DATABASE_CACHE
    if _ATR_DATABASE_CACHE is not None:
        return _ATR_DATABASE_CACHE
    local_path = os.environ.get("SIMTESTER_ATR_DATABASE")
    try:
        if local_path:
            with open(local_path, "r", encoding="utf-8", errors="replace") as database:
                text = database.read()
            source = local_path
        else:
            with urllib.request.urlopen(ATR_DATABASE_URL, timeout=4) as response:
                text = response.read().decode("utf-8", "replace")
            source = ATR_DATABASE_URL
        _ATR_DATABASE_CACHE = text, source
    except Exception as exc:
        _ATR_DATABASE_CACHE = None, f"unavailable ({exc}); set SIMTESTER_ATR_DATABASE to a local copy"
    return _ATR_DATABASE_CACHE


def _eftlab_html_to_database(page: str) -> str:
    """Convert EFTLab's ATR HTML table into the simple pcsc-tools entry form."""
    text = re.sub(r"<(?:br|/p|/tr|/td|/li)\b[^>]*>", "\n", page, flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    entries: list[str] = []
    atr_pattern = re.compile(r"\b(?:3B|3F)(?:[ :\-]*(?:[0-9A-Fa-f]{2}|\.\.)){1,}\b")
    for index, line in enumerate(lines):
        match = atr_pattern.search(line)
        if not match:
            continue
        raw = re.sub(r"[^0-9A-Fa-f.]", "", match.group()).upper()
        if len(raw) < 4 or len(raw) % 2:
            continue
        description = line[match.end():].strip(" :-")
        if not description and index + 1 < len(lines):
            description = lines[index + 1]
        entries.append(" ".join(raw[pos:pos + 2] for pos in range(0, len(raw), 2))
                       + "\n\t" + (description or "EFTLab ATR entry"))
    return "\n\n".join(entries)


def load_eftlab_atr_database() -> tuple[str | None, str]:
    """Load and normalize EFTLab's Complete List of ATRs."""
    global _EFTLAB_ATR_CACHE
    if _EFTLAB_ATR_CACHE is not None:
        return _EFTLAB_ATR_CACHE
    local_path = os.environ.get("SIMTESTER_EFTLAB_ATR_DATABASE")
    try:
        if local_path:
            with open(local_path, "r", encoding="utf-8", errors="replace") as database:
                page = database.read()
            source = local_path
        else:
            with urllib.request.urlopen(EFTLAB_ATR_URL, timeout=4) as response:
                page = response.read().decode("utf-8", "replace")
            source = EFTLAB_ATR_URL
        normalized = _eftlab_html_to_database(page)
        _EFTLAB_ATR_CACHE = normalized, source
    except Exception as exc:
        _EFTLAB_ATR_CACHE = None, (
            f"unavailable ({exc}); set SIMTESTER_EFTLAB_ATR_DATABASE to a local HTML copy"
        )
    return _EFTLAB_ATR_CACHE


def load_combined_atr_database() -> tuple[str | None, str]:
    """Return one normalized index assembled from both public ATR sources.

    The normalized text is kept in this single-file process cache. Operators
    can pin reproducible offline inputs with the two existing environment
    variables; unavailable sources do not discard entries from the other one.
    """
    global _COMBINED_ATR_CACHE
    if _COMBINED_ATR_CACHE is not None:
        return _COMBINED_ATR_CACHE
    pcsc_text, pcsc_source = load_atr_database()
    eftlab_text, eftlab_source = load_eftlab_atr_database()
    sections = []
    if pcsc_text:
        sections.append(f"# Source: {pcsc_source}\n{pcsc_text}")
    if eftlab_text:
        sections.append(f"# Source: {eftlab_source}\n{eftlab_text}")
    sources = f"pcsc-tools={pcsc_source}; EFTLab={eftlab_source}"
    _COMBINED_ATR_CACHE = ("\n\n".join(sections) or None, sources)
    return _COMBINED_ATR_CACHE


def lookup_atr_database(atr: bytes, database_text: str | None) -> list[str]:
    """Return descriptions matching exact or `..` wildcard ATR database entries."""
    if not database_text or not atr:
        return []
    target = atr.hex().upper()
    matches: list[str] = []
    lines = database_text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        pattern = "".join(stripped.split()).upper()
        if not pattern.startswith(("3B", "3F")) or len(pattern) != len(target):
            continue
        if not all(pattern[pos:pos + 2] in ("..", "??", target[pos:pos + 2])
                   for pos in range(0, len(target), 2)):
            continue
        descriptions = []
        for following in lines[index + 1:]:
            if following and not following[0].isspace():
                break
            description = following.strip()
            if description and not description.startswith("#"):
                descriptions.append(description)
        matches.extend(descriptions or [stripped])
    return matches


def filter_major_sim_atr_matches(matches: Iterable[str]) -> list[tuple[str, str]]:
    """Keep telecom-card entries attributable to a known major SIM vendor."""
    filtered: list[tuple[str, str]] = []
    for description in matches:
        upper = description.upper()
        if not any(marker in upper for marker in TELECOM_CARD_MARKERS):
            continue
        vendor = next((name for marker, name in VENDOR_MARKERS
                       if marker.decode("ascii") in upper), None)
        if vendor is not None and (vendor, description) not in filtered:
            filtered.append((vendor, description))
    return filtered


def detect_sim_vendor(atr: bytes, manufacturer_area: bytes | None,
                      gemxpresso_file: bool = False,
                      atr_database_text: str | None = None) -> tuple[str, str]:
    """Conservative vendor match using public ATR text markers and vendor files."""
    evidence = atr.upper() + b" " + (manufacturer_area or b"").upper()
    database_matches = filter_major_sim_atr_matches(
        lookup_atr_database(atr, atr_database_text)
    )
    if database_matches:
        vendor = database_matches[0][0]
        description = " | ".join(match[1] for match in database_matches[:3])
        return vendor, f"major telecom-card ATR match: {description}"
    for marker, vendor in VENDOR_MARKERS:
        if marker in evidence:
            return vendor, f"matched marker {marker.decode('ascii')} in ATR/manufacturer data"
    if gemxpresso_file:
        return "Gemplus/Gemalto", "vendor-specific GemXpresso DF 5F11 is present"
    return "unknown", "no conservative public ATR/vendor-file signature matched"


def _card_command(transport: CardTransport, command: bytes) -> APDUResponse:
    """Transmit a summary APDU and handle 61xx and 6Cxx responses."""
    response, _exchanges = _card_command_trace(transport, command)
    return response


def _card_command_trace(
    transport: CardTransport, command: bytes
) -> tuple[APDUResponse, tuple[tuple[bytes, APDUResponse], ...]]:
    """Transmit with bounded Le correction/GET RESPONSE and retain each exchange."""
    current = command
    response = transport.transmit(current)
    exchanges = [(current, response)]
    if response.sw1 == 0x6C and current:
        current = current[:-1] + bytes((response.sw2,))
        response = transport.transmit(current)
        exchanges.append((current, response))
    data = response.data
    while response.sw1 in (0x61, 0x9F):
        current = bytes((command[0], 0xC0, 0, 0, response.sw2))
        response = transport.transmit(current)
        exchanges.append((current, response))
        data += response.data
    return APDUResponse(data, response.sw1, response.sw2), tuple(exchanges)


def _read_transparent_file(transport: CardTransport, path: Sequence[int]) -> bytes | None:
    for cla in (0x00, 0xA0):
        selected = True
        for fid in path:
            response = _card_command(
                transport, bytes((cla, 0xA4, 0x00, 0x04 if cla == 0 else 0x00, 0x02))
                + fid.to_bytes(2, "big")
            )
            if response.sw != 0x9000:
                selected = False
                break
        if selected:
            response = _card_command(transport, bytes((cla, 0xB0, 0, 0, 0)))
            if response.sw == 0x9000:
                return response.data
    return None


def _read_first_record(transport: CardTransport, path: Sequence[int]) -> bytes | None:
    for cla in (0x00, 0xA0):
        selected = True
        for fid in path:
            response = _card_command(
                transport, bytes((cla, 0xA4, 0x00, 0x04 if cla == 0 else 0x00, 0x02))
                + fid.to_bytes(2, "big")
            )
            if response.sw != 0x9000:
                selected = False
                break
        if selected:
            response = _card_command(transport, bytes((cla, 0xB2, 1, 4, 0)))
            if response.sw == 0x9000:
                return response.data
    return None


def _file_exists(transport: CardTransport, path: Sequence[int]) -> bool:
    for cla in (0x00, 0xA0):
        found = True
        for fid in path:
            response = _card_command(
                transport, bytes((cla, 0xA4, 0, 0x04 if cla == 0 else 0, 2))
                + fid.to_bytes(2, "big")
            )
            if response.sw != 0x9000:
                found = False
                break
        if found:
            return True
    return False


def _credential_status(transport: CardTransport, apdu_format: APDUFormat,
                       instruction: int, references: Sequence[int]) -> str:
    """Query PIN/PUK state, falling back across UICC and classic SIM formats."""
    preferred_cla = apdu_format.select_cla
    clas = (preferred_cla, 0xA0 if preferred_cla == 0 else 0x00)
    rejected: list[str] = []
    response = None
    used_cla = preferred_cla
    used_reference = references[0]
    for cla in clas:
        for reference in references:
            command = bytes((cla, instruction, 0x00, reference))
            try:
                candidate = transport.transmit(command)
            except Exception as exc:
                rejected.append(f"CLA={cla:02X}/REF={reference:02X}: {exc}")
                continue
            # Wrong P1/P2, CLA, INS, or APDU length means this credential
            # addressing form is unsupported; transparently try the next one.
            if candidate.sw in (0x6700, 0x6A86, 0x6B00, 0x6D00, 0x6E00):
                rejected.append(f"CLA={cla:02X}/REF={reference:02X}: SW={candidate.sw:04X}")
                continue
            response = candidate
            used_cla = cla
            used_reference = reference
            break
        if response is not None:
            break
    if response is None:
        details = "; ".join(rejected) or "no response"
        return f"not reported ({details})"
    addressing = f" [CLA={used_cla:02X}, REF={used_reference:02X}]"
    if response.sw == 0x9000:
        return "enabled and already verified" + addressing
    if response.sw1 == 0x63 and response.sw2 & 0xF0 == 0xC0:
        return f"enabled, {response.sw2 & 15} attempts remaining" + addressing
    if response.sw in (0x6983, 0x9840):
        return "blocked" + addressing
    if response.sw == 0x9804:
        return "enabled, attempts remaining not reported" + addressing
    if response.sw == 0x9802:
        return "not initialized" + addressing
    if response.sw in (0x6985, 0x9808):
        return "disabled, already satisfied, or status contradiction" + addressing
    if response.sw in (0x6A88, 0x9404):
        return "not available" + addressing
    return (f"not reported (SW={response.sw:04X}: "
            f"{decode_status_word(response.sw1, response.sw2).meaning})" + addressing)


def collect_sim_summary(transport: CardTransport,
                        apdu_format: APDUFormat | None = None,
                        use_atr_database: bool = True) -> dict[str, str]:
    """Best-effort read of common subscriber identity files."""
    summary = {"ATR": "unavailable", "ICCID": "unavailable", "IMSI": "unavailable",
               "MSISDN": "unavailable", "SPN": "unavailable", "SIM vendor": "unknown"}
    if apdu_format is not None:
        summary["APDU format"] = apdu_format.name
        summary["Supported command CLA"] = f"SELECT={apdu_format.select_cla:02X}, ENVELOPE={apdu_format.envelope_cla:02X}"
    atr = getattr(transport, "atr", None)
    if atr is not None:
        try:
            atr_bytes = atr()
            summary["ATR"] = atr_bytes.hex().upper()
            summary.update(decode_atr(atr_bytes))
        except Exception:
            pass
    try:
        iccid = _read_transparent_file(transport, (0x3F00, 0x2FE2))
        if iccid:
            summary["ICCID"] = _decode_bcd(iccid)
        imsi = _read_transparent_file(transport, (0x3F00, 0x7F20, 0x6F07))
        if imsi and len(imsi) > 1:
            length = min(imsi[0], len(imsi) - 1)
            body = imsi[1:1 + length]
            summary["IMSI"] = (f"{body[0] >> 4:X}" + _decode_bcd(body[1:])).rstrip("F")
        spn = _read_transparent_file(transport, (0x3F00, 0x7F20, 0x6F46))
        if spn and len(spn) > 1:
            summary["SPN"] = spn[1:].rstrip(b"\xFF\0").decode("ascii", "replace").strip() or "unavailable"
        msisdn = _read_first_record(transport, (0x3F00, 0x7F10, 0x6F40))
        if msisdn and len(msisdn) >= 14:
            footer = msisdn[-14:]
            number_length = footer[0]
            if 1 < number_length <= 11:
                number = _decode_bcd(footer[2:2 + number_length - 1])
                summary["MSISDN"] = ("+" if footer[1] & 0x70 == 0x10 else "") + number
        manufacturer = _read_transparent_file(transport, (0x3F00, 0x0002))
        if manufacturer:
            summary["Manufacturer area"] = manufacturer.hex().upper()
        gemxpresso = _file_exists(transport, (0x3F00, 0x5F11))
        atr_value = bytes.fromhex(summary["ATR"]) if summary["ATR"] != "unavailable" else b""
        combined_database, combined_source = (
            load_combined_atr_database() if use_atr_database else (None, "disabled")
        )
        summary["Combined ATR sources"] = combined_source
        database_matches = filter_major_sim_atr_matches(
            lookup_atr_database(atr_value, combined_database)
        )
        summary["ATR database match"] = (
            " | ".join(f"{vendor}: {description}" for vendor, description in database_matches[:3]) or "none"
        )
        vendor, evidence = detect_sim_vendor(
            atr_value, manufacturer, gemxpresso, combined_database
        )
        summary["SIM vendor"] = vendor
        summary["Vendor evidence"] = evidence
        summary["SIM vendor info"] = MAJOR_SIM_VENDOR_INFO.get(
            vendor, "no embedded major-vendor profile available"
        )
        if apdu_format is not None:
            pin2_references = (0x81, 0x02) if apdu_format.third_gen else (0x02, 0x81)
            summary["PIN1 status"] = _credential_status(transport, apdu_format, 0x20, (0x01,))
            summary["PIN2 status"] = _credential_status(transport, apdu_format, 0x20, pin2_references)
            # A zero-data RESET RETRY COUNTER is the standardized status query;
            # it does not submit a PUK and therefore does not consume an attempt.
            summary["PUK1 status"] = _credential_status(transport, apdu_format, 0x2C, (0x01,))
            summary["PUK2 status"] = _credential_status(transport, apdu_format, 0x2C, pin2_references)
    except Exception as exc:
        summary["Read status"] = f"partial ({exc})"
    return summary


def print_sim_summary(transport: CardTransport,
                      apdu_format: APDUFormat | None = None) -> None:
    print("\n========== SIM CARD SUMMARY ==========", flush=True)
    for name, value in collect_sim_summary(transport, apdu_format).items():
        print(f"{name}: {value}", flush=True)
    print("======================================", flush=True)


@dataclass(frozen=True)
class ScanFinding:
    value: int
    response: APDUResponse
    channel: int = 0


def encode_logical_channel_cla(cla: int, channel: int) -> int:
    """Encode ISO/IEC 7816-4 / ETSI UICC logical channels 0 through 19."""
    if not 0 <= channel <= 19:
        raise ValueError("logical channel must be between 0 and 19")
    if channel <= 3:
        return (cla & 0xFC) | channel
    return (cla & 0xB0) | 0x40 | (channel - 4)


APDUTraceValue = APDUResponse | Exception | None
APDUTrace = Callable[[int, int, bytes, APDUTraceValue, bool | None], None]


def with_correct_le(command: bytes, le: int) -> bytes:
    """Return a corrected short APDU after a 6Cxx response.

    A four-byte case-1 command becomes case 2.  For case 2/4 the final Le is
    replaced; case-3 commands gain Le and become case 4.  Extended APDUs are
    deliberately rejected because a two-byte Le cannot be inferred from SW2.
    ``le=256`` is encoded as the short-APDU sentinel 00.
    """
    if len(command) < 4:
        raise ValueError("APDU must contain CLA, INS, P1 and P2")
    if not 1 <= le <= 256:
        raise ValueError("short APDU Le must be between 1 and 256")
    encoded_le = le & 0xFF
    if len(command) == 4:
        return command + bytes((encoded_le,))
    if command[4] == 0:
        if len(command) == 5:  # short case 2 with Le=256
            return command[:4] + bytes((encoded_le,))
        raise ValueError("cannot correct Le on an extended APDU from SW2")
    lc = command[4]
    if len(command) == 5:  # short case 2
        return command[:4] + bytes((encoded_le,))
    if len(command) == 5 + lc:  # short case 3
        return command + bytes((encoded_le,))
    if len(command) == 6 + lc:  # short case 4
        return command[:-1] + bytes((encoded_le,))
    raise ValueError("malformed short APDU length")


def scan_apdus(transport: CardTransport, *, level2: bool = False,
               interesting: Callable[[APDUResponse], bool] | None = None,
               trace: APDUTrace | None = None, retries: int = 2,
               max_consecutive_errors: int = 10) -> Iterator[ScanFinding]:
    """Probe CLA/INS values, tracing every exchange and yielding supported ones."""
    if retries < 0 or max_consecutive_errors < 1:
        raise ValueError("retries must be non-negative and max errors must be positive")
    def predicate(command: bytes, response: APDUResponse) -> bool:
        return interesting(response) if interesting is not None else analyze_apdu_response(command, response).interesting
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
            # 6Cxx is an explicit correction, not a command failure.  Retry
            # once using the card-provided short Le (SW2=00 means 256).
            if response.sw1 == 0x6C:
                try:
                    corrected = with_correct_le(command, response.sw2 or 256)
                except ValueError:
                    corrected = b""
                if corrected:
                    if trace is not None:
                        trace(sequence, total, command, response, None)
                    corrected_response, last_error = transmit(corrected, sequence)
                    if corrected_response is not None:
                        command = corrected
                        response = corrected_response
            combined_data = response.data
            followups = 0
            response_traced = False
            while response.sw1 in (0x61, 0x9F) and followups < 8:
                if trace is not None and followups == 0:
                    trace(sequence, total, command, response, None)
                # ISO/UICC 61xx and classic-SIM 9Fxx both request GET RESPONSE.
                # SW2=00 encodes the maximum short Le.
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
                          predicate(command, response) if response.sw1 not in (0x61, 0x9F) else None)
                response_traced = True
            is_interesting = predicate(command, response)
            if trace is not None and not response_traced:
                trace(sequence, total, command, response, is_interesting)
            if is_interesting:
                yield ScanFinding(cla << 8 | instruction, response)
            if response.sw == 0x6881:
                opened_channels: list[int] = []
                try:
                    for _ in range(19):
                        open_command = bytes.fromhex("0070000001")
                        opened, _open_error = transmit(open_command, sequence)
                        if opened is None:
                            break
                        if trace is not None:
                            trace(sequence, total, open_command, opened, None)
                        if opened.sw != 0x9000 or not opened.data:
                            break
                        channel = opened.data[0]
                        if not 1 <= channel <= 19 or channel in opened_channels:
                            break
                        opened_channels.append(channel)
                        channel_command = bytes((encode_logical_channel_cla(command[0], channel),)) + command[1:]
                        channel_response, _channel_error = transmit(channel_command, sequence)
                        if channel_response is None:
                            continue
                        channel_interesting = predicate(channel_command, channel_response)
                        if trace is not None:
                            trace(sequence, total, channel_command, channel_response, channel_interesting)
                        if channel_interesting:
                            yield ScanFinding(cla << 8 | instruction, channel_response, channel)
                finally:
                    for channel in reversed(opened_channels):
                        close_command = bytes((0x00, 0x70, 0x80, channel))
                        closed, _close_error = transmit(close_command, sequence)
                        if trace is not None and closed is not None:
                            trace(sequence, total, close_command, closed, None)
            if level2 and response.sw == 0x6E00:
                # CLA is rejected, so the remaining 255 INS probes cannot add
                # information for this class.
                break


def tar_values(ranges: Iterable[tuple[int, int]], start: int = 0) -> Iterator[int]:
    for low, high in ranges:
        if not 0 <= low <= high <= 0xFFFFFF:
            raise ValueError("TAR range must fit in three bytes")
        yield from range(max(low, start), high + 1)


def build_tar_packets(ranges: Iterable[tuple[int, int]], *, keyset: int = 0,
                      start: int = 0, user_data: bytes = b"\0" * 5) -> Iterator[CommandPacket]:
    for value in tar_values(ranges, start):
        yield CommandPacket(value.to_bytes(3, "big"), keyset=keyset, user_data=user_data)


@dataclass(frozen=True)
class TARContextResult:
    name: str
    command: bytes
    response: APDUResponse
    analysis: ResponseAnalysis
    exchanges: tuple[tuple[bytes, APDUResponse], ...] = ()
    decoded: tuple[str, ...] = ()
    short_decoded: str = ""


def _ber_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    """Decode the definite-length BER-TLV subset used by UICC FCP templates."""
    result = []
    offset = 0
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag & 0x1F == 0x1F:
            if offset >= len(data):
                raise PacketError("truncated multi-byte BER tag")
            tag = tag << 8 | data[offset]
            offset += 1
        if offset >= len(data):
            raise PacketError("missing BER length")
        length = data[offset]
        offset += 1
        if length == 0x81:
            if offset >= len(data):
                raise PacketError("truncated BER length")
            length = data[offset]
            offset += 1
        elif length == 0x82:
            if offset + 2 > len(data):
                raise PacketError("truncated BER length")
            length = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
        elif length & 0x80:
            raise PacketError("unsupported BER length form")
        if offset + length > len(data):
            raise PacketError("BER value exceeds response length")
        result.append((tag, data[offset:offset + length]))
        offset += length
    return result


def decode_uicc_status_data(data: bytes) -> tuple[str, ...]:
    """Decode standardized ETSI UICC STATUS FCP fields conservatively."""
    if not data:
        return ("No STATUS response data",)
    try:
        outer = _ber_tlvs(data)
    except PacketError as exc:
        return (f"Malformed STATUS BER-TLV: {exc}", f"Raw data={data.hex().upper()}")
    if len(outer) != 1 or outer[0][0] != 0x62:
        return ("Response is not an FCP template (tag 62)", f"Raw data={data.hex().upper()}")
    details = [f"FCP template: {len(outer[0][1])} byte(s)"]
    lifecycle = {
        0x01: "creation", 0x03: "initialization", 0x04: "operational/deactivated",
        0x05: "operational/activated", 0x0C: "termination",
    }
    key_refs = {0x01: "PIN1", 0x81: "PIN2"}
    try:
        fields = _ber_tlvs(outer[0][1])
        for tag, value in fields:
            raw = value.hex().upper()
            if tag == 0x82:
                kind = "DF/ADF" if value and value[0] & 0x38 == 0x38 else "EF/other"
                shareable = "shareable" if value and value[0] & 0x40 else "not shareable"
                details.append(f"File descriptor={raw} ({kind}, {shareable})")
            elif tag == 0x83 and len(value) == 2:
                fid = int.from_bytes(value, "big")
                details.append(f"File identifier={fid:04X}" + (" (MF)" if fid == 0x3F00 else ""))
            elif tag == 0x8A and value:
                state = lifecycle.get(value[0], "ETSI/ISO profile-specific state")
                details.append(f"Life-cycle status={value[0]:02X} ({state})")
            elif tag == 0x8B:
                details.append(f"Security attributes (compact)={raw}")
            elif tag == 0xA5:
                for nested_tag, nested_value in _ber_tlvs(value):
                    nested_raw = nested_value.hex().upper()
                    if nested_tag == 0x80:
                        details.append(f"UICC characteristics={nested_raw}")
                    elif nested_tag == 0x83:
                        details.append(f"Available memory={int.from_bytes(nested_value, 'big')} byte(s)")
                    else:
                        details.append(f"Proprietary information tag {nested_tag:02X}={nested_raw}")
            elif tag == 0xC6:
                pin_fields = _ber_tlvs(value)
                qualifier = next((item for item in pin_fields if item[0] == 0x90), None)
                references = [item[1][0] for item in pin_fields if item[0] == 0x83 and item[1]]
                names = [key_refs.get(ref, f"ADM{ref - 9}" if 0x0A <= ref <= 0x0E else f"REF-{ref:02X}")
                         for ref in references]
                qualifier_text = qualifier[1].hex().upper() if qualifier else "missing"
                details.append(f"PIN status template: qualifier={qualifier_text}, references={','.join(names) or 'none'}")
            else:
                details.append(f"FCP tag {tag:02X}={raw}")
    except PacketError as exc:
        details.append(f"Malformed nested FCP BER-TLV: {exc}")
    return tuple(details)


def decode_card_recognition_data(data: bytes) -> tuple[str, ...]:
    """Decode the ISO/IEC 7816 card-recognition data object without guessing values."""
    if not data:
        return ("No GET DATA response data",)
    try:
        outer = _ber_tlvs(data)
    except PacketError as exc:
        return (f"Malformed card-recognition BER-TLV: {exc}",
                f"Raw response data={data.hex().upper()}")
    details = [f"Card-recognition response: {len(data)} byte(s)"]
    tag_names = {
        0x06: "Object identifier", 0x41: "Country code and national data",
        0x42: "Issuer identification number", 0x43: "Card service data",
        0x45: "Card issuer data", 0x46: "Pre-issuing data",
        0x47: "Card capabilities", 0x4F: "Application identifier",
        0x5F50: "Issuer URL", 0x73: "Card capabilities template",
    }

    def append_fields(fields: Sequence[tuple[int, bytes]], prefix: str = "") -> None:
        for tag, value in fields:
            label = tag_names.get(tag, f"Tag {tag:02X}")
            raw = value.hex().upper() or "<empty>"
            details.append(f"{prefix}{label}={raw}")
            if tag == 0x73 and value:
                try:
                    append_fields(_ber_tlvs(value), prefix="  ")
                except PacketError as exc:
                    details.append(f"  Malformed capabilities template: {exc}")

    # P1/P2=0066 normally returns the Card Recognition Data template (66).
    # Keep accepting an unwrapped object for cards/readers that return its value.
    if len(outer) == 1 and outer[0][0] == 0x66:
        details.append(f"Card Recognition Data template: {len(outer[0][1])} byte(s)")
        try:
            append_fields(_ber_tlvs(outer[0][1]))
        except PacketError as exc:
            details.append(f"Malformed template content: {exc}")
    else:
        details.append("Response is not wrapped in Card Recognition Data tag 66")
        append_fields(outer)
    return tuple(details)


def decode_tar_context_response(name: str, response: APDUResponse) -> tuple[str, ...]:
    """Return human-readable context data/status details without overclaiming."""
    if name.startswith("STATUS") and response.sw == 0x9000:
        return decode_uicc_status_data(response.data)
    if name.startswith("GET DATA") and response.sw == 0x9000:
        return decode_card_recognition_data(response.data)
    if name.startswith("GET DATA") and response.sw in (0x6D00, 0x6E00):
        return (f"GET DATA command format is not supported (SW={response.sw:04X})",
                "This result is unrelated to TAR existence, MSL, or PoR support")
    return ()


def summarize_tar_context_response(name: str, response: APDUResponse,
                                   decoded: Sequence[str]) -> str:
    """Create a one-line counterpart to the complete context decoding."""
    if name.startswith("STATUS") and response.sw == 0x9000:
        wanted = ("File identifier=", "File descriptor=", "Life-cycle status=",
                  "Available memory=", "PIN status template:")
        selected = [detail for detail in decoded if detail.startswith(wanted)]
        return "STATUS OK: " + "; ".join(selected or ("FCP returned but no standard fields decoded",))
    if name.startswith("GET DATA") and response.sw == 0x9000:
        templates = [detail for detail in decoded if "template:" in detail]
        capabilities = sum("capabilit" in detail.lower() for detail in decoded)
        suffix = f"; capability field(s)={capabilities}" if capabilities else ""
        return "GET DATA OK: " + "; ".join(templates or (f"{len(response.data)} byte(s) returned",)) + suffix
    if name.startswith("GET DATA") and response.sw in (0x6D00, 0x6E00):
        return (f"GET DATA unavailable with this command format ({response.sw:04X}); "
                "unrelated to TAR/MSL/PoR")
    info = decode_status_word(response.sw1, response.sw2)
    return f"{name}: SW={response.sw:04X} ({info.meaning})"


def analyze_tar_context_response(name: str, command: bytes,
                                 response: APDUResponse) -> ResponseAnalysis:
    """Interpret STATUS/GET DATA without confusing optional support with TARs."""
    if name.startswith("STATUS"):
        if response.sw == 0x9000:
            detail = " and returned status/FCP data" if response.data else " with no response data"
            return ResponseAnalysis(True, "medium", f"ETSI UICC STATUS succeeded{detail}",
                                    "Decode returned FCP/TLV data; this does not identify a TAR")
        if response.sw1 == 0x6C:
            return ResponseAnalysis(True, "medium", "UICC STATUS recognized, but corrected Le was not accepted",
                                    f"Card continues to request Le={response.sw2 or 256}; do not infer TAR support")
    if name.startswith("GET DATA") and response.sw in (0x6D00, 0x6E00, 0x6A81, 0x6A88):
        return ResponseAnalysis(False, "none",
                                "Optional ISO GET DATA object is unavailable in this UICC command context",
                                "Treat as a context capability result, not evidence for or against OTA/TAR support")
    generic = analyze_apdu_response(command, response)
    return ResponseAnalysis(generic.interesting, generic.severity, generic.conclusion,
                            generic.next_step + "; do not infer a TAR from this context command")


def probe_tar_scan_context(transport: CardTransport,
                           apdu_format: APDUFormat) -> list[TARContextResult]:
    """Issue read-only GET STATUS/GET DATA context probes around a TAR scan."""
    if apdu_format.third_gen:
        commands = (
            ("STATUS current UICC application", bytes.fromhex("80F2000000")),
            ("GET DATA card recognition data", bytes.fromhex("80CA006600")),
        )
    else:
        commands = (
            ("STATUS current SIM application", bytes.fromhex("A0F2000000")),
            ("GET DATA card recognition data", bytes.fromhex("A0CA006600")),
        )
    results = []
    for name, command in commands:
        response, exchanges = _card_command_trace(transport, command)
        decoded = decode_tar_context_response(name, response)
        results.append(TARContextResult(
            name, command, response, analyze_tar_context_response(name, command, response),
            exchanges, decoded, summarize_tar_context_response(name, response, decoded)
        ))
    return results


def ensure_por_requested(packet: CommandPacket) -> CommandPacket:
    """Return a packet whose SPI requests PoR without mutating the caller's packet."""
    return replace(packet, request_por=True, fake_spi2=None)


def classify_tar_scan_results(
    results: Sequence[tuple[str, str, CommandPacket, APDUResponse, ResponsePacket | None]],
) -> tuple[tuple[int, bytes], int,
           list[tuple[str, str, CommandPacket, APDUResponse, ResponsePacket | None]]]:
    """Separate repeated no-PoR transport behavior from differential findings."""
    signatures = Counter(
        (result[3].sw, result[3].data) for result in results if result[4] is None
    )
    baseline, count = signatures.most_common(1)[0] if signatures else ((0, b""), 0)
    findings = [
        result for result in results
        if result[4] is not None or count <= 1 or (result[3].sw, result[3].data) != baseline
    ]
    return baseline, count, findings


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
        analysis = analyze_apdu_response(command, response)
        status_counts[response.sw] += 1
        result = "follow-up" if found is None else ("FOUND" if found else "filtered")
        print(f"[{sequence:05d}/{total:05d}] RX DATA={data} SW={response.sw:04X} "
              f"{result} - {info.meaning} [{info.standard}] ANALYSIS={analysis.conclusion}", flush=True)

    transport = PCSCTransport(reader)
    apdu_format = detect_apdu_format(transport)
    print(f"Using {apdu_format.name} command format for card setup and follow-ups", flush=True)
    findings: list[ScanFinding] = []
    aborted = False
    try:
        for finding in scan_apdus(transport, level2=level2, trace=screen_trace):
            findings.append(finding)
            response = finding.response
            print(f"FINDING VALUE={finding.value:04X} CHANNEL={finding.channel} SW={response.sw:04X} "
                  f"DATA={response.data.hex().upper() or '<empty>'}", flush=True)
    except RuntimeError as exc:
        aborted = True
        print(f"SCAN ABORTED: {exc}", flush=True)
    finally:
        print_sim_summary(transport, apdu_format)
        try:
            transport.close()
        except Exception as exc:
            print(f"CARD CLOSE ERROR: {exc}", flush=True)
        print("\n========== APDU SCAN SUMMARY ==========", flush=True)
        print(f"Result: {'ABORTED' if aborted else 'COMPLETED'}", flush=True)
        print(f"Responses received: {sum(status_counts.values())}", flush=True)
        print(f"Communication errors/retries: {error_count}", flush=True)
        print(f"Potentially supported APDU values: {len(findings)}", flush=True)
        print("Interesting findings only:", flush=True)
        if findings:
            for finding in findings:
                response = finding.response
                info = decode_status_word(response.sw1, response.sw2)
                base_cla = finding.value >> 8
                actual_cla = encode_logical_channel_cla(base_cla, finding.channel)
                command = bytes((actual_cla, finding.value & 0xFF, 0, 0))
                analysis = analyze_apdu_response(command, response)
                print(f"  CLA={finding.value >> 8:02X} INS={finding.value & 0xFF:02X} "
                      f"CHANNEL={finding.channel} APDU={command.hex().upper()} SW={response.sw:04X} "
                      f"DATA={response.data.hex().upper() or '<empty>'} SEVERITY={analysis.severity} "
                      f"- {info.meaning}; {analysis.conclusion}; NEXT={analysis.next_step}", flush=True)
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
    supplied_probes = known_tar_packets(keyset, groups) if probes is None else probes
    # A TAR scan is only conclusive when the UICC can return a response packet.
    # Force the PoR request bit even for caller-supplied packets that omitted it.
    probe_list = [
        (group, ensure_por_requested(packet))
        for group, packet in supplied_probes
    ]
    transport = PCSCTransport(reader)
    apdu_format = detect_apdu_format(transport)
    results: list[tuple[str, str, CommandPacket, APDUResponse, ResponsePacket | None]] = []
    context_results: list[TARContextResult] = []
    errors = 0
    print(f"{title} START: {len(probe_list)} probes; reader {reader}: "
          f"{reader_names[reader]}; keyset {keyset}; "
          f"SIMTester Python {__version__} ({BUILD_ID})", flush=True)
    try:
        print("Read-only card context probes:", flush=True)
        try:
            for context in probe_tar_scan_context(transport, apdu_format):
                context_results.append(context)
                for exchange_index, (exchange_command, exchange_response) in enumerate(context.exchanges, 1):
                    info = decode_status_word(exchange_response.sw1, exchange_response.sw2)
                    print(f"  {context.name} [{exchange_index}/{len(context.exchanges)}] "
                          f"TX={exchange_command.hex().upper()} "
                          f"RX={exchange_response.data.hex().upper() or '<empty>'} "
                          f"SW={exchange_response.sw:04X} - {info.meaning}", flush=True)
                print(f"    ANALYSIS={context.analysis.conclusion}; "
                      f"NEXT={context.analysis.next_step}", flush=True)
                print(f"    COMPACT={context.short_decoded}", flush=True)
                if context.decoded:
                    print("    EXPANDED:", flush=True)
                    print(f"      - Raw response data="
                          f"{context.response.data.hex().upper() or '<empty>'}", flush=True)
                    for detail in context.decoded:
                        print(f"      - {detail}", flush=True)
        except Exception as exc:
            errors += 1
            print(f"  Context probe error: {exc}; continuing with TAR probes", flush=True)
        for index, (group, packet) in enumerate(probe_list, 1):
            tar = packet.tar.hex().upper()
            command = build_sms_pp_download_apdu(packet, third_gen=apdu_format.third_gen)
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
            por = f" ({decode_por_status(parsed.status_code)})" if parsed is not None else ""
            print(f"[{index:03d}/{len(probe_list):03d}] {group}:{tar} RX "
                  f"DATA={data.hex().upper() or '<empty>'} SW={response.sw:04X}{ota} "
                  f"{por} - {info.meaning}; {requested_msl(packet)}", flush=True)
            results.append((group, tar, packet, response, parsed))
    finally:
        print_sim_summary(transport, apdu_format)
        try:
            transport.close()
        except Exception:
            pass
    parsed_results = [result for result in results if result[4] is not None]
    baseline_signature, baseline_count, interesting_results = classify_tar_scan_results(results)
    insecure = [result for result in parsed_results
                if result[4].status_code == 0 and requested_msl(result[2]).startswith("MSL=0")]
    por_requested = sum(1 for result in results if result[2].request_por)
    por_received = sum(1 for result in parsed_results if result[2].request_por)
    msl_attempts = Counter(requested_msl(result[2]) for result in results)
    msl_successes = Counter(requested_msl(result[2]) for result in parsed_results
                            if result[4].status_code == 0)
    print(f"\n========== {title} SUMMARY ==========", flush=True)
    print(f"Tool build: SIMTester Python {__version__} ({BUILD_ID})", flush=True)
    print(f"Probes attempted: {len(probe_list)}", flush=True)
    print(f"Card responses: {len(results)}", flush=True)
    print(f"Communication errors/retries: {errors}", flush=True)
    print(f"Parsed OTA response packets: {len(parsed_results)}", flush=True)
    print(f"PoR support: {por_received}/{por_requested} requested PoR packets received", flush=True)
    if baseline_count:
        baseline_sw, baseline_data = baseline_signature
        baseline_info = decode_status_word(baseline_sw >> 8, baseline_sw & 0xFF)
        print(f"Dominant no-PoR baseline: {baseline_count}/{len(results)} responses "
              f"SW={baseline_sw:04X} DATA={baseline_data.hex().upper() or '<empty>'} "
              f"- {baseline_info.meaning}", flush=True)
        if baseline_sw >> 8 == 0x62:
            print("  Analysis: ENVELOPE produced the same warning for unrelated TARs; "
                  "this is transport/parser behavior, not evidence that any listed TAR exists.", flush=True)
    print("GET STATUS / GET DATA context:", flush=True)
    for context in context_results:
        info = decode_status_word(context.response.sw1, context.response.sw2)
        print(f"  {context.name}: SW={context.response.sw:04X} "
              f"SEVERITY={context.analysis.severity} - {info.meaning}; "
              f"{context.analysis.conclusion}", flush=True)
        print(f"    COMPACT: {context.short_decoded}", flush=True)
        if context.decoded:
            print("    EXPANDED:", flush=True)
            print(f"      - Raw response data="
                  f"{context.response.data.hex().upper() or '<empty>'}", flush=True)
            for detail in context.decoded:
                print(f"      - {detail}", flush=True)
    if not context_results:
        print("  unavailable", flush=True)
    print("MSL coverage:", flush=True)
    for level, attempts in msl_attempts.items():
        print(f"  {level}: responses={attempts}, successful-PoR={msl_successes[level]}", flush=True)
    if insecure:
        print(f"WARNING: {len(insecure)} UNSECURE MSL=0 command(s) succeeded", flush=True)
    print(f"Interesting differential/PoR findings: {len(interesting_results)}", flush=True)
    for group, tar, packet, response, parsed in interesting_results:
        info = decode_status_word(response.sw1, response.sw2)
        ota = (f" OTA-RSC={parsed.status_code:02X}({decode_por_status(parsed.status_code)})"
               if parsed is not None else " no-PoR")
        warning = " WARNING=UNSECURE" if (parsed is not None and parsed.status_code == 0
                                          and requested_msl(packet).startswith("MSL=0")) else ""
        print(f"  {group}:{tar} SW={response.sw:04X}{ota} "
              f"DATA={response.data.hex().upper() or '<empty>'} {requested_msl(packet)}"
              f"{warning} - {info.meaning}", flush=True)
    if not interesting_results:
        print("  None", flush=True)
    print("============================================", flush=True)


@dataclass(frozen=True)
class OTAFuzzResult:
    pid: int
    dcs: int
    udhi: bool
    response: APDUResponse
    por: ResponsePacket | None = None


def analyze_ota_fuzz_results(results: Sequence[OTAFuzzResult]) -> list[str]:
    """Find parameter-correlated OTA behavior without overstating empty 9000 replies."""
    if not results:
        return ["No card responses were received."]
    lines: list[str] = []
    signatures = Counter((result.response.sw, result.response.data) for result in results)
    dominant, dominant_count = signatures.most_common(1)[0]
    lines.append(f"Dominant response: SW={dominant[0]:04X} DATA={dominant[1].hex().upper() or '<empty>'} "
                 f"({dominant_count}/{len(results)} variants)")
    empty_success = sum(1 for result in results
                        if result.response.sw == 0x9000 and not result.response.data)
    if empty_success:
        lines.append(f"{empty_success} variant(s) returned empty 9000: ENVELOPE accepted, but no PoR/data proves OTA execution.")
    warnings = [result for result in results if result.response.sw1 == 0x62]
    if warnings:
        labels = ", ".join(f"PID={r.pid:02X}/DCS={r.dcs:02X}/UDHI={int(r.udhi)}" for r in warnings)
        lines.append(f"WARNING-sensitive variants ({len(warnings)}): {labels}")
    sensitivity: dict[str, int] = {}
    controlled_groups: dict[str, int] = {}
    for field, label in (("pid", "PID"), ("dcs", "DCS"), ("udhi", "UDHI")):
        other_fields = [name for name in ("pid", "dcs", "udhi") if name != field]
        groups: dict[tuple[object, ...], list[OTAFuzzResult]] = {}
        for result in results:
            key = tuple(getattr(result, name) for name in other_fields)
            groups.setdefault(key, []).append(result)
        differences = 0
        comparable = 0
        for group in groups.values():
            if len({getattr(item, field) for item in group}) > 1:
                comparable += 1
                if len({item.response.sw for item in group}) > 1:
                    differences += 1
        sensitivity[field] = differences
        controlled_groups[field] = comparable
        if differences:
            lines.append(f"{label}-sensitive behavior: {differences} controlled comparison(s) changed SW.")
        elif comparable:
            lines.append(f"{label}-independent behavior: all {comparable} controlled comparison(s) kept the same SW.")
    by_parameters = {(result.pid, result.dcs, result.udhi): result.response.sw for result in results}
    ota_path_pairs = 0
    seven_bit_pairs = 0
    tested_pids = sorted({result.pid for result in results})
    for pid in tested_pids:
        if (by_parameters.get((pid, 0x00, False)) == 0x9000
                and by_parameters.get((pid, 0x00, True)) == 0x9000):
            seven_bit_pairs += 1
        for dcs in (0x04, 0xF6):
            if (by_parameters.get((pid, dcs, False)) == 0x9000
                    and by_parameters.get((pid, dcs, True), 0) >> 8 == 0x62):
                ota_path_pairs += 1
    if ota_path_pairs:
        lines.append(
            f"DCS/UDHI interaction: {ota_path_pairs} pair(s) changed from empty 9000 with UDHI=0 "
            "to 62xx with UDHI=1 for 8-bit/class-2 DCS 04/F6. This strongly suggests the "
            "secured-packet UDH reaches a different UICC parser path."
        )
    if seven_bit_pairs:
        lines.append(
            f"DCS=00 control: all {seven_bit_pairs} PID pair(s) stayed at empty 9000 regardless of UDHI; "
            "the 7-bit alphabet setting likely prevents equivalent binary OTA processing."
        )
    if controlled_groups.get("pid") and not sensitivity.get("pid"):
        lines.append(
            "PID conclusion: PID 00/40/7F did not affect any matched comparison; observed behavior is "
            "driven by DCS/UDHI rather than PID within this test set."
        )
    por_results = [result for result in results if result.por is not None]
    lines.append(f"PoR support: {len(por_results)}/{len(results)} variants returned a parseable response packet.")
    insecure = [result for result in por_results if result.por.status_code == 0]
    if insecure:
        lines.append(f"SECURITY WARNING: {len(insecure)} MSL=0 OTA variant(s) returned successful PoR.")
    else:
        lines.append("No successful MSL=0 PoR was observed; transport acceptance alone is not an unprotected-TAR finding.")
    return lines


def _run_ota_fuzzing(reader: int, tar: str, keyset: int,
                     bruteforce: bool = False) -> None:
    """Fuzz SMS PID, DCS, and UDHI around one OTA command packet."""
    pids = range(256) if bruteforce else (0x00, 0x40, 0x7F)
    dcss = range(256) if bruteforce else (0x00, 0x04, 0xF6)
    combinations = [(pid, dcs, udhi) for pid in pids for dcs in dcss for udhi in (False, True)]
    packet = CommandPacket(bytes.fromhex(tar), keyset=keyset, user_data=b"\0" * 5)
    transport = PCSCTransport(reader)
    apdu_format = detect_apdu_format(transport)
    counts: Counter[int] = Counter()
    results: list[OTAFuzzResult] = []
    try:
        for index, (pid, dcs, udhi) in enumerate(combinations, 1):
            command = build_sms_pp_download_apdu(
                packet, third_gen=apdu_format.third_gen, pid=pid, dcs=dcs, udhi=udhi
            )
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
            analysis = analyze_apdu_response(command, response)
            parsed = None
            try:
                parsed = ResponsePacket.parse(response.data, strict=False)
            except PacketError:
                pass
            results.append(OTAFuzzResult(pid, dcs, udhi, response, parsed))
            if response.sw == 0x9000 and not response.data:
                ota_analysis = "ENVELOPE accepted only; empty 9000 is not PoR and does not prove OTA execution"
            elif response.sw1 == 0x62:
                ota_analysis = ("UICC returned a state-unchanged warning; retain as parser-path evidence, "
                                "not as proof of command execution")
            else:
                ota_analysis = analysis.conclusion
            print(f"  RX={response.data.hex().upper() or '<empty>'} SW={response.sw:04X} "
                  f"- {info.meaning}; ANALYSIS={ota_analysis}", flush=True)
    finally:
        print_sim_summary(transport, apdu_format)
        try:
            transport.close()
        except Exception:
            pass
    print("\n========== OTA FUZZING SUMMARY ==========", flush=True)
    print(f"Combinations attempted: {len(combinations)}", flush=True)
    for sw, count in counts.most_common():
        print(f"  SW={sw:04X} COUNT={count} - {decode_status_word(sw >> 8, sw & 255).meaning}", flush=True)
    print("Smart differential analysis:", flush=True)
    for line in analyze_ota_fuzz_results(results):
        print(f"  {line}", flush=True)
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
        assert decode_status_word(0x69, 0x87).category == "security"
        assert "TLV" in decode_status_word(0x6A, 0x85).meaning
        assert "7 internal" in decode_status_word(0x92, 0x07).meaning
        try:
            decode_status_word(0x100, 0)
        except ValueError:
            pass
        else:
            raise AssertionError("out-of-range SW1 accepted")
        assert analyze_apdu_response(bytes.fromhex("00240000"), APDUResponse(b"", 0x67, 0)).interesting
        assert "recognized" in analyze_apdu_response(
            bytes.fromhex("00200000"), APDUResponse(b"", 0x6B, 0)
        ).conclusion
        assert not analyze_apdu_response(
            bytes.fromhex("006D0000"), APDUResponse(b"", 0x6D, 0)
        ).interesting

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

    @check("short APDU cases and 6C correction")
    def _correct_le() -> None:
        assert with_correct_le(bytes.fromhex("00CA0000"), 256) == bytes.fromhex("00CA000000")
        assert with_correct_le(bytes.fromhex("00CA000010"), 4) == bytes.fromhex("00CA000004")
        assert with_correct_le(bytes.fromhex("00DA000002AABB"), 3) == bytes.fromhex("00DA000002AABB03")
        assert with_correct_le(bytes.fromhex("00DA000002AABB10"), 3) == bytes.fromhex("00DA000002AABB03")
        commands: list[bytes] = []

        def wrong_le_card(apdu: bytes) -> APDUResponse:
            commands.append(apdu)
            if apdu == bytes.fromhex("00000000"):
                return APDUResponse(b"", 0x6C, 0x02)
            if apdu == bytes.fromhex("0000000002"):
                return APDUResponse(b"OK", 0x90, 0x00)
            return APDUResponse(b"", 0x6E, 0x00)

        findings = list(scan_apdus(MockTransport(wrong_le_card)))
        assert commands[:2] == [bytes.fromhex("00000000"), bytes.fromhex("0000000002")]
        assert findings[0].response == APDUResponse(b"OK", 0x90, 0x00)

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
        assert requested_msl(packets[0][1]) == "MSL=0 (no command security)"
        assert "CC" in requested_msl(packets[5][1])
        assert "ciphering" in requested_msl(packets[13][1])
        matrix = [
            OTAFuzzResult(
                pid, dcs, udhi,
                APDUResponse(b"", 0x62 if udhi and dcs in (0x04, 0xF6) else 0x90, 0),
            )
            for pid in (0x00, 0x40, 0x7F)
            for dcs in (0x00, 0x04, 0xF6)
            for udhi in (False, True)
        ]
        intelligence = analyze_ota_fuzz_results(matrix)
        assert any("UDHI-sensitive" in line for line in intelligence)
        assert any("DCS-sensitive" in line for line in intelligence)
        assert any("PID-independent" in line for line in intelligence)
        assert any("DCS/UDHI interaction: 6 pair(s)" in line for line in intelligence)
        assert any("DCS=00 control: all 3 PID pair(s)" in line for line in intelligence)
        assert any("PID conclusion" in line for line in intelligence)
        assert any("no PoR/data proves OTA execution" in line for line in intelligence)
        assert any("not an unprotected-TAR finding" in line for line in intelligence)

    @check("combined ATR index, forced PoR and TAR context probes")
    def _tar_scan_intelligence() -> None:
        global _ATR_DATABASE_CACHE, _EFTLAB_ATR_CACHE, _COMBINED_ATR_CACHE
        saved = (_ATR_DATABASE_CACHE, _EFTLAB_ATR_CACHE, _COMBINED_ATR_CACHE)
        try:
            _ATR_DATABASE_CACHE = ("3B 10 94\n\tThales UICC", "pcsc fixture")
            _EFTLAB_ATR_CACHE = ("3B 10 94\n\tGemalto telecom SIM", "EFTLab fixture")
            _COMBINED_ATR_CACHE = None
            combined, sources = load_combined_atr_database()
            assert combined is not None and "Thales UICC" in combined
            assert "Gemalto telecom SIM" in combined and "pcsc fixture" in sources
        finally:
            _ATR_DATABASE_CACHE, _EFTLAB_ATR_CACHE, _COMBINED_ATR_CACHE = saved

        no_por = CommandPacket(bytes.fromhex("B00010"), request_por=False, fake_spi2=0)
        with_por = ensure_por_requested(no_por)
        assert not no_por.request_por and with_por.request_por and with_por.fake_spi2 is None
        commands: list[bytes] = []

        def context_card(apdu: bytes) -> APDUResponse:
            commands.append(apdu)
            if apdu == bytes.fromhex("80F2000000"):
                return APDUResponse(b"", 0x6C, 0x2B)
            if apdu == bytes.fromhex("80F200002B"):
                return APDUResponse(b"FCP", 0x90, 0x00)
            return APDUResponse(b"", 0x6A, 0x88)

        context = probe_tar_scan_context(
            MockTransport(context_card), APDUFormat("3G/UICC", True, 0, 0x80)
        )
        assert [item.name for item in context] == [
            "STATUS current UICC application", "GET DATA card recognition data"
        ]
        assert context[0].response == APDUResponse(b"FCP", 0x90, 0x00)
        assert "UICC STATUS succeeded" in context[0].analysis.conclusion
        assert context[1].response.sw == 0x6A88
        assert not context[1].analysis.interesting
        assert "Optional ISO GET DATA" in context[1].analysis.conclusion
        assert commands == [bytes.fromhex(value) for value in (
            "80F2000000", "80F200002B", "80CA006600"
        )]
        packet = CommandPacket(bytes.fromhex("000000"))
        scan_rows = [
            ("RAM", f"{index:06X}", packet, APDUResponse(b"", 0x62, 0), None)
            for index in range(3)
        ]
        scan_rows.append(("RAM", "000003", packet, APDUResponse(b"PoR", 0x90, 0),
                          ResponsePacket(None, None, 0, 0, None, b"", b"")))
        baseline, count, findings = classify_tar_scan_results(scan_rows)
        assert baseline == (0x6200, b"") and count == 3
        assert len(findings) == 1 and findings[0][4] is not None
        logged_fcp = bytes.fromhex(
            "62298202782183023F00A509800171830400042DD08A01058B032F0612"
            "C60C90016083010183018183010A"
        )
        decoded = decode_uicc_status_data(logged_fcp)
        assert "FCP template: 41 byte(s)" in decoded
        assert "File identifier=3F00 (MF)" in decoded
        assert "Life-cycle status=05 (operational/activated)" in decoded
        assert "Available memory=273872 byte(s)" in decoded
        assert "PIN status template: qualifier=60, references=PIN1,PIN2,ADM1" in decoded
        short = summarize_tar_context_response(
            "STATUS current UICC application", APDUResponse(logged_fcp, 0x90, 0x00), decoded
        )
        assert short.startswith("STATUS OK:")
        assert "File identifier=3F00 (MF)" in short
        assert "Available memory=273872 byte(s)" in short
        get_data = decode_tar_context_response(
            "GET DATA card recognition data", APDUResponse(b"", 0x6D, 0x00)
        )
        assert "not supported" in get_data[0] and "unrelated to TAR" in get_data[1]
        get_data_short = summarize_tar_context_response(
            "GET DATA card recognition data", APDUResponse(b"", 0x6D, 0x00), get_data
        )
        assert get_data_short == "GET DATA unavailable with this command format (6D00); unrelated to TAR/MSL/PoR"

        recognition = bytes.fromhex("660A4602010273044702AABB")
        recognition_decoded = decode_card_recognition_data(recognition)
        assert "Card Recognition Data template: 10 byte(s)" in recognition_decoded
        assert "Pre-issuing data=0102" in recognition_decoded
        assert "  Card capabilities=AABB" in recognition_decoded
        get_data_ok = summarize_tar_context_response(
            "GET DATA card recognition data", APDUResponse(recognition, 0x90, 0),
            recognition_decoded
        )
        assert get_data_ok.startswith("GET DATA OK: Card Recognition Data template:")

    @check("automatic 2G and 3G APDU format detection")
    def _apdu_format_detection() -> None:
        uicc = MockTransport(lambda apdu: APDUResponse(b"", 0x90, 0))
        assert detect_apdu_format(uicc).name == "3G/UICC"

        def classic_sim(apdu: bytes) -> APDUResponse:
            return APDUResponse(b"", 0x6E, 0) if apdu[0] == 0 else APDUResponse(b"", 0x9F, 0x16)

        detected = detect_apdu_format(MockTransport(classic_sim))
        assert detected.name == "2G SIM" and detected.envelope_cla == 0xA0
        packet = CommandPacket(bytes.fromhex("B00010"), user_data=b"\0" * 5)
        assert build_sms_pp_download_apdu(packet, third_gen=False)[:2] == bytes.fromhex("A0C2")

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
        calls = 0

        def unsupported_cla(_apdu: bytes) -> APDUResponse:
            nonlocal calls
            calls += 1
            return APDUResponse(b"", 0x6E, 0)

        assert list(scan_apdus(MockTransport(unsupported_cla), level2=True)) == []
        assert calls == 256

    @check("6881 opens and probes 3GPP logical channels")
    def _logical_channels() -> None:
        commands: list[bytes] = []

        def channel_card(apdu: bytes) -> APDUResponse:
            commands.append(apdu)
            if apdu == bytes.fromhex("00000000"):
                return APDUResponse(b"", 0x68, 0x81)
            if apdu == bytes.fromhex("0070000001"):
                return APDUResponse(b"\x01", 0x90, 0)
            if apdu == bytes.fromhex("01000000"):
                return APDUResponse(b"channel-one", 0x90, 0)
            if apdu == bytes.fromhex("00708001"):
                return APDUResponse(b"", 0x90, 0)
            return APDUResponse(b"", 0x6E, 0)

        scanner = scan_apdus(MockTransport(channel_card))
        finding = next(scanner)
        assert finding.channel == 1 and finding.response.data == b"channel-one"
        scanner.close()
        assert commands[:3] == [bytes.fromhex("00000000"), bytes.fromhex("0070000001"),
                               bytes.fromhex("01000000")]
        assert commands[-1] == bytes.fromhex("00708001")
        assert encode_logical_channel_cla(0x00, 4) == 0x40
        assert encode_logical_channel_cla(0x00, 19) == 0x4F
        assert encode_logical_channel_cla(0x80, 4) == 0xC0

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

    @check("SIM summary decodes ICCID, IMSI, MSISDN and SPN")
    def _sim_summary() -> None:
        class SummaryCard:
            selected = 0

            def atr(self) -> bytes:
                return bytes.fromhex("3B00")

            def transmit(self, apdu: bytes) -> APDUResponse:
                if apdu[1] == 0xA4:
                    self.selected = int.from_bytes(apdu[-2:], "big")
                    return APDUResponse(b"", 0x6A, 0x82) if self.selected == 0x5F11 else APDUResponse(b"", 0x90, 0)
                files = {
                    0x2FE2: bytes.fromhex("981032547698103254F6"),
                    0x6F07: bytes.fromhex("082943658709214365"),
                    0x6F46: b"\x00Carrier\xFF",
                    0x6F40: bytes.fromhex("06912143658709FFFFFFFFFFFFFF"),
                }
                return APDUResponse(files.get(self.selected, b""), 0x90, 0)

        summary = collect_sim_summary(
            SummaryCard(), APDUFormat("3G/UICC", True, 0, 0x80), use_atr_database=False
        )
        assert summary["ATR"] == "3B00"
        assert summary["ATR convention"] == "direct" and summary["ATR protocols"] == "T=0"
        assert summary["APDU format"] == "3G/UICC"
        assert summary["Supported command CLA"] == "SELECT=00, ENVELOPE=80"
        assert summary["ICCID"] == "8901234567890123456"
        assert summary["IMSI"] == "234567890123456"
        assert summary["MSISDN"] == "+1234567890"
        assert summary["SPN"] == "Carrier"
        assert summary["PIN1 status"] == "enabled and already verified [CLA=00, REF=01]"
        assert summary["SIM vendor"] == "unknown"
        t1 = decode_atr(bytes.fromhex("3B800181"))
        assert t1["ATR protocols"] == "T=1" and t1["ATR TCK"] == "81"
        fast = decode_atr(bytes.fromhex("3B1094"))
        assert "78125 bit/s" in fast["ATR PPS speed"]
        assert fast["ATR PPS request"] == "FF10947B"
        vendor = detect_sim_vendor(b"3B GEMALTO", None)
        assert vendor[0] == "Gemalto/Thales"
        database = "3B 10 ..\n\tGemalto test UICC\n\n3F 00\n\tOther card\n"
        assert lookup_atr_database(bytes.fromhex("3B1094"), database) == ["Gemalto test UICC"]
        db_vendor = detect_sim_vendor(bytes.fromhex("3B1094"), None, atr_database_text=database)
        assert db_vendor[0] == "Gemalto/Thales"
        assert "Thales" in MAJOR_SIM_VENDOR_INFO["Gemalto/Thales"]
        eftlab = _eftlab_html_to_database(
            "<table><tr><td>3B 10 94</td><td>Thales demo UICC</td></tr></table>"
        )
        assert lookup_atr_database(bytes.fromhex("3B1094"), eftlab) == ["Thales demo UICC"]
        filtered = filter_major_sim_atr_matches((
            "Gemalto banking card", "Unknown operator UICC", "Thales 5G UICC",
            "Giesecke+Devrient USIM", "random access badge",
        ))
        assert filtered == [("Thales", "Thales 5G UICC"),
                            ("Giesecke+Devrient", "Giesecke+Devrient USIM")]

    @check("PIN2 and PUK2 fall back from UICC to classic references")
    def _credential_fallback() -> None:
        commands: list[bytes] = []

        def handler(apdu: bytes) -> APDUResponse:
            commands.append(apdu)
            if apdu[3] == 0x81:
                return APDUResponse(b"", 0x6B, 0x00)
            return APDUResponse(b"", 0x63, 0xC7 if apdu[1] == 0x20 else 0xCA)

        card = MockTransport(handler)
        card_format = APDUFormat("3G/UICC", True, 0, 0x80)
        pin2 = _credential_status(card, card_format, 0x20, (0x81, 0x02))
        puk2 = _credential_status(card, card_format, 0x2C, (0x81, 0x02))
        assert pin2 == "enabled, 7 attempts remaining [CLA=00, REF=02]"
        assert puk2 == "enabled, 10 attempts remaining [CLA=00, REF=02]"
        assert commands == [bytes.fromhex("00200081"), bytes.fromhex("00200002"),
                            bytes.fromhex("002C0081"), bytes.fromhex("002C0002")]

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
    parser.add_argument("--version", action="version",
                        version=f"SIMTester Python {__version__} ({BUILD_ID})")
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
