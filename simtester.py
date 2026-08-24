#!/usr/bin/env python3
"""Standalone Python SIMTester: codecs, transports, scanners, CLI, and menu."""
from __future__ import annotations

import argparse
import json
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
    def readers() -> list[str]:
        try:
            from smartcard.System import readers
        except ImportError as exc:
            raise RuntimeError("PC/SC requires the optional 'pyscard' package") from exc
        return [str(reader) for reader in readers()]

    def __init__(self, reader_index: int = 0):
        try:
            from smartcard.System import readers
        except ImportError as exc:
            raise RuntimeError("PC/SC requires the optional 'pyscard' package") from exc
        available = readers()
        if not 0 <= reader_index < len(available):
            raise RuntimeError(f"reader {reader_index} unavailable; found {len(available)}")
        self.connection = available[reader_index].createConnection()
        self.connection.connect()

    def transmit(self, apdu: bytes) -> APDUResponse:
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        return APDUResponse(bytes(data), sw1, sw2)

    def close(self) -> None:
        self.connection.disconnect()


@dataclass(frozen=True)
class ScanFinding:
    value: int
    response: APDUResponse


def scan_apdus(transport: CardTransport, *, level2: bool = False,
               interesting: Callable[[APDUResponse], bool] | None = None) -> Iterator[ScanFinding]:
    """Probe CLA and optionally INS values, yielding supported responses."""
    predicate = interesting or (lambda response: response.sw not in {0x6E00, 0x6D00, 0x6881, 0x6882})
    for cla in range(256):
        for instruction in range(256) if level2 else (0,):
            response = transport.transmit(bytes((cla, instruction, 0, 0)))
            if predicate(response):
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


def _print_response(packet: ResponsePacket) -> None:
    print(json.dumps({"tar": packet.tar.hex().upper() if packet.tar else None,
                      "counter": packet.counter, "padding_counter": packet.padding_counter,
                      "status_code": packet.status_code,
                      "checksum": packet.checksum.hex().upper() if packet.checksum else None,
                      "additional_data": packet.additional_data.hex().upper(),
                      "proprietary": packet.proprietary}, indent=2))


def _run_scan(reader: int, level2: bool) -> None:
    transport = PCSCTransport(reader)
    try:
        for finding in scan_apdus(transport, level2=level2):
            response = finding.response
            print(f"{finding.value:04X},{response.sw:04X},{response.data.hex().upper()}")
    finally:
        transport.close()


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

    @check("TAR generation is inclusive and resumable")
    def _tar_generation() -> None:
        assert list(tar_values([(1, 3), (10, 11)], start=2)) == [2, 3, 10, 11]

    @check("APDU scan filters unsupported classes")
    def _apdu_scan() -> None:
        transport = MockTransport(
            lambda apdu: APDUResponse(b"ok", 0x90, 0) if apdu[0] == 7
            else APDUResponse(b"", 0x6E, 0)
        )
        findings = list(scan_apdus(transport))
        assert len(findings) == 1 and findings[0].value == 0x0700

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
        "1": "Build OTA command packet", "2": "Parse OTA command packet",
        "3": "Parse OTA response packet", "4": "Preview TAR scan packets",
        "5": "List PC/SC readers", "6": "Run APDU level 1 scan",
        "7": "Run APDU level 2 scan", "8": "Run built-in self-tests",
        "0": "Exit",
    }
    while True:
        print("\nSIMTester Python — authorized test cards only")
        for key, label in actions.items():
            print(f"  {key}. {label}")
        choice = input("Choose an option: ").strip()
        try:
            if choice == "0":
                return 0
            if choice == "1":
                packet = CommandPacket(_hex("TAR [B00010]: ", length=3, default="B00010"),
                                       _read_int("Keyset [0]: "), _read_int("Counter [0]: "),
                                       _hex("User data hex [empty]: "))
                print(packet.to_bytes().hex().upper())
            elif choice == "2":
                packet = CommandPacket.parse(_hex("Command packet hex: "))
                print(packet)
            elif choice == "3":
                _print_response(ResponsePacket.parse(_hex("Response packet hex: "), strict=False))
            elif choice == "4":
                low = _read_int("First TAR hex [000000]: ", base=16)
                high = _read_int("Last TAR hex [00000F]: ", 15, 16)
                keyset = _read_int("Keyset [0]: ")
                for packet in build_tar_packets([(low, high)], keyset=keyset):
                    print(f"{packet.tar.hex().upper()}: {packet.to_bytes().hex().upper()}")
            elif choice == "5":
                readers = PCSCTransport.readers()
                print("\n".join(f"{index}: {reader}" for index, reader in enumerate(readers)) or "No readers found")
            elif choice in {"6", "7"}:
                _run_scan(_read_int("Reader index [0]: "), choice == "7")
            elif choice == "8":
                run_self_tests()
            else:
                print("Unknown option. Choose 0 through 8.")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
