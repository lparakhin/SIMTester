"""Port of de.srlabs.simtester.FuzzerResult / FuzzerResultComparator."""

from __future__ import annotations

import functools

from simlib import hex_toolkit as hx


class FuzzerResult:
    def __init__(self, command_packet, fuzzer, response_packet):
        self.command_packet = command_packet
        self.fuzzer = fuzzer
        self.response_packet = response_packet

    def __hash__(self):
        return hash((bytes(self.command_packet.get_tar()), self.command_packet.get_keyset(), bytes(self.response_packet.get_bytes())))

    def __eq__(self, other):
        if not isinstance(other, FuzzerResult):
            return NotImplemented
        return (self.command_packet.get_tar() == other.command_packet.get_tar()
                and self.command_packet.get_keyset() == other.command_packet.get_keyset()
                and self.response_packet.get_bytes() == other.response_packet.get_bytes())


def _compare(a: FuzzerResult, b: FuzzerResult) -> int:
    by_tars = hx.compare_tars(a.command_packet.get_tar(), b.command_packet.get_tar())
    if by_tars == 0:
        return a.command_packet.get_keyset() - b.command_packet.get_keyset()
    return by_tars


fuzzer_result_key = functools.cmp_to_key(_compare)
