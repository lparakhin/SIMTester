"""Port of de.srlabs.simtester.EntryPoint."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, eq=False)
class EntryPoint:
    tar: bytes
    keyset: int
    command_packet: object
    response_packet: object

    def __post_init__(self):
        if len(self.tar) != 3:
            raise ValueError("TAR must be 3 bytes")
        if not (0 <= self.keyset <= 15):
            raise ValueError("keyset must be between 0 and 15")

    def __hash__(self):
        return hash(self.tar)

    def __eq__(self, other):
        if not isinstance(other, EntryPoint):
            return NotImplemented
        return self.tar == other.tar
