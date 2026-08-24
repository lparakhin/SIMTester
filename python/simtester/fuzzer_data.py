"""Port of de.srlabs.simtester.FuzzerData."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FuzzerData:
    name: str
    counter: int
    kic: int
    kid: int
    request_por: bool
    cipher_por: bool
