from dataclasses import dataclass


@dataclass(frozen=True)
class FuzzerData:
    name: str
    counter: int
    kic: int
    kid: int
    request_por: bool
    cipher_por: bool
