from dataclasses import dataclass
from .FuzzerData import FuzzerData
from ._utils import CommandPacketView, ResponsePacketView


@dataclass(frozen=True)
class FuzzerResult:
    command_packet: CommandPacketView
    fuzzer: FuzzerData
    response_packet: ResponsePacketView

    def __hash__(self) -> int:
        return hash((self.command_packet.tar, self.command_packet.keyset, self.response_packet.raw))
