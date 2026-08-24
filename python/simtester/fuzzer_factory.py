"""Port of de.srlabs.simtester.FuzzerFactory."""

from __future__ import annotations

from simlib.command_packet import CommandPacket

from .fuzzer_data import FuzzerData

_FUZZERS: dict[int, FuzzerData] = {
    # special case for WIB/SAT
    0: FuzzerData("fuzzer0", CommandPacket.CNTR_NO_CNTR_AVAILABLE, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, False, False),

    # just signature
    1: FuzzerData("fuzzer1", CommandPacket.CNTR_NO_CNTR_AVAILABLE, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, False),
    2: FuzzerData("fuzzer2", CommandPacket.CNTR_CNTR_AVAILABLE, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, False),
    3: FuzzerData("fuzzer3", CommandPacket.CNTR_CNTR_HIGHER, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, False),
    4: FuzzerData("fuzzer4", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, False),
    5: FuzzerData("fuzzer5", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_DES_CBC, True, False),
    6: FuzzerData("fuzzer6", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_3DES_CBC_2KEYS, True, False),
    7: FuzzerData("fuzzer7", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_3DES_CBC_3KEYS, True, False),
    8: FuzzerData("fuzzer8", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_3DES_CBC_3KEYS, CommandPacket.KID_ALGO_3DES_CBC_3KEYS, True, False),

    # ciphered PoRs - same fuzzers as above, with ciphering enabled for PoRs
    9: FuzzerData("fuzzer9", CommandPacket.CNTR_NO_CNTR_AVAILABLE, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, True),
    10: FuzzerData("fuzzer10", CommandPacket.CNTR_CNTR_AVAILABLE, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, True),
    11: FuzzerData("fuzzer11", CommandPacket.CNTR_CNTR_HIGHER, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, True),
    12: FuzzerData("fuzzer12", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_IMPLICIT, CommandPacket.KID_ALGO_IMPLICIT, True, True),
    13: FuzzerData("fuzzer13", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_DES_CBC, CommandPacket.KID_ALGO_IMPLICIT, True, True),
    14: FuzzerData("fuzzer14", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_3DES_CBC_2KEYS, CommandPacket.KID_ALGO_IMPLICIT, True, True),
    15: FuzzerData("fuzzer15", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_3DES_CBC_3KEYS, CommandPacket.KID_ALGO_IMPLICIT, True, True),
    16: FuzzerData("fuzzer16", CommandPacket.CNTR_CNTR_ONE_HIGHER, CommandPacket.KIC_ALGO_3DES_CBC_3KEYS, CommandPacket.KID_ALGO_3DES_CBC_3KEYS, True, True),
}


def get_fuzzer(fuzzer_nr: int) -> FuzzerData:
    return _FUZZERS[fuzzer_nr]


def get_all_fuzzers() -> list[FuzzerData]:
    return list(_FUZZERS.values())


def get_amount_of_fuzzers() -> int:
    return len(_FUZZERS)


default_tars = [
    "RAM:000000",
    "WIB:000001", "WIB:000002", "WIB:000003", "WIB:000004", "WIB:000005",
    "WIB:000006", "WIB:000007", "WIB:000008", "WIB:000009",
    "RFM:00000A", "RFM:00000B", "RFM:00000C", "RFM:00000D", "RFM:00004F",
    "RFM:000057", "RFM:000070", "RFM:000076", "RFM:000080", "RFM:000092",
    "RFM:0000B6", "RFM:0000E2", "RFM:000203", "RFM:000304", "RFM:000503",
    "RFM:010001", "RFM:010101", "RFM:010203", "RFM:012345", "RFM:012347",
    "RFM:060504", "RFM:100000", "RFM:111212", "RFM:212223", "RFM:260500",
    "RFM:313131", "RFM:385300", "RFM:3F0000", "RFM:3F0001", "RFM:3F0002",
    "RFM:3F0010", "RFM:3F0011", "RFM:41444E", "RFM:414C4F", "RFM:415256",
    "RFM:415345", "RFM:424950", "RFM:425058", "RFM:434354", "RFM:443231",
    "RFM:474341", "RFM:47534D", "RFM:484353", "RFM:49434D", "RFM:494D45",
    "RFM:4C5041", "RFM:4D4552", "RFM:4D4C4D", "RFM:4E4147", "RFM:4E5550",
    "RFM:4E5553", "RFM:4E5650", "RFM:4F4350", "RFM:504F53", "SAT:505348",
    "RFM:514F43", "RFM:524144", "RFM:524648", "RFM:524A49", "RFM:54454C",
    "RFM:524F4D", "RFM:533347", "SAT:534054", "RFM:534143", "RFM:534441",
    "RFM:534F44", "RFM:53534D", "RFM:535353", "RFM:564153", "RFM:64646D",
    "RFM:800001", "RFM:800002", "RFM:800040", "RFM:800041", "RFM:B00000",
    "RFM:B00001", "RFM:B00002", "RFM:B00003", "RFM:B0000F", "RFM:B00010",
    "RFM:B00011", "RFM:B00012", "RFM:B00013", "RFM:B00020", "RFM:B00021",
    "RFM:B00030", "RFM:B00040", "RFM:B00041", "RFM:B00042", "RFM:B00050",
    "RFM:B000F1", "RFM:B00120", "RFM:B00140", "RFM:B00141", "RFM:B00142",
    "RFM:B00143", "RFM:B00144", "RFM:B00145", "RFM:B11000", "RFM:B20100",
    "RFM:B20102", "RFM:BAFE02", "WIB:BFFF00", "WIB:BFFF01", "WIB:BFFF02",
    "WIB:BFFF03", "WIB:BFFF04", "WIB:BFFF05", "WIB:BFFF15", "WIB:BFFF22",
    "WIB:BFFFBA", "WIB:BFFFEE", "WIB:BFFFFF", "RFM:C00000", "RFM:C0013D",
    "RFM:C001AA", "RFM:C001AB", "RFM:C001AD", "RFM:D00003", "RFM:EED200",
    "RFM:EED201", "RFM:EEE200", "RFM:EEE201", "RFM:FFFF01", "RFM:FFFFFF",
]
