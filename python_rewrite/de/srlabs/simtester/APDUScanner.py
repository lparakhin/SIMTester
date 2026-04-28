"""Python APDU scanner implementation with pluggable transport."""

from collections.abc import Callable
from ._utils import CSVWriter, to_hex

Transport = Callable[[bytes], bytes]


def run(transmit: Transport, writer: CSVWriter, level2: bool = False, identifier: str = "I/O") -> None:
    print(f"Performing a {'LEVEL 2' if level2 else 'LEVEL 1'} APDU scan.")
    for cla in range(0x100):
        cla_apdu = bytes((cla, 0x00, 0x00, 0x00, 0x00))
        cla_res = transmit(cla_apdu)
        if not level2:
            writer.write_line(identifier, cla_apdu, cla_res)
        cla_sw = int.from_bytes(cla_res[-2:], "big") if len(cla_res) >= 2 else 0xFFFF
        if cla_sw in {0x6E00, 0x6881, 0x6882}:
            continue
        print(f"Valid CLA {cla:02X}, SW={cla_sw:04X}, response={to_hex(cla_res)}")
        if not level2:
            continue
        for ins in range(0x100):
            apdu = bytes((cla, ins, 0x00, 0x00, 0x00))
            res = transmit(apdu)
            writer.write_line(identifier, apdu, res)
            sw = int.from_bytes(res[-2:], "big") if len(res) >= 2 else 0xFFFF
            if sw == 0x6D00:
                continue
            print(f"Valid APDU CLA={cla:02X} INS={ins:02X} SW={sw:04X} response={to_hex(res)}")
    print("APDU scan has finished.")
