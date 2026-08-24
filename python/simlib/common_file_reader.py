"""Port of de.srlabs.simlib.CommonFileReader."""

from __future__ import annotations

import sys

from . import config
from . import debug as _debug
from . import hex_toolkit as hx
from . import tlv_toolkit
from .file_management import FileManagement, FileNotFoundOnCard
from .logging_utils import format_debug_message
from .sim_card_file import SimCardLinearFixedFile


def read_loci() -> bytes | None:
    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)
    if _debug.DEBUG:
        print(format_debug_message("reading EF_LOCI file"))

    try:
        file = FileManagement.select_path("3f007f206f7e")
    except FileNotFoundOnCard:
        return None

    if file is None:
        return None
    return file.get_content()


def read_kc() -> bytes | None:
    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)
    if _debug.DEBUG:
        print(format_debug_message("reading EF_LOCI file"))

    try:
        file = FileManagement.select_path("3f007f206f20")
    except FileNotFoundOnCard:
        return None

    if file is None:
        return None
    return file.get_content()


def read_smsp() -> list[bytes] | None:
    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)
    if _debug.DEBUG:
        print(format_debug_message("reading EF_SMSP file"))

    try:
        file = FileManagement.select_path("3f007f106f42")
    except Exception:
        file = None

    if file is None:
        return None

    result = []
    smsp: SimCardLinearFixedFile = file
    for i in range(1, smsp.get_number_of_records() + 1):
        result.append(smsp.get_record(i))

    return result or None


def read_raw_msisdn() -> bytes | None:
    if _debug.DEBUG:
        print(format_debug_message("reading EF_MSISDN file"))

    try:
        file = FileManagement.select_path("6f40" if config.third_gen_apdu else "3f007f106f40")
    except FileNotFoundOnCard:
        file = None

    if file is None:
        return None

    content = file.get_first_record()
    if content is None:
        return None
    if content[len(content) - 14] != 0xFF:
        return content
    return None


def decode_msisdn(msisdn_content: bytes) -> str | None:
    if _debug.DEBUG:
        print(format_debug_message(f"decoding {hx.to_string(msisdn_content)}"))

    alpha_id_size = len(msisdn_content) - 14  # fixed size for the rest of the record
    length = msisdn_content[alpha_id_size]

    if length == 0 or length > 13:
        return None

    ton_npi = msisdn_content[alpha_id_size + 1]
    result = ""

    if hx.is_bit_set(ton_npi, 4) and not hx.is_bit_set(ton_npi, 5) and not hx.is_bit_set(ton_npi, 6):
        result += "+"

    for i in range(alpha_id_size + 2, length + alpha_id_size + 1):
        result += hx.to_string(hx.swap(msisdn_content[i]))

    return result


def read_st() -> bytes | None:
    try:
        if config.third_gen_apdu:
            if _debug.DEBUG:
                print(format_debug_message("reading EF_UST file"))
            file = FileManagement.select_path("6f38")
        else:
            if _debug.DEBUG:
                print(format_debug_message("reading EF_SST file"))
            file = FileManagement.select_path("3f007f206f38")
    except Exception:
        file = None

    if file is None:
        return None

    try:
        return file.get_content()
    except Exception:
        return None


def decode_gsm_ef_sst(sst_content: bytes):
    if _debug.DEBUG:
        print(format_debug_message(f"length of SSTContent ({hx.to_string(sst_content)}) = {len(sst_content)}"))

    for i, b in enumerate(sst_content):
        print(f"Byte: {i} ({hx.to_string(b)}), Service {1 + i * 4}: allocated: {'1' if hx.is_bit_set(b, 0) else '0'}, activated: {'1' if hx.is_bit_set(b, 1) else '0'}")
        print(f"Byte: {i} ({hx.to_string(b)}), Service {2 + i * 4}: allocated: {'1' if hx.is_bit_set(b, 2) else '0'}, activated: {'1' if hx.is_bit_set(b, 3) else '0'}")
        print(f"Byte: {i} ({hx.to_string(b)}), Service {3 + i * 4}: allocated: {'1' if hx.is_bit_set(b, 4) else '0'}, activated: {'1' if hx.is_bit_set(b, 5) else '0'}")
        print(f"Byte: {i} ({hx.to_string(b)}), Service {4 + i * 4}: allocated: {'1' if hx.is_bit_set(b, 6) else '0'}, activated: {'1' if hx.is_bit_set(b, 7) else '0'}")


def read_adn() -> None:
    if config.third_gen_apdu:
        print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)
    if _debug.DEBUG:
        print(format_debug_message("reading EF_ADN file"))

    try:
        file = FileManagement.select_path("3f007f106f3a")
    except FileNotFoundOnCard:
        file = None

    if file is None:
        return None

    nr_of_records = file.get_number_of_records()
    record_length = file.get_record_length()
    alpha_length = record_length - 14

    if _debug.DEBUG:
        print(format_debug_message(f"Record length: {record_length}, Alpha ID length: {alpha_length}"))

    for i in range(1, nr_of_records + 1):
        content = file.get_record(i)
        if content is None:
            continue
        empty = all(b == 0xFF for b in content[:record_length])
        if not empty:
            print(f"Record {i}: {hx.to_string(content)}")

    return None


def read_raw_imsi() -> bytes | None:
    if _debug.DEBUG:
        print(format_debug_message("reading EF_IMSI file"))

    try:
        file = FileManagement.select_path("3f007f206f07")
    except FileNotFoundOnCard:
        file = None

    if file is None and config.third_gen_apdu:
        try:
            usim_aid = get_usim_aid()
            if usim_aid is None:
                raise RuntimeError("There is no USIM available.")

            FileManagement.select_aid(hx.from_string(usim_aid))
            file = FileManagement.select_path("6f07")
        except FileNotFoundOnCard:
            file = None

    if file is None:
        return None

    content = file.get_content()
    if content is None:
        return None

    length = content[0]
    if len(content) - 1 != length:
        print(format_debug_message("readIMSI: Length of data is somehow messaged up compared to length defined as 1st byte of EF_IMSI"), file=sys.stderr)
        return None

    return content


def swap_imsi(content: bytes) -> str:
    swapped = bytearray(len(content) - 1)
    for i in range(len(content) - 1):
        swapped[i] = hx.swap(content[i + 1])
        if i == 0:
            swapped[i] = swapped[i] | 0xF0

    return hx.strip_chars(hx.to_string(bytes(swapped)))


def read_iccid() -> str | None:
    if _debug.DEBUG:
        print(format_debug_message("reading EF_ICCID file"))

    try:
        file = FileManagement.select_path("2fe2" if config.third_gen_apdu else "3f002fe2")
    except FileNotFoundOnCard:
        file = None

    if file is None:
        return None

    content = file.get_content()
    swapped = bytes(hx.swap(b) for b in content)

    return hx.strip_chars(hx.to_string(swapped))


def read_manuarea() -> str | None:
    if _debug.DEBUG:
        print(format_debug_message("reading EF_MANUAREA file"))

    try:
        file = FileManagement.select_path("0002" if config.third_gen_apdu else "3f000002")
    except FileNotFoundOnCard:
        file = None

    if file is None:
        return None

    content = file.get_content()
    if content is None:
        return None
    return hx.to_string(content)


def read_dir() -> list[bytes]:
    records: list[bytes] = []

    if _debug.DEBUG:
        print(format_debug_message("reading EF_DIR file"))

    try:
        file = FileManagement.select_path("3f002f00")
    except FileNotFoundOnCard:
        return records

    if isinstance(file, SimCardLinearFixedFile):
        no_of_records = file.get_number_of_records()
        for i in range(1, no_of_records + 1):
            record_content = file.get_record(i)
            if record_content is not None:
                records.append(record_content)

    return records


def get_aids() -> list[str]:
    aids: list[str] = []
    for record_content in read_dir():
        aid_data = tlv_toolkit.get_tlv(record_content, 0x4F)
        if aid_data is not None:
            aid = aid_data[2:2 + aid_data[1]]
            aids.append(hx.to_string(aid))
    return aids


def get_usim_aid() -> str | None:
    for aid in get_aids():
        if aid.startswith("A0000000871002"):
            return aid
    return None
