"""Port of de.srlabs.simlib.FileManagement."""

from __future__ import annotations

import sys

from . import config
from . import debug as _debug
from . import hex_toolkit as hx
from . import tlv_toolkit
from .apdu import CommandAPDU, ResponseAPDU
from .channel_handler import ChannelHandler
from .logging_utils import format_debug_message


class FileNotFoundOnCard(Exception):
    """Port of java.io.FileNotFoundException as (ab)used by the Java code."""


class FileManagement:

    @staticmethod
    def _get_sim_card_file_type(file_path_id: str, select_response):
        from .sim_card_file import (
            SimCardFile, SimCardElementaryFile, SimCardMasterFile, SimCardDirectoryFile,
            SimCardTransparentFile, SimCardLinearFixedFile, SimCardCyclicFile,
            SimCardBerTlvFile, SimCardNoInfoFile,
        )

        file_type = select_response.get_file_type()

        if file_type == SimCardFile.MF:
            selected = SimCardMasterFile(select_response)
            if _debug.DEBUG:
                print(format_debug_message(
                    f"selected MF {select_response.get_file_id()}, child DFs: {selected.get_number_of_child_dfs()}, "
                    f"child EFs: {selected.get_number_of_child_efs()}"))
            return selected

        if file_type in (SimCardFile.DF, SimCardFile.ADF):
            selected = SimCardDirectoryFile(select_response)
            if _debug.DEBUG:
                print(format_debug_message(
                    f"selected DF {select_response.get_file_id()}, child DFs: {selected.get_number_of_child_dfs()}, "
                    f"child EFs: {selected.get_number_of_child_efs()}"))
            return selected

        if file_type in (SimCardFile.EF, SimCardFile.INTERNAL_EF):
            ef_type = select_response.get_ef_type()
            if ef_type == SimCardElementaryFile.EF_TRANSPARENT:
                selected = SimCardTransparentFile(select_response)
                if _debug.DEBUG:
                    print(format_debug_message(f"selected EF Transparent {select_response.get_file_id()}, size: {selected.get_file_size()}"))
            elif ef_type == SimCardElementaryFile.EF_LINEAR_FIXED:
                selected = SimCardLinearFixedFile(select_response)
                if _debug.DEBUG:
                    print(format_debug_message(f"selected EF Linear-Fixed {select_response.get_file_id()}, size: {selected.get_file_size()}"))
            elif ef_type == SimCardElementaryFile.EF_CYCLIC:
                selected = SimCardCyclicFile(select_response)
                if _debug.DEBUG:
                    print(format_debug_message(f"selected EF Cyclic {select_response.get_file_id()}, size: {selected.get_file_size()}"))
            elif ef_type == SimCardElementaryFile.EF_NO_INFO:
                selected = SimCardNoInfoFile(select_response)
                if _debug.DEBUG:
                    print(format_debug_message(f"selected EF NoInfo {select_response.get_file_id()}, size: {selected.get_file_size()}"))
            elif ef_type == SimCardElementaryFile.EF_BER_TLV:
                selected = SimCardBerTlvFile(select_response)
                if _debug.DEBUG:
                    print(format_debug_message(f"selected EF NoInfo {select_response.get_file_id()}, size: {selected.get_file_size()}"))
            else:
                raise RuntimeError(f"Unknown EF type while selecting {file_path_id}")
            return selected

        raise RuntimeError(f"Unknown file type while selecting {file_path_id}; File type value: {file_type}")

    @staticmethod
    def select_path(file_path: str):
        from .select_response import SelectResponse3G

        if len(file_path) % 4 != 0:
            raise ValueError("filePath entered doesn't seem like a valid path (length is weird)")

        file_path_bytes = hx.from_string(file_path)
        selected_file = None

        for i in range(0, len(file_path_bytes), 2):
            file_id = file_path_bytes[i:i + 2]

            r = FileManagement.select_file_by_id(file_id)

            if config.third_gen_apdu:
                if r.get_sw() == 0x9000:
                    select_response = SelectResponse3G(r.get_data())
                elif r.get_sw() == 0x6A82:
                    raise FileNotFoundOnCard(f"file ID: {hx.to_string(file_id)}; doesn't seem to exist on this card; SW = {r.get_sw():X}")
                else:
                    raise RuntimeError(f"an unexpected error has occured during selection of file ID: {hx.to_string(file_id)}; SW = {r.get_sw():X}")
            else:
                if r.get_sw1() == 0x9F:
                    select_response = FileManagement._get_response_2g(file_id, r.get_sw2())
                elif r.get_sw() == 0x9404:
                    raise FileNotFoundOnCard(f"file ID: {hx.to_string(file_id)}; doesn't seem to exist on this card; SW = {r.get_sw():X}")
                elif r.get_sw() == 0x9000:
                    print(format_debug_message(f"w00t! fileId: {hx.to_string(file_id)} returned 0x9000 with no additional data"))
                    return None
                else:
                    raise RuntimeError(f"an unexpected error has occured during selection of file ID: {hx.to_string(file_id)}; SW = {r.get_sw():X}")

            selected_file = FileManagement._get_sim_card_file_type(hx.to_string(file_id), select_response)

        return selected_file

    @staticmethod
    def select_aid(aid: bytes) -> bytes | None:
        if _debug.DEBUG:
            print(format_debug_message(f"selecting AID: {hx.to_string(aid)}"))

        select = CommandAPDU(0x00, 0xA4, 0x04, 0x04, aid)
        r = ChannelHandler.transmit_on_default_channel(select)

        if r.get_sw() != 0x9000:
            print("Application cannot be selected")
            raise FileNotFoundOnCard(f"AID: {hx.to_string(aid)}; doesn't seem to exist on this card; SW = {r.get_sw():X}")

        fid_data = tlv_toolkit.get_tlv(r.get_data(), 0x83, 0x82)
        if fid_data is None:
            return None

        return bytes([fid_data[2], fid_data[3]])

    @staticmethod
    def select_file_by_path(file_path: str):
        """Select a file by path using 3G APDU (P1=08: select by path from MF)."""
        if not config.third_gen_apdu:
            return None

        select = CommandAPDU(0x00, 0xA4, 0x08, 0x04, hx.from_string(file_path))
        r = ChannelHandler.transmit_on_default_channel(select)

        from .select_response import SelectResponse3G

        if r.get_sw() == 0x9000:
            select_response = SelectResponse3G(r.get_data())
        elif r.get_sw() == 0x6A82:
            raise FileNotFoundOnCard(f"file ID: {file_path}; doesn't seem to exist on this card; SW = {r.get_sw():X}")
        else:
            raise RuntimeError(
                f"an unexpected error has occurred during selection of file ID: {file_path}; SW = {r.get_sw():X}; "
                f"APDU = {hx.to_string(select.get_bytes())}")

        return FileManagement._get_sim_card_file_type(file_path, select_response)

    @staticmethod
    def select_file_by_id(file_id: bytes) -> ResponseAPDU:
        if _debug.DEBUG:
            print(format_debug_message(f"selecting file: {hx.to_string(file_id)}"))

        if config.third_gen_apdu:
            select = CommandAPDU(0x00, 0xA4, 0x00, 0x04, file_id)
        else:
            select = CommandAPDU(0xA0, 0xA4, 0x00, 0x00, file_id)

        return ChannelHandler.transmit_on_default_channel(select)

    @staticmethod
    def _get_response_2g(file_id: bytes, count: int):
        from . import apdu_toolkit
        from .select_response import SelectResponse2G

        response = apdu_toolkit.get_response(count)

        if response.get_sw() == 0x9000:
            if _debug.DEBUG:
                print(format_debug_message(f"file {hx.to_string(file_id)} selected; "))
        else:
            print(format_debug_message(f"weird SW received: {response.get_sw1():x} {response.get_sw2():x}"), file=sys.stderr)
            print(format_debug_message("this may mean your reader is not responding well, reconnect it, restart pcscd, reload osmocom BB firmware, etc."), file=sys.stderr)
            print(format_debug_message("trying to parse Select command response anyway, this may get ugly.."))

        return SelectResponse2G(response.get_data(), hx.to_string(file_id))
