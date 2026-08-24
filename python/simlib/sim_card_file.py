"""Port of the de.srlabs.simlib.SimCardFile hierarchy."""

from __future__ import annotations

import sys

from . import config
from .logging_utils import format_debug_message
from .channel_handler import ChannelHandler
from .apdu import CommandAPDU


class SimCardFile:
    RFU = 0x00
    MF = 0x01
    DF = 0x02
    EF = 0x04
    INTERNAL_EF = 0x08
    ADF = 0x09

    def __init__(self, select_response):
        self._file_name = "N/A"
        self._file_description = "N/A"
        self._file_path = None

        self._file_id = select_response.get_file_id()
        self._selectResponseData = select_response.get_response_data()
        self._fileSize = select_response.get_file_size()
        self._fileType = select_response.get_file_type()
        self._ef_type = None
        if self._fileType == SimCardFile.EF:
            self._ef_type = select_response.get_ef_type()

    def get_file_size(self) -> int:
        return self._fileSize

    def get_file_id(self) -> str:
        return self._file_id

    def get_file_type(self) -> int:
        return self._fileType

    def get_file_type_name(self) -> str:
        if self._fileType == SimCardFile.RFU:
            return "RFU"
        if self._fileType == SimCardFile.MF:
            return "MF"
        if self._fileType == SimCardFile.DF:
            return "DF"
        if self._fileType == SimCardFile.ADF:
            return "ADF"
        if self._fileType in (SimCardFile.EF, SimCardFile.INTERNAL_EF):
            if self._ef_type == SimCardElementaryFile.EF_TRANSPARENT:
                return "EF_TRANSPARENT"
            if self._ef_type == SimCardElementaryFile.EF_LINEAR_FIXED:
                return "EF_LINEAR"
            if self._ef_type == SimCardElementaryFile.EF_CYCLIC:
                return "EF_CYCLIC"
        return "N/A"

    def get_number_of_child_dfs(self) -> int:
        if self._fileType not in (SimCardFile.MF, SimCardFile.DF, SimCardFile.ADF):
            raise RuntimeError(f"Unable to get number of child DFs for {self._file_id} as it's not a DF, nor MF")

        if config.third_gen_apdu:
            print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)
            return 0
        return self._selectResponseData[14] & 0xFF

    def get_number_of_child_efs(self) -> int:
        if config.third_gen_apdu:
            print(format_debug_message("3G format not yet implemented!"), file=sys.stderr)

        if self._fileType not in (SimCardFile.MF, SimCardFile.DF, SimCardFile.ADF):
            raise RuntimeError(f"Unable to get number of child DFs for {self._file_id} as it's not a DF, nor MF")
        return self._selectResponseData[15] & 0xFF

    def get_raw_select_response_data(self) -> bytes:
        return self._selectResponseData

    def get_file_name(self) -> str:
        return self._file_name

    def _set_file_name(self, name: str):
        self._file_name = name

    def get_file_description(self) -> str:
        return self._file_description

    def _set_file_description(self, desc: str):
        self._file_description = desc

    def get_file_path(self) -> str:
        return self._file_path

    def set_file_path(self, path: str):
        self._file_path = path

    def set_file_name(self, name: str):
        self._file_name = name

    def set_file_description(self, desc: str):
        self._file_description = desc


class SimCardElementaryFile(SimCardFile):
    EF_TRANSPARENT = 0x00
    EF_LINEAR_FIXED = 0x01
    EF_CYCLIC = 0x03
    EF_NO_INFO = 0x04
    EF_BER_TLV = 0x05

    def __init__(self, select_response):
        super().__init__(select_response)
        if self.get_file_type() in (SimCardFile.EF, SimCardFile.INTERNAL_EF):
            self._file_structure = select_response.get_ef_type()
        else:
            raise TypeError("Selected file is not an EF, unable to get EF structure")

    def get_file_structure(self) -> int:
        return self._file_structure

    def get_file_structure_name(self) -> str:
        return {
            self.EF_TRANSPARENT: "Transparent",
            self.EF_LINEAR_FIXED: "Linear-fixed",
            self.EF_CYCLIC: "Cyclic",
        }.get(self._file_structure, "UNKNOWN")


class SimCardTransparentFile(SimCardElementaryFile):
    def get_content(self, offset: int = 0, length: int | None = None) -> bytes | None:
        if length is None:
            length = self._fileSize

        cla = 0x00 if config.third_gen_apdu else 0xA0
        read_binary = CommandAPDU(cla, 0xB0, 0x00, 0x00, length)
        response = ChannelHandler.transmit_on_default_channel(read_binary)

        sw = response.get_sw()
        if sw == 0x9000:
            return response.get_data()
        if sw in (0x9804, 0x6982):  # security status not satisfied (2G/3G)
            print(format_debug_message(
                f"security problem during reading content of a file {self._file_id} perhaps you need to "
                "enter PIN or auth via ADM to read this file, check ARR"), file=sys.stderr)
            return None
        raise RuntimeError(f"an unexpected error has occured during reading content of a file {self._file_id}; SW = {sw:02X}")


class SimCardLinearFixedFile(SimCardElementaryFile):
    def __init__(self, select_response):
        super().__init__(select_response)
        self._record_length = None
        self._number_of_records = None

        if self.get_file_structure() == self.EF_LINEAR_FIXED:
            if config.third_gen_apdu:
                from . import tlv_toolkit

                file_desc = tlv_toolkit.get_tlv(select_response.get_response_data(), 0x82)
                if file_desc[1] != 0x05:
                    raise RuntimeError(f"FCM template does not contain record information, wth? FCM: {file_desc.hex().upper()}")
                self._record_length = ((file_desc[4] << 8) & 0xFF00) | file_desc[5]
                self._number_of_records = file_desc[6]
            else:
                self._record_length = select_response.get_response_data()[14]
                self._number_of_records = self._fileSize // self._record_length

    def get_record_length(self) -> int:
        if self.get_file_type() == SimCardFile.EF and self.get_file_structure() == self.EF_LINEAR_FIXED:
            return self._record_length
        raise TypeError("Selected file is not an EF or an EF is not a Linear-Fixed structed")

    def get_first_record(self) -> bytes | None:
        return self.get_record(1)

    def get_record(self, record_nr: int) -> bytes | None:
        cla = 0x00 if config.third_gen_apdu else 0xA0
        read_record = CommandAPDU(cla, 0xB2, record_nr, 0x04, self._record_length)
        response = ChannelHandler.transmit_on_default_channel(read_record)

        sw = response.get_sw()
        if sw == 0x9000:
            return response.get_data()
        if sw in (0x9402, 0x6A83):  # out of file / record not found
            print(format_debug_message(
                f"problem during reading content of a file {self._file_id}, recordNr = {record_nr}, "
                f"recordLength = {self._record_length}; outOfFile - Record NOT found!"), file=sys.stderr)
            return None
        if sw in (0x9804, 0x6982):  # security status not satisfied
            print(format_debug_message(
                f"security problem during reading content of a file {self._file_id} perhaps you need to "
                "enter PIN or auth via ADM to read this file, check ARR"), file=sys.stderr)
            return None
        raise RuntimeError(f"an unexpected error has occured during reading content of a file {self._file_id}; SW = {sw:04x}")

    def get_number_of_records(self) -> int:
        return self._number_of_records


class SimCardCyclicFile(SimCardElementaryFile):
    def __init__(self, select_response):
        super().__init__(select_response)
        print(format_debug_message(f"not yet implemented, a blank class, FileID: {select_response.get_file_id()}"), file=sys.stderr)


class SimCardBerTlvFile(SimCardElementaryFile):
    def __init__(self, select_response):
        super().__init__(select_response)
        print(format_debug_message(f"not yet implemented, a blank class, FileID: {select_response.get_file_id()}"), file=sys.stderr)


class SimCardNoInfoFile(SimCardElementaryFile):
    def __init__(self, select_response):
        super().__init__(select_response)
        print(format_debug_message(f"not yet implemented, a blank class, FileID: {select_response.get_file_id()}"), file=sys.stderr)


class SimCardMasterFile(SimCardFile):
    pass


class SimCardDirectoryFile(SimCardFile):
    pass
