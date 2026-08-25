"""Port of de.srlabs.simlib.SelectResponse / SelectResponse2G / SelectResponse3G."""

from __future__ import annotations

import sys

from . import debug as _debug
from . import hex_toolkit as hx
from . import tlv_toolkit
from .logging_utils import format_debug_message


class SelectResponse2G:
    def __init__(self, response_data: bytes, file_id: str):
        self._file_id = hx.to_string(bytes([response_data[4], response_data[5]]))
        if file_id != self._file_id:
            print("If this happened during file scanning (-sf), try to add the fileId "
                  f"{file_id} as a reserved fileId using -sfrv option.", file=sys.stderr)
            raise ValueError(
                f"Response Data ({hx.to_string(response_data)}) you've provided doesn't seem to "
                f"correspond to the fileId provided ({file_id}), fileId in data: {self._file_id}")

        self._response_data = response_data
        self._file_type = response_data[6]

        from .sim_card_file import SimCardFile

        if self._file_type in (SimCardFile.MF, SimCardFile.DF):
            self._file_size = -1
        else:
            self._file_size = ((response_data[2] & 0xFF) << 8) | (response_data[3] & 0xFF)

    def get_file_id(self) -> str:
        return self._file_id

    def get_response_data(self) -> bytes:
        return self._response_data

    def get_file_type(self) -> int:
        return self._file_type

    def get_ef_type(self) -> int:
        from .sim_card_file import SimCardFile

        if self.get_file_type() != SimCardFile.EF:
            raise IllegalStateError("File is not an EF!")
        return self._response_data[13]

    def get_file_size(self) -> int:
        return self._file_size


class IllegalStateError(RuntimeError):
    pass


class SelectResponse3G:
    def __init__(self, response_data: bytes):
        if _debug.DEBUG:
            print(format_debug_message(f"Parsing responseData: {hx.to_string(response_data)}"))

        if response_data[0] != 0x62:
            raise ValueError(
                "3G response has to start with 0x62 (FCP template tag). Your response starts with "
                f"{hx.to_string(response_data[0])}")

        from .sim_card_file import SimCardFile, SimCardElementaryFile

        self._response_data = response_data

        file_desc = tlv_toolkit.get_tlv(response_data, 0x82)
        if _debug.DEBUG:
            print(format_debug_message(f"File Descriptor data (0x82): {hx.to_string(file_desc)}"))

        # "DF name is mandatory for only ADF" -> if a df_name is present, this is an ADF
        df_name = tlv_toolkit.get_tlv(response_data, 0x84, 0x82)

        if df_name is not None:
            self._file_type = SimCardFile.ADF
        elif hx.is_bit_set(file_desc[2], 7):
            self._file_type = SimCardFile.RFU
        elif (file_desc[2] & 0x38) == 0x38 and (file_desc[2] | 0x78) == 0x78:
            self._file_type = SimCardFile.DF
        elif (file_desc[2] | 0x47) == 0x47:
            self._file_type = SimCardFile.EF
        elif (file_desc[2] & 0x08) == 0x08:
            self._file_type = SimCardFile.INTERNAL_EF
        elif (file_desc[2] & 0x39) == 0x39 and (file_desc[2] | 0x79) == 0x79:
            self._file_type = SimCardFile.EF  # BER-TLV EF structure
        else:
            self._file_type = SimCardFile.RFU

        self._ef_type = None
        if self._file_type in (SimCardFile.EF, SimCardFile.INTERNAL_EF):
            structure = file_desc[2] & 0x07
            if structure == 0x00:
                self._ef_type = SimCardElementaryFile.EF_NO_INFO
            elif structure == 0x01:
                if (file_desc[2] & 0x39) == 0x39:
                    self._ef_type = SimCardElementaryFile.EF_BER_TLV
                else:
                    self._ef_type = SimCardElementaryFile.EF_TRANSPARENT
            elif structure == 0x02:
                self._ef_type = SimCardElementaryFile.EF_LINEAR_FIXED
            elif structure == 0x06:
                self._ef_type = SimCardElementaryFile.EF_CYCLIC
            else:
                raise RuntimeError(f"RFU EF structure found. File Descriptor data: {hx.to_string(response_data)}")

        file_id_data = tlv_toolkit.get_tlv(response_data, 0x83, 0x82)
        if _debug.DEBUG:
            print(format_debug_message(f"File Identifier data (0x83): {hx.to_string(file_id_data)}"))

        self._file_id = None
        if file_id_data is not None:
            self._file_id = bytes([file_id_data[2], file_id_data[3]])

        file_size_data = tlv_toolkit.get_tlv(response_data, 0x80, 0x82)
        if _debug.DEBUG:
            print(format_debug_message(f"File Size data (0x80): {hx.to_string(file_size_data)}"))

        if file_size_data is None:
            self._file_size = -1
        elif file_size_data[1] == 1:
            self._file_size = file_size_data[2] & 0xFF
        else:
            self._file_size = ((file_size_data[2] & 0xFF) << 8) | (file_size_data[3] & 0xFF)

    def get_file_id(self) -> str:
        return hx.to_string(self._file_id)

    def get_response_data(self) -> bytes:
        return self._response_data

    def get_file_type(self) -> int:
        return self._file_type

    def get_ef_type(self) -> int:
        from .sim_card_file import SimCardFile

        if self._file_type not in (SimCardFile.EF, SimCardFile.INTERNAL_EF):
            raise IllegalStateError("File is not an EF!")
        return self._ef_type

    def get_file_size(self) -> int:
        return self._file_size
