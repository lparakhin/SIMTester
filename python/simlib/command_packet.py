"""Port of de.srlabs.simlib.CommandPacket (TS 03.48 / TS 102.225 Command Packet)."""

from __future__ import annotations

from . import debug as _debug
from . import hex_toolkit as hx
from .logging_utils import format_debug_message


class CommandPacket:
    # Counter management (SPI1 bits 3-4)
    CNTR_NO_CNTR_AVAILABLE = 0x0
    CNTR_CNTR_AVAILABLE = 0x1
    CNTR_CNTR_HIGHER = 0x2
    CNTR_CNTR_ONE_HIGHER = 0x3

    # KIC
    KIC_ALGO_ERROR_UNKNOWN = -1
    KIC_ALGO_IMPLICIT = 0
    KIC_ALGO_DES_CBC = 1
    KIC_ALGO_3DES_CBC_2KEYS = 2
    KIC_ALGO_3DES_CBC_3KEYS = 3
    KIC_ALGO_DES_ECB = 4

    # KID
    KID_ALGO_ERROR_UNKNOWN = -1
    KID_ALGO_IMPLICIT = 0
    KID_ALGO_DES_CBC = 1
    KID_ALGO_3DES_CBC_2KEYS = 2
    KID_ALGO_3DES_CBC_3KEYS = 3

    # PoR Security
    POR_SECURITY_NONE = 0x0
    POR_SECURITY_RC = 0x1
    POR_SECURITY_CC = 0x2
    POR_SECURITY_DS = 0x3

    # PoR mode
    POR_MODE_SMS_DELIVER_REPORT = 0x0
    POR_MODE_SMS_SUBMIT = 0x1

    def __init__(self):
        self._fake3des = False  # no public setter exists upstream either; always False
        self._bytes: bytes | None = None

        self._cph = bytes([0x02, 0x70, 0x00])  # Command Packet Header
        self._cpl = bytearray(2)
        self._chl = 0

        self._spi1 = 0
        self._fake_spi1: int | None = None
        self._spi2 = 0
        self._fake_spi2: int | None = None
        self._kic = 0
        self._fake_kic: int | None = None
        self._kid = 0
        self._fake_kid: int | None = None
        self._tar: bytes | None = None
        self._cntr: bytes | None = None
        self._pcntr = 0
        self._cc: bytes | None = None
        self._ud: bytes | None = None

        self._kic_implicit_algo = -1
        self._kid_implicit_algo = -1
        self._kic_key: bytes = b""
        self._kid_key: bytes = b""
        self._encrypted_cntr: bytes | None = None

        self._axalto_signature = False
        self._really_perform_encryption = False

    # -- basic getters ---------------------------------------------------

    def get_spi1(self) -> int:
        return self._spi1

    def get_spi2(self) -> int:
        return self._spi2

    def get_kic(self) -> int:
        return self._kic

    def get_kid(self) -> int:
        return self._kid

    def set_cph(self, cph: bytes):
        self._cph = cph

    # -- SPI1 settings -----------------------------------------------------

    def is_cryptographic_checksum_enabled(self) -> bool:
        return hx.is_bit_set(self._spi1, 1)

    def set_cryptographic_checksum(self, enabled: bool, kid_key: bytes = b""):
        if enabled:
            self._spi1 = (self._spi1 | 0x2) & 0xFF
            if len(kid_key) % 8 != 0:
                raise ValueError("Key length is not a multiple of a block size (8 bytes)!")
            self._kid_key = kid_key
        else:
            self._spi1 = (self._spi1 & 0xFD) & 0xFF
            self._kid_key = b""

    def is_ciphering_enabled(self) -> bool:
        return (self._spi1 & 0x4) == 0x4

    def set_ciphering(self, enabled: bool, kic_key: bytes = b"", really_perform_encryption: bool = False):
        self._really_perform_encryption = really_perform_encryption
        if enabled:
            self._spi1 = ((self._spi1 & 0xFB) | 0x4) & 0xFF
            if len(kic_key) % 8 != 0:
                raise ValueError("Key length is not a multiple of a block size (8 bytes)!")
            self._kic_key = kic_key
        else:
            self._spi1 = (self._spi1 & 0xFB) & 0xFF
            self._kic_key = b""

    def get_counter_management(self) -> int:
        return (self._spi1 & 0x18) >> 3

    def set_counter_management(self, counter_management: int):
        self._spi1 = (self._spi1 | ((counter_management << 3) & 0x18)) & 0xFF

    # kept for naming parity with the (mistyped, upstream) Java method name
    set_counter_manegement = set_counter_management

    # -- SPI2 settings -------------------------------------------------------

    def is_por_enabled(self) -> bool:
        return (self._spi2 & 0x3) == 0x1

    def set_por(self, enabled: bool):
        if enabled:
            self._spi2 = ((self._spi2 & 0xFC) | 0x1) & 0xFF
        else:
            self._spi2 = (self._spi2 & 0xFC) & 0xFF

    def get_por_security(self) -> int:
        return (self._spi2 & 0xC) >> 2

    def set_por_security(self, por_security: int):
        self._spi2 = (self._spi2 | ((por_security << 2) & 0xC)) & 0xFF

    def is_por_ciphering_enabled(self) -> bool:
        return (self._spi2 & 0x10) == 0x10

    def set_por_ciphering(self, enabled: bool):
        if enabled:
            self._spi2 = ((self._spi2 & 0xEF) | 0x10) & 0xFF
        else:
            self._spi2 = (self._spi2 & 0xEF) & 0xFF

    def get_por_mode(self) -> int:
        return (self._spi2 & 0x20) >> 5

    def set_por_mode(self, por_mode: int):
        self._spi2 = (self._spi2 | ((por_mode << 5) & 0x20)) & 0xFF

    # -- KIC/KID settings ------------------------------------------------

    def get_keyset(self) -> int:
        kic_keyset = (self._kic >> 4) & 0x0F
        kid_keyset = (self._kid >> 4) & 0x0F
        if kic_keyset != kid_keyset:
            raise RuntimeError(f"KIC and KID keysets are not the same, wtf? KIC = {hx.to_string(self._kic)}, KID = {hx.to_string(self._kid)}")
        return kic_keyset

    def get_kic_keyset(self) -> int:
        return (self._kic >> 4) & 0x0F

    def get_kid_keyset(self) -> int:
        return (self._kid >> 4) & 0x0F

    def set_keyset(self, keyset: int):
        self._kic = ((self._kic & 0x0F) | (keyset << 4)) & 0xFF
        self._kid = ((self._kid & 0x0F) | (keyset << 4)) & 0xFF

    def set_kic_keyset(self, keyset: int):
        self._kic = ((self._kic & 0x0F) | (keyset << 4)) & 0xFF

    def set_kid_keyset(self, keyset: int):
        self._kid = ((self._kid & 0x0F) | (keyset << 4)) & 0xFF

    def get_kic_algo(self) -> int:
        if (self._kic & 0x3) == 0x0:
            return self.KIC_ALGO_IMPLICIT
        if (self._kic & 0x3) == 0x1:
            return {
                0x0: self.KIC_ALGO_DES_CBC,
                0x4: self.KIC_ALGO_3DES_CBC_2KEYS,
                0x8: self.KIC_ALGO_3DES_CBC_3KEYS,
                0xC: self.KIC_ALGO_DES_ECB,
            }.get(self._kic & 0xC, self.KIC_ALGO_ERROR_UNKNOWN)
        return self.KIC_ALGO_ERROR_UNKNOWN

    def get_kic_algo_name(self) -> str:
        if (self._kic & 0x3) == 0x0:
            return "IMPLICIT"
        if (self._kic & 0x3) == 0x1:
            return {
                0x0: "1DES-CBC",
                0x4: "3DES-2keys",
                0x8: "3DES-3keys",
                0xC: "1DES-ECB",
            }.get(self._kic & 0xC, "N/A")
        return "N/A"

    def set_kic_algo(self, algo: int):
        if algo == self.KIC_ALGO_IMPLICIT:
            self._kic = self._kic & 0xF0
        elif algo == self.KIC_ALGO_DES_CBC:
            self._kic = (self._kic & 0xF0) | 0x1
        elif algo == self.KIC_ALGO_3DES_CBC_2KEYS:
            self._kic = (self._kic & 0xF0) | 0x5
        elif algo == self.KIC_ALGO_3DES_CBC_3KEYS:
            self._kic = (self._kic & 0xF0) | 0x9
        elif algo == self.KIC_ALGO_DES_ECB:
            self._kic = (self._kic & 0xF0) | 0xD
        self._kic &= 0xFF

    def get_kid_algo(self) -> int:
        if (self._kid & 0x3) == 0x0:
            return self.KID_ALGO_IMPLICIT
        if (self._kid & 0x3) == 0x1:
            return {
                0x0: self.KID_ALGO_DES_CBC,
                0x4: self.KID_ALGO_3DES_CBC_2KEYS,
                0x8: self.KID_ALGO_3DES_CBC_3KEYS,
            }.get(self._kid & 0xC, self.KID_ALGO_ERROR_UNKNOWN)
        return self.KID_ALGO_ERROR_UNKNOWN

    def get_kid_algo_name(self) -> str:
        if (self._kid & 0x3) == 0x0:
            return "IMPLICIT"
        if (self._kid & 0x3) == 0x1:
            return {
                0x0: "1DES-CBC",
                0x4: "3DES-2keys",
                0x8: "3DES-3keys",
            }.get(self._kid & 0xC, "N/A")
        return "N/A"

    def set_kid_algo(self, algo: int):
        if algo == self.KID_ALGO_IMPLICIT:
            self._kid = self._kid & 0xF0
        elif algo == self.KID_ALGO_DES_CBC:
            self._kid = (self._kid & 0xF0) | 0x1
        elif algo == self.KID_ALGO_3DES_CBC_2KEYS:
            self._kid = (self._kid & 0xF0) | 0x5
        elif algo == self.KID_ALGO_3DES_CBC_3KEYS:
            self._kid = (self._kid & 0xF0) | 0x9
        self._kid &= 0xFF

    def set_kid_implicit_algo(self, algo: int):
        if algo not in (self.KID_ALGO_DES_CBC, self.KID_ALGO_3DES_CBC_2KEYS, self.KID_ALGO_3DES_CBC_3KEYS):
            raise ValueError("invalid implicit KID algo")
        self._kid_implicit_algo = algo

    # -- TAR / counter / user data ---------------------------------------

    def get_tar(self) -> bytes | None:
        return self._tar

    def set_tar(self, tar: bytes):
        if len(tar) != 3:
            raise ValueError("TAR you have specified has incorrect size (not 3 bytes)!")
        self._tar = bytes(tar)

    def get_counter(self) -> int:
        if self.is_ciphering_enabled():
            return -1
        return hx.byte_array_to_long(self._cntr)

    def get_por_counter(self) -> int:
        if self.is_ciphering_enabled():
            return hx.byte_array_to_long(self._encrypted_cntr[:5])
        return self.get_counter()

    def set_counter(self, counter: int):
        self._cntr = counter.to_bytes(5, "big")

    def get_padding_counter(self) -> int:
        return self._pcntr

    def get_cryptographic_checksum(self) -> bytes | None:
        return self._cc

    def get_user_data(self) -> bytes | None:
        return self._ud

    def set_user_data(self, user_data: bytes):
        self._ud = bytes(user_data)

    # -- serialization -----------------------------------------------------

    def get_bytes(self) -> bytes:
        if self._bytes is not None:
            return self._bytes

        if not (0 <= self.get_kic_keyset() < 16 and 0 <= self.get_kid_keyset() < 16):
            raise RuntimeError("You must set keyset / algorithm before message formatting!")
        if self._tar is None:
            raise RuntimeError("You must set Target Application Identifier (TAR) before message formatting!")
        if self._cntr is None:
            raise RuntimeError("You must set Counter before message formatting!")
        if self._ud is None:
            raise RuntimeError("You must set User Data before message formatting!")

        return self._format_message()

    def is_axalto_signature_enabled(self) -> bool:
        return self._axalto_signature

    def set_axalto_signature(self, value: bool):
        self._axalto_signature = value

    def _format_message(self) -> bytes:
        chl = 13  # 2b SPI + 1b KIC + 1b KID + 3b TAR + 5b CNTR + 1b PCNTR

        if self.is_cryptographic_checksum_enabled():
            chl += 8

        if self.is_ciphering_enabled():
            self._cipher_set_pcntr()

        cpl = 1 + chl + len(self._ud) + (self._pcntr if self.is_ciphering_enabled() else 0)

        self._cpl[0] = (cpl >> 8) & 0xFF
        self._cpl[1] = cpl & 0xFF
        self._chl = chl & 0xFF

        spi1 = self._spi1 if self._fake_spi1 is None else self._fake_spi1
        spi2 = self._spi2 if self._fake_spi2 is None else self._fake_spi2
        kic = self._kic if self._fake_kic is None else ((self._kic & 0xF0) | self._fake_kic)
        kid = self._kid if self._fake_kid is None else ((self._kid & 0xF0) | self._fake_kid)

        header = bytes(self._cph) + bytes(self._cpl) + bytes([self._chl, spi1 & 0xFF, spi2 & 0xFF, kic & 0xFF, kid & 0xFF]) + self._tar + self._cntr + bytes([self._pcntr])

        cc = b""
        if self.is_cryptographic_checksum_enabled():
            self._cc = self._calc_cc()
            cc = self._cc

        body = header + cc + self._ud

        if self.is_ciphering_enabled():
            ciphered = self._cipher()
            if self._really_perform_encryption:
                # ciphertext replaces CNTR..end-of-user-data (same offset as CNTR)
                prefix_len = len(self._cph) + len(self._cpl) + 5 + len(self._tar)
                body = bytearray(body)
                body[prefix_len:prefix_len + len(ciphered)] = ciphered
                body = bytes(body)

        self._bytes = body
        return self._bytes

    def _cipher_set_pcntr(self):
        data_length = len(self._cntr) + 1 + (8 if self.is_cryptographic_checksum_enabled() else 0) + len(self._ud)
        self._pcntr = (8 - (data_length % 8)) % 8

    def _cipher(self) -> bytes:
        from Crypto.Cipher import DES, DES3

        data_length = len(self._cntr) + 1 + (8 if self.is_cryptographic_checksum_enabled() else 0) + len(self._ud)
        self._cipher_set_pcntr()

        to_be_ciphered = bytearray(data_length + self._pcntr)
        to_be_ciphered[0:len(self._cntr)] = self._cntr
        to_be_ciphered[len(self._cntr)] = self._pcntr
        if self.is_cryptographic_checksum_enabled():
            to_be_ciphered[len(self._cntr) + 1:len(self._cntr) + 1 + len(self._cc)] = self._cc
            to_be_ciphered[len(self._cntr) + 1 + len(self._cc):len(self._cntr) + 1 + len(self._cc) + len(self._ud)] = self._ud
        else:
            to_be_ciphered[len(self._cntr) + 1:len(self._cntr) + 1 + len(self._ud)] = self._ud

        kic_algo = self.get_kic_algo()

        if kic_algo == self.KIC_ALGO_IMPLICIT:
            if self._kic_implicit_algo == -1:
                raise ValueError("You need to set KIC implicit algo before using implicit value in KIC itself")
            kic_algo = self._kic_implicit_algo

        if kic_algo in (self.KIC_ALGO_DES_CBC, self.KIC_ALGO_IMPLICIT):
            if len(self._kic_key) != 8:
                raise ValueError("Key length for a single DES has to be 8 bytes!")
            cipher = DES.new(self._kic_key, DES.MODE_CBC, bytes(8))
        elif kic_algo == self.KIC_ALGO_DES_ECB:
            if len(self._kic_key) != 8:
                raise ValueError("Key length for a single DES has to be 8 bytes!")
            cipher = DES.new(self._kic_key, DES.MODE_ECB)
        elif kic_algo == self.KIC_ALGO_3DES_CBC_2KEYS:
            if len(self._kic_key) not in (16, 24):
                raise ValueError("Key length for a 3DES with 2 keys has to be either 16 or 24 bytes!")
            cipher = DES3.new(self._kic_key, DES3.MODE_CBC, bytes(8))
        elif kic_algo == self.KIC_ALGO_3DES_CBC_3KEYS:
            if len(self._kic_key) != 24:
                raise ValueError("Key length for a 3DES with 3 keys has to be 24 bytes!")
            cipher = DES3.new(self._kic_key, DES3.MODE_CBC, bytes(8))
        else:
            raise ValueError(f"Unknown algorithm for Cryptograpic checksum calculation, algo = {self.get_kid_algo()}")

        if _debug.DEBUG:
            print(format_debug_message(f"toBeCiphered: {hx.to_string(bytes(to_be_ciphered))}"))

        ciphered = cipher.encrypt(bytes(to_be_ciphered))
        self._encrypted_cntr = ciphered[:len(self._cntr)]

        return ciphered

    def _calc_cc(self) -> bytes:
        from Crypto.Cipher import DES, DES3

        chl = 13

        if self._axalto_signature and self.is_ciphering_enabled():
            self._cipher_set_pcntr()  # set PCNTR/padding for encryption first, because Axalto
            data_length = len(self._cpl) + 1 + chl + len(self._ud) + self._pcntr
        else:
            data_length = len(self._cpl) + 1 + chl + len(self._ud)

        pompadlen = (8 - (data_length % 8)) % 8
        to_be_signed = bytearray(data_length + pompadlen)

        to_be_signed[0:len(self._cpl)] = self._cpl
        to_be_signed[len(self._cpl)] = self._chl
        to_be_signed[len(self._cpl) + 1] = self._spi1
        to_be_signed[len(self._cpl) + 2] = self._spi2
        to_be_signed[len(self._cpl) + 3] = self._kic
        to_be_signed[len(self._cpl) + 4] = self._kid
        to_be_signed[len(self._cpl) + 5:len(self._cpl) + 5 + len(self._tar)] = self._tar
        to_be_signed[len(self._cpl) + 5 + len(self._tar):len(self._cpl) + 5 + len(self._tar) + len(self._cntr)] = self._cntr
        to_be_signed[len(self._cpl) + 5 + len(self._tar) + len(self._cntr)] = self._pcntr
        ud_offset = len(self._cpl) + 5 + len(self._tar) + len(self._cntr) + 1
        to_be_signed[ud_offset:ud_offset + len(self._ud)] = self._ud
        # padding stays zero, same as the Java implementation

        if _debug.DEBUG:
            print(format_debug_message(f"toBeSigned: {hx.to_string(bytes(to_be_signed))}"))

        kid_algo = self.get_kid_algo()

        if kid_algo == self.KID_ALGO_IMPLICIT:
            if self._kid_implicit_algo == -1:
                raise ValueError("You need to set KID implicit algo before using implicit value in KID itself")
            kid_algo = self._kid_implicit_algo

        if kid_algo in (self.KID_ALGO_DES_CBC, self.KID_ALGO_IMPLICIT):
            if len(self._kid_key) != 8:
                raise ValueError("Key length for a single DES has to be 8 bytes!")
            cipher = DES.new(self._kid_key, DES.MODE_CBC, bytes(8))
        elif kid_algo == self.KID_ALGO_3DES_CBC_2KEYS:
            if len(self._kid_key) not in (16, 24):
                raise ValueError("Key length for a 3DES with 2 keys has to be either 16 or 24 bytes!")
            cipher = DES3.new(self._kid_key, DES3.MODE_CBC, bytes(8))
        elif kid_algo == self.KID_ALGO_3DES_CBC_3KEYS:
            if self._fake3des:
                if len(self._kid_key) != 8:
                    raise ValueError("Key length for a single DES has to be 8 bytes!")
                cipher = DES.new(self._kid_key, DES.MODE_CBC, bytes(8))
            else:
                if len(self._kid_key) != 24:
                    raise ValueError("Key length for a 3DES with 3 keys has to be 24 bytes!")
                cipher = DES3.new(self._kid_key, DES3.MODE_CBC, bytes(8))
        else:
            raise ValueError(f"Unknown algorithm for Cryptograpic checksum calculation, algo = {self.get_kid_algo()}")

        signature = cipher.encrypt(bytes(to_be_signed))
        return signature[-8:]

    # -- parsing (response side helper - used when reading raw CP bytes back) --

    def parse(self, data: bytes):
        if data[0:3] != self._cph:
            raise ValueError("Command packet header not found in the data provided")

        self._bytes = data

        cp_length = len(data) - len(self._cph) - len(self._cpl)
        cpl_data_length = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF)

        if cp_length != cpl_data_length:
            raise ValueError(
                f"Command packet length (CPL) doesn't correspond with the actual data length; "
                f"real length = {cp_length}; CPL = {cpl_data_length}")

        self._cpl[0] = data[3]
        self._cpl[1] = data[4]
        self._chl = data[5]

        self._spi1 = data[6]
        self._spi2 = data[7]
        self._kic = data[8]
        self._kid = data[9]

        self._tar = data[10:13]
        self._encrypted_cntr = data[13:18]

        if not self.is_ciphering_enabled():
            self._cntr = data[13:18]
            self._pcntr = data[18]
            if self.is_cryptographic_checksum_enabled():
                self._cc = data[19:19 + 8]
                self._ud = data[27:]
            else:
                self._ud = data[19:]

    def set_fake_kic(self, kic: int):
        self._fake_kic = kic

    def set_fake_kid(self, kid: int):
        self._fake_kid = kid

    def set_fake_spi1(self, spi1: int):
        self._fake_spi1 = spi1

    def set_fake_spi2(self, spi2: int):
        self._fake_spi2 = spi2
