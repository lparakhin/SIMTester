"""Port of de.srlabs.simlib.Envelope / EnvelopeSMSPPDownload."""

from __future__ import annotations

from . import config
from .address import Address
from .apdu import CommandAPDU
from .device_identities import DeviceIdentities
from .inner_tlv import get_inner_tlv
from .sms_tpdu import SMSTPDU


class Envelope:
    def __init__(self, data: bytes | None = None):
        self._data = data

    def get_apdu(self) -> CommandAPDU:
        if self._data is None:
            raise RuntimeError("Envelope: data variable has not been set!")

        cla = 0x80 if config.third_gen_apdu else 0xA0
        return CommandAPDU(cla, 0xC2, 0x00, 0x00, self._data)


class EnvelopeSMSPPDownload(Envelope):
    """As defined in TS 51.014, Section 7.1.2."""

    def __init__(self, address: Address, sms_tpdu: SMSTPDU):
        super().__init__()

        if config.third_gen_apdu:
            device_identities = DeviceIdentities(DeviceIdentities.DI_NETWORK, DeviceIdentities.DI_UICC, DeviceIdentities.TYPE_3G)
        else:
            device_identities = DeviceIdentities(DeviceIdentities.DI_NETWORK, DeviceIdentities.DI_UICC, DeviceIdentities.TYPE_GSM)

        smspp_data = device_identities.get_bytes() + address.get_bytes() + sms_tpdu.get_bytes()
        self._data = get_inner_tlv(0xD1, smspp_data)
