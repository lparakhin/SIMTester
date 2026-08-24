"""Port of de.srlabs.simlib.OTASMS."""

from __future__ import annotations

from . import config
from . import debug as _debug
from . import hex_toolkit as hx
from .address import Address
from .apdu import ResponseAPDU
from .channel_handler import ChannelHandler
from .envelope import EnvelopeSMSPPDownload
from .logging_utils import format_debug_message
from .sms_deliver_tpdu import SMSDeliverTPDU
from .sms_tpdu import SMSTPDU


class OTASMS:
    def __init__(self):
        self._smsdeliver = SMSDeliverTPDU()
        self._smsdeliver.set_tpudhi(True)

    def set_tpud(self, data: bytes):
        self._smsdeliver.set_tpud(data)

    def get_sms_deliver_tpdu(self) -> SMSDeliverTPDU:
        return self._smsdeliver

    def set_sms_deliver_tpdu(self, sms_deliver_tpdu: SMSDeliverTPDU):
        self._smsdeliver = sms_deliver_tpdu

    def set_command_packet(self, cp):
        if _debug.DEBUG:
            print(format_debug_message(f"Counter used in this SMS: {cp.get_counter()}"))
        self._smsdeliver.set_tpud(cp.get_bytes())

    def send(self) -> ResponseAPDU:
        sms_tpdu = SMSTPDU(self._smsdeliver.get_bytes())

        addr = Address(hx.from_string("86050021436587" if config.third_gen_apdu else "06050021436587"))

        env = EnvelopeSMSPPDownload(addr, sms_tpdu)
        envelope = env.get_apdu()

        if _debug.DEBUG:
            print(format_debug_message(f"CommandAPDU: {hx.to_string(envelope.get_bytes())}"))

        return ChannelHandler.transmit_on_default_channel(envelope)
