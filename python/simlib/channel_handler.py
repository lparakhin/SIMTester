"""Port of de.srlabs.simlib.ChannelHandler.

Only PC/SC readers are supported (via `pyscard`) - the original Java
OsmocomBB/JNI card provider is niche vendor-specific native code and has not
been ported.
"""

from __future__ import annotations

import sys
import time

from . import debug as _debug
from . import hex_toolkit as hx
from .apdu import CommandAPDU, ResponseAPDU
from .logging_utils import format_debug_message


class ChannelHandler:
    _instance: "ChannelHandler | None" = None

    def __init__(self, reader_index: int = 0):
        from smartcard.System import readers as list_readers

        self._reader_index = reader_index
        self._connection = None

        available = list_readers()

        if not available:
            print(format_debug_message("No valid PC/SC reader was found, check the connection and pcscd daemon"), file=sys.stderr)
            sys.exit(1)

        print(f"Terminals connected: {len(available)}")
        for reader in available:
            print(reader)
        print()

        if len(available) < reader_index + 1:
            print(format_debug_message(f"No valid PC/SC reader under index {reader_index}, start from zero!"), file=sys.stderr)
            sys.exit(1)

        self._reader = available[reader_index]
        print(f"Using terminal: {self._reader}")

        self._connect_card()

    def _connect_card(self):
        from smartcard.Exception import CardConnectionException

        self._connection = self._reader.createConnection()
        try:
            self._connection.connect()
        except CardConnectionException as e:
            print(format_debug_message(f"Unable to connect the card, exiting.. ({e})"), file=sys.stderr)
            sys.exit(1)

        print(f"Card connected: {self._reader}")

    @classmethod
    def get_instance(cls, reader_index: int | None = None, terminal_factory_name: str | None = None) -> "ChannelHandler":
        if terminal_factory_name not in (None, "PCSC"):
            raise NotImplementedError("Only the PCSC terminal factory is supported by this port (OsmocomBB was not ported)")

        if reader_index is None:
            if cls._instance is None:
                raise RuntimeError("Illegal state! There's no initialized channel to the card! Report this bug")
            return cls._instance

        if cls._instance is None or reader_index != cls._instance._reader_index:
            cls._instance = ChannelHandler(reader_index)

        return cls._instance

    def get_default_channel(self):
        if self._connection is None:
            self._connect_card()
        return self._connection

    @classmethod
    def transmit_on_default_channel(cls, apdu: CommandAPDU, retry: bool = True) -> ResponseAPDU | None:
        instance = cls.get_instance()
        connection = instance.get_default_channel()

        if _debug.DEBUG:
            print("TRANSMIT: " + hx.to_string(apdu.get_bytes()))

        try:
            data, sw1, sw2 = connection.transmit(list(apdu.get_bytes()))
            response = ResponseAPDU(bytes(data) + bytes([sw1, sw2]))
        except Exception as e:  # pyscard raises various CardConnectionException subtypes
            print(format_debug_message(f"Transmit failed ({e}), trying to reset the card and retry.."), file=sys.stderr)
            time.sleep(1)  # give everything time to settle
            instance.reset()
            print(format_debug_message("You might loose context after card reset, only basic TERMINAL PROFILE is executed."), file=sys.stderr)

            from .auto_terminal_profile import AutoTerminalProfile
            AutoTerminalProfile.auto_terminal_profile()

            if retry:
                data, sw1, sw2 = connection.transmit(list(apdu.get_bytes()))
                response = ResponseAPDU(bytes(data) + bytes([sw1, sw2]))
            else:
                response = None

        if _debug.DEBUG:
            print("RESPONSE: " + (hx.to_string(response.get_bytes()) if response is not None else "null"))

        return response

    @classmethod
    def disconnect_card(cls):
        if cls._instance is not None and cls._instance._connection is not None:
            try:
                cls._instance._connection.disconnect()
            except Exception:
                pass
            cls._instance._connection = None

    def reset(self):
        if _debug.DEBUG:
            print(format_debug_message("Resetting the card.."))

        try:
            self._connection.disconnect()
        except Exception:
            pass

        self._connect_card()

    def get_reader_name(self) -> str:
        return str(self._reader)
