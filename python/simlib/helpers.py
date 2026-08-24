"""Port of de.srlabs.simlib.Helpers."""

from __future__ import annotations

from . import config
from . import debug as _debug
from . import hex_toolkit as hx
from .apdu import ResponseAPDU
from .logging_utils import format_debug_message


def handle_sim_response(response: ResponseAPDU, print_summary: bool = True) -> ResponseAPDU:
    from . import apdu_toolkit
    from .auto_terminal_profile import AutoTerminalProfile
    from .proactive_command import ProactiveCommand

    if _debug.DEBUG:
        print(format_debug_message(f"Handling SIM response: {hx.to_string(response.get_bytes())}"))

    sw1 = response.get_sw1()

    if sw1 in (0x9E, 0x9F) or (config.third_gen_apdu and sw1 in (0x62, 0x61)):
        return apdu_toolkit.get_response(response.get_sw2())

    if sw1 == 0x91:
        fetch_response = apdu_toolkit.perform_fetch(response.get_sw2())
        fetched_data = fetch_response.get_data()

        if fetched_data and fetched_data[0] == 0xD0:  # proactive command
            try:
                pc = ProactiveCommand(fetched_data)
            except ValueError:
                print("\033[95m" + "WARNING! Unable to parse ProactiveCommand, data = " + hx.to_string(fetched_data) + "\033[0m")
                return fetch_response

            if print_summary:
                summary = pc.get_summary()
                if summary:
                    print("\033[90m" + "Proactive command (" + "\033[95m" + pc.get_type() + "\033[90m" + ") identified, details: " + "\033[95m" + summary + "\033[90m" + "; trying to handle it.." + "\033[0m")
                else:
                    print("\033[90m" + "Proactive command (" + "\033[95m" + pc.get_type() + "\033[90m" + ") identified, trying to handle it.." + "\033[0m")

            proactive_response = AutoTerminalProfile.handle_proactive_command(fetch_response)

            if proactive_response.get_sw() != 0x9000:
                print("\033[95m" + "WARNING! Response (SW) to terminal response apdu is not 0x9000: " + hx.to_string(proactive_response.get_bytes()) + "\033[0m")

        return fetch_response

    return response


def sort_by_values_desc(mapping: dict) -> dict:
    return dict(sorted(mapping.items(), key=lambda kv: kv[1], reverse=True))


def version_compare(str1: str, str2: str) -> int:
    """Non-lexicographical comparison of dotted version strings, e.g. "1.10" > "1.6"."""
    vals1 = str1.split(".")
    vals2 = str2.split(".")

    i = 0
    while i < len(vals1) and i < len(vals2) and vals1[i] == vals2[i]:
        i += 1

    if i < len(vals1) and i < len(vals2):
        diff = int(vals1[i]) - int(vals2[i])
        return (diff > 0) - (diff < 0)

    diff = len(vals1) - len(vals2)
    return (diff > 0) - (diff < 0)
