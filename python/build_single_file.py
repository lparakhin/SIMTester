#!/usr/bin/env python3
"""Combine the simlib/ + simtester/ packages into one standalone script.

Reads every module under simlib/ and simtester/, base64-embeds each one's
source verbatim, and emits simtester_standalone.py: a single self-contained
file that installs an in-memory import hook (sys.meta_path) recreating the
two packages at runtime, then runs the exact same simtester.simtester.main().

Because the modules are embedded byte-for-byte and loaded through the real
Python import machinery (not a hand-flattened/renamed merge), the combined
script behaves identically to running `python -m simtester` against the
multi-file source - it is just packaged as one file for easy distribution.

Usage: python3 build_single_file.py   (run from the python/ directory)
Regenerate this file whenever simlib/ or simtester/ change.
"""

from __future__ import annotations

import base64
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
OUTPUT = ROOT / "simtester_standalone.py"

# Module load order matters only in the sense that Python's normal import
# resolution needs it - since we register a real meta path finder/loader,
# dependencies are resolved on demand just like a normal package, so any
# order here is fine. Kept in a readable, roughly-dependency-ordered list.
MODULES = [
    "simlib/__init__.py",
    "simlib/debug.py",
    "simlib/logging_utils.py",
    "simlib/hex_toolkit.py",
    "simlib/tlv_toolkit.py",
    "simlib/inner_tlv.py",
    "simlib/encoding_toolkit.py",
    "simlib/config.py",
    "simlib/device_identities.py",
    "simlib/address.py",
    "simlib/apdu.py",
    "simlib/channel_handler.py",
    "simlib/apdu_toolkit.py",
    "simlib/helpers.py",
    "simlib/select_response.py",
    "simlib/sim_card_file.py",
    "simlib/file_management.py",
    "simlib/file_mapping.py",
    "simlib/common_file_reader.py",
    "simlib/auth.py",
    "simlib/sms_tpdu.py",
    "simlib/sms_deliver_tpdu.py",
    "simlib/envelope.py",
    "simlib/ota_sms.py",
    "simlib/command_packet.py",
    "simlib/response_packet.py",
    "simlib/proactive_command.py",
    "simlib/auto_terminal_profile.py",
    "simtester/__init__.py",
    "simtester/entry_point.py",
    "simtester/csv_writer.py",
    "simtester/fuzzer_data.py",
    "simtester/fuzzer_result.py",
    "simtester/fuzzer_factory.py",
    "simtester/apdu_scanner.py",
    "simtester/file_scanner.py",
    "simtester/gsmmap_uploader.py",
    "simtester/fuzzer.py",
    "simtester/ota_fuzzer.py",
    "simtester/tar_scanner.py",
    "simtester/simtester.py",
    "simtester/__main__.py",
]


def _module_name(relpath: str) -> str:
    dotted = relpath[:-3].replace("/", ".")  # strip ".py"
    return dotted[:-len(".__init__")] if dotted.endswith(".__init__") else dotted


def main():
    entries = []
    for relpath in MODULES:
        source = (ROOT / relpath).read_text()
        name = _module_name(relpath)
        is_pkg = relpath.endswith("__init__.py")
        encoded = base64.b64encode(source.encode()).decode()
        entries.append((name, is_pkg, encoded))

    lines = []
    lines.append('#!/usr/bin/env python3')
    lines.append('"""')
    lines.append("SIMTester - single-file Python port of SRLabs' SIMTester + SIMLibrary.")
    lines.append("")
    lines.append("Auto-generated (by build_single_file.py) from python/simlib/ and")
    lines.append("python/simtester/ - edit those, then regenerate this file; don't hand-edit it.")
    lines.append("")
    lines.append("Usage:")
    lines.append("    python3 simtester_standalone.py --help")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("import base64")
    lines.append("import importlib.abc")
    lines.append("import importlib.util")
    lines.append("import sys")
    lines.append("")
    lines.append("# name -> (is_package, base64-encoded source)")
    lines.append("_MODULES: dict[str, tuple[bool, str]] = {")
    for name, is_pkg, encoded in entries:
        lines.append(f"    {name!r}: ({is_pkg!r}, {encoded!r}),")
    lines.append("}")
    lines.append("")
    lines.append('''
class _InMemoryLoader(importlib.abc.Loader):
    def __init__(self, name: str, is_package: bool, encoded_source: str):
        self._name = name
        self._is_package = is_package
        self._source = base64.b64decode(encoded_source).decode()

    def create_module(self, spec):
        return None  # let importlib create the default module object

    def exec_module(self, module):
        if self._is_package:
            module.__path__ = []  # marks it as a package for submodule imports
        exec(compile(self._source, f"<simtester-standalone:{self._name}>", "exec"), module.__dict__)


class _InMemoryFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname not in _MODULES:
            return None
        is_package, encoded_source = _MODULES[fullname]
        loader = _InMemoryLoader(fullname, is_package, encoded_source)
        return importlib.util.spec_from_loader(fullname, loader, is_package=is_package)


sys.meta_path.insert(0, _InMemoryFinder())

from simtester.simtester import main  # noqa: E402

if __name__ == "__main__":
    main()
'''.strip("\n"))
    lines.append("")

    OUTPUT.write_text("\n".join(lines))
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes) from {len(entries)} modules.")


if __name__ == "__main__":
    main()
