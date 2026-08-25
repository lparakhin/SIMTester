"""Mutable library-wide globals (port of static fields on de.srlabs.simlib.SIMLibrary).

Kept in a dedicated module (instead of simlib/__init__.py) so that other
modules can `from . import config` and read `config.third_gen_apdu` fresh on
every access - matching the semantics of a mutable Java static field.
"""

VERSION = "SIMLibrary (Python port) v1.0.0"

# Global switch between 2G (CLA=0xA0) and 3G (CLA=0x00) APDU framing used
# throughout the whole library. Auto-detected/overridden by the CLI.
third_gen_apdu = True
