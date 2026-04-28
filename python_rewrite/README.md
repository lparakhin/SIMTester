# Python Rewrite (Single-file tools + startup menu)

All SIMTester tools are combined in:

- `python_rewrite/simtester_tools.py`

## Real reader mode (default)

The tool now attempts **real PC/SC SIM reader scanning** by default via `pyscard` (`smartcard.System.readers`).
If real reader initialization fails, the command fails unless you explicitly allow fallback:

```bash
python3 -m python_rewrite.simtester_tools --allow-dummy apdu --readers "Reader Name"
```

## Startup menu before scan

```bash
python3 -m python_rewrite.simtester_tools
# or
python3 -m python_rewrite.simtester_tools --menu
```

Menu includes:
- action selection (`apdu`, `tar`, `ota`, `file`, `fuzz`)
- SIM reader selection (single or multi-reader, full detected names)
- scan options and parameters
- choice to allow/disallow dummy fallback

## Human-readable APDU decoding

During scans, APDU responses are printed on-screen and decoded into human-readable descriptions including:
- SW1/SW2 interpretation aligned with ISO/3GPP SIM/USIM status handling (e.g., `9000`, `61xx`, `98xx`, `6A82`, etc.)
- basic TLV/FCP interpretation for common response templates

## Reader listing

```bash
python3 -m python_rewrite.simtester_tools --list-readers
```


If a reader is present but no card is inserted, the tool now reports a clear per-reader error and continues with other readers.


## TAR scanner well-known option

The TAR menu now includes `scanWellKnownTARs` that uses a curated, cross-vendor TAR catalog (Gemalto/Thales, G+D, IDEMIA/OT, WIB/S@T, generic OTA/RFM).


## APDU GET RESPONSE support

For APDU statuses that indicate continuation data (`61xx` / `9Fxx`), the scanner now automatically issues `GET RESPONSE` (`CLA C0 00 00 Le`) and decodes both responses in human-readable form.


TAR scan output now includes human family labels (e.g., WIB family detected, S@T family detected, vendor profile hints).


For TAR scans you can test multiple well-known keysets in one run using `--keysets`, for example:

```bash
python3 -m python_rewrite.simtester_tools --allow-dummy tar --mode scanWellKnownTARs --keysets 1,3,5
```


TAR positive responses now trigger GET RESPONSE follow-up (`61xx`/`9Fxx`) and decoded analysis of returned bytes using 3GPP-oriented TLV interpretation.
