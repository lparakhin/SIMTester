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
