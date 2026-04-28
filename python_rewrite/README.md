# Python Rewrite (Single-file tools + startup menu)

All SIMTester tools are combined in:

- `python_rewrite/simtester_tools.py`

## Startup menu before scan

Run without subcommands to open the interactive menu:

```bash
python3 -m python_rewrite.simtester_tools
```

Or explicitly:

```bash
python3 -m python_rewrite.simtester_tools --menu
```

Menu includes:
- action selection (`apdu`, `tar`, `ota`, `file`, `fuzz`)
- SIM reader selection (single or multi-reader)
- scan options and parameters (level, mode, keyset, TAR start, regex, bruteforce, lazy scan, DF start, fuzz lists)

## Direct CLI examples

```bash
python3 -m python_rewrite.simtester_tools --readers reader0,reader1 apdu --level2
python3 -m python_rewrite.simtester_tools --readers reader0,reader1 tar --mode scanRangesOfTARs --keyset 1 --start 000000
python3 -m python_rewrite.simtester_tools --readers reader0,reader1 ota --keyset 1 --tar RAM:000000 --fuzzer 1
python3 -m python_rewrite.simtester_tools --readers reader0 file --start-df 3F00 --lazy
```

`python_rewrite/de/srlabs/simtester/SIMTester.py` remains a compatibility shim forwarding to this module.


Reader detection uses full system reader names (via pyscard/PCSC when available).
You can list them with:

```bash
python3 -m python_rewrite.simtester_tools --list-readers
```
