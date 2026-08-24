# Python port and source audit

This repository contains a clean-room Python implementation in the single
standalone `simtester.py` script. Its classes still keep protocol encoding
separate from card I/O, while one file and one menu make the complete tool easy
to copy, run, and test without a physical SIM.

## Useful approaches found in the Java source

* `CommandPacket` models the TS 03.48 fields explicitly and varies SPI, KIC,
  KID, keyset, counter policy, PoR mode, and TAR independently. The Python
  `CommandPacket` retains this approach and validates every bounded field.
* `ResponsePacket` recognizes standard `027100` and proprietary `027F00`
  responses, can locate a packet embedded in other bytes, honors declared
  lengths, and distinguishes checksum, padding, and additional response data.
* `FuzzerFactory` uses a small, intentional matrix rather than random bytes.
  Its 17 mechanisms cover counter policy and implicit/DES/2-key and 3-key 3DES
  identifiers, with plain and ciphered PoR variants. This remains a useful plan
  for authorized testing; the Python packet object exposes all these controls.
* `TARScanner` supports exhaustive, ranged, resumable, and baseline-response
  scans. Python exposes lazy TAR range and packet generators so callers can add
  persistence and response classification without allocating millions of items.
* `APDUScanner` first scans CLA and optionally scans all INS values only at
  level 2. It filters the standard unsupported-class/instruction status words.
  `scan_apdus` preserves that strategy and permits a custom finding predicate.
* `FileScanner` traverses the MF/DF/ADF hierarchy, skips reserved identifiers,
  optionally restricts candidates by standard file-ID ranges, and uses reported
  child counts as an early exit. This is valuable but remains transport/card-
  state-specific and is not yet in the Python port.
* The Java transport centralizes APDU transmission and card reconnect behavior.
  Python replaces global state with a `CardTransport` protocol, a deterministic
  mock, and an optional PC/SC implementation.

## Implemented Python functionality

* Strict TS 03.48 command construction and parsing for the non-cryptographic,
  fuzzer-compatible packet form.
* Strict/lenient response parsing, including embedded and proprietary packets.
* Lazy TAR range generation, OTA packet generation, APDU level 1/2 scanning.
* PC/SC hardware access through optional `pyscard`, plus a dependency-free mock.
* A single interactive menu for building/parsing packets, previewing TAR scans,
  listing readers, and starting APDU level 1 or level 2 scans.
* Live scan logging prints every transmitted APDU and every response data/status
  word to the screen, including progress, filtered results, and findings.
* Transient PC/SC errors are logged and retried after reconnecting. A repeatedly
  failing APDU is skipped, while persistent reader/card failure stops the scan
  cleanly after ten consecutive errors instead of displaying a traceback.
* Every card status word is decoded against ISO/IEC 7816-4, ETSI TS 102 221 and
  TS 102 223, 3GPP TS 31.101 and TS 31.111, with legacy TS 11.11 SIM meanings.
  These are the card conventions referenced by GSMA UICC/eSIM profiles; unknown
  values are explicitly marked application/profile-specific rather than guessed.
* Completed or aborted scans print totals, communication errors, status-word and
  category counts, and a decoded table of every potentially supported CLA/INS.
* `61xx` responses automatically trigger an ISO/IEC 7816-4 GET RESPONSE using
  SW2 as Le; chained response data is collected and shown in the finding.
* The single script includes the original 135-entry SIMTester probe corpus:
  RAM, 20 WIB TARs, two S@T TARs, and 112 common RFM/vendor/proprietary applet
  candidates. TAR scanning in menu option 2 and `scan-known-tars` deliver them to the selected
  UICC as SMS-PP DOWNLOAD envelopes; `known-tars` only previews packet bytes.
* Non-interactive subcommands for automation and dependency-free self-tests.

## Simplified interactive menu

Running `python simtester.py` now shows only the four primary test workflows:

1. Standard fuzzing with the original 17 mechanisms and configurable TAR/keysets.
2. TAR scanning using either the known corpus or a hexadecimal range.
3. APDU scanning at level 1 or level 2.
4. OTA fuzzing of PID, DCS, and UDHI values (common values or brute force).

Lower-level packet and automation commands remain available as CLI subcommands.
Reader discovery and card connection failures are reported as short actionable
errors (for example, asking the user to insert the card) rather than tracebacks.
Before every interactive workflow, the tool lists all discovered PC/SC readers
by name and validates the selected reader index.
After every scan, a best-effort SIM card summary reads and decodes ATR, ICCID,
IMSI, MSISDN, and service-provider name. Both UICC (`00`) and classic SIM (`A0`)
APDU classes are attempted; protected or absent fields are shown as unavailable.

There is nothing to install and no second Python source file. Examples:

```console
python simtester.py build-ota B00010 --keyset 1 --data A0A40000023F00
python simtester.py parse-response 027100000B0AB0001000000000010000
python simtester.py scan-apdu --reader 0
python simtester.py self-test
python simtester.py known-tars --groups SAT,WIB --keyset 1
python simtester.py scan-known-tars --reader 0 --groups SAT,WIB --keyset 1
```

Run `python simtester.py` without arguments to open the menu. All Python code,
including its dependency-free self-tests, is contained in that one script.
The script intentionally contains ASCII source text only, so it also runs when
copied through Windows editors that do not preserve UTF-8 encoding.

## Scope and safety

This is an independent implementation, not a line-for-line translation. It
does not silently pretend to encrypt or sign packets: real cryptographic OTA
operations require legitimate operator keys and are intentionally outside the
initial port. PIN mutation, GSM authentication collection, OTA SMS envelope
delivery, file-system traversal, proactive command handling, and network upload
also remain future work. Only test cards and systems you own or are authorized
to assess.
