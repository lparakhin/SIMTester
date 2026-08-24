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

Standard fuzzing adds two explicitly labeled unprotected submit-mode PoR probes
to the original matrix. Quick known-TAR scans use the common RAM/WIB/S@T/RFM
values `000000`, `000001`, `505348`, `534054`, `B00001`, and `B00010` across
keysets 1 through 6 by default; full-corpus and custom keyset scans remain
available.
Standard fuzzing preserves each profile's SPI2 exactly; unlike conclusive TAR
scans, it does not force PoR onto the original no-PoR control. Before sending,
the tool validates ENVELOPE CLA/INS/P1/P2/Lc, the `D1` TLV hierarchy,
network-to-UICC identities, SMS-DELIVER PID/DCS/UDL, and secured-packet lengths.
Response correlation distinguishes repeated parser warnings and empty
submit-mode acknowledgements from parseable PoR evidence.
Known and ranged TAR scans now expand each TAR/keyset over the 16 original
response-capable profiles plus 20 explicit unsecured SPI1/MSL values:
`00, 01, 02, 04, 05, 06, 08, 09, 0A, 0C, 0D, 0E, 10, 11, 14, 15, 18, 19, 1C, 1D`.
The matrix covers counter, checksum, ciphering, and RFU-bit declarations, but
does not apply real ciphering and uses zero-filled checksum bytes. A TAR is confirmed only when a parseable
PoR returns the same TAR with an RSC other than `09`; matching RSC `09` is shown
as `NOT FOUND ON TESTED ROUTE`, and transport-only status words remain `UNDETERMINED`.
The menu and `scan-known-tars --single-profile` retain a fast basic-profile mode.
PoR SPI2 is validated independently of command MSL: bits 1-0 select no PoR,
always PoR, or error-only PoR; bits 3-2 select no security/RC/CC/DS; bit 4
selects PoR ciphering; and bit 5 selects SMS-DELIVER-REPORT or SMS-SUBMIT.
The live log prints this full decode for every probe. Reserved request value
`11`, RFU bits, contradictory no-PoR options, and attempts to treat an
SMS-SUBMIT PoR as an ENVELOPE response are rejected.
For a direct answer, `check-tar` accepts one or more arbitrary three-byte TARs,
tests them across selected keysets and all response-capable MSL profiles, and
prints `EXISTS=YES`, `NO`, or `UNKNOWN`. `YES` requires a matching non-`09` PoR;
`NO` means the tested route explicitly returned unknown-TAR RSC `09`; `UNKNOWN`
means the card returned no matching PoR, so absence cannot be inferred.

Lower-level packet and automation commands remain available as CLI subcommands.
Reader discovery and card connection failures are reported as short actionable
errors (for example, asking the user to insert the card) rather than tracebacks.
Before every interactive workflow, the tool lists all discovered PC/SC readers
by name and validates the selected reader index.
After every scan, a best-effort SIM card summary reads and decodes ATR, ICCID,
IMSI, MSISDN, and service-provider name. Both UICC (`00`) and classic SIM (`A0`)
APDU classes are attempted; protected or absent fields are shown as unavailable.
ATR details include convention, supported T= protocols, interface bytes,
historical bytes/text, and TCK where applicable. The summary also states the
detected 2G/3G format and supported SELECT/ENVELOPE CLA values.
TA1 is decoded into Fi, Di, ETU clocks, maximum PPS bit rate and the applicable
PPS request. Vendor detection conservatively matches public ATR/manufacturer
text signatures and the vendor-specific GemXpresso `5F11` directory, always
showing its evidence or `unknown`. Zero-data status queries report PIN1, PIN2,
PUK1, and PUK2 availability, blocking state, and remaining attempts when given.
PIN2/PUK2 queries first use the detected generation's reference (`81` for UICC,
`02` for classic SIM), then safely fall back across both references and `00`/`A0`
CLA formats when the card returns wrong-parameter or unsupported-format status.
Before scanning, the selected card is probed with SELECT MF in modern UICC and
classic SIM forms. The detected 3G (`00`/`80`) or 2G (`A0`) CLA format is then
used automatically for ENVELOPE and GET RESPONSE commands.
Scan summaries list only interesting findings; repetitive filtered status words
remain visible in the live log but are omitted from the final findings section.
ATR identity/vendor lookup uses the public pcsc-tools database at
`https://pcsc-tools.apdu.fr/smartcard_list.txt`; set `SIMTESTER_ATR_DATABASE`
to an updated local copy for offline use. Standard fuzzing reports coverage for
every requested MSL combination, PoR support, decoded PoR status, and a prominent
warning whenever an MSL=0 command succeeds without command security.
EFTLab's Complete List of ATRs at
`https://www.eftlab.com/knowledge-base/complete-list-of-atrs` is queried as a
second source; `SIMTESTER_EFTLAB_ATR_DATABASE` accepts an offline HTML copy.
APDU findings now include contextual support confidence, severity, conclusions,
and a recommended next step instead of relying on the status-word label alone.
Both ATR sources are normalized into one index. Their raw matches are filtered to
telecom indicators (SIM/UICC/USIM/eSIM, GSM/UMTS/LTE/3G/4G/5G, mobile/operator)
and accepted only when attributed to a recognized major SIM manufacturer;
payment cards, access badges, and unknown-vendor entries are excluded.
Major-vendor background is embedded in the script so summaries remain useful
offline even when both ATR sources are unavailable.
The pcsc-tools text and normalized EFTLab HTML are now assembled into one
in-process ATR lookup index, with both source locations retained in
the summary. Local snapshots can still be selected through the environment
variables for fully offline and reproducible matching.
When a probe returns `6881`, the scanner uses MANAGE CHANNEL to open every
logical channel offered by the UICC (channels 1 through 19), applies ISO/IEC
7816-4/ETSI channel CLA encoding, retries the APDU on each channel, records the
channel in findings, and closes every channel afterward.
OTA fuzzing performs controlled PID/DCS/UDHI comparisons, identifies which
parameter changes correlate with status-word changes, separates warning variants
from the dominant response, measures parseable PoR support, and explicitly avoids
treating an empty `9000` transport acknowledgement as proof of OTA execution.
For the common 18-variant matrix, it also recognizes the repeated `9000` to
`62xx` transition caused by combining UDHI with binary/class-2 DCS `04` or `F6`,
uses DCS `00` as a control, and reports when PID `00`/`40`/`7F` is independent.
This is classified as evidence that a different UICC parser path was reached,
not as evidence that the secured command executed or that a TAR is unprotected.
Every TAR probe now requests PoR, including caller-supplied packets that omitted
the request bit. Before delivery, the TAR workflow sends the generation-specific
ETSI UICC/SIM STATUS command and optional card-recognition GET DATA probes using
both ISO CLA `00` and the detected UICC/SIM telecom CLA (`80`/`A0`),
follows `61xx`, `9Fxx`, and `6Cxx`, and logs every initial and corrected exchange.
`6D00` from optional GET DATA is reported as a context capability result rather
than evidence against OTA support. Repeated empty `62xx` replies are collapsed
into a dominant transport/parser baseline instead of listing every TAR as found.
TAR scan headers include the tool version and build identifier. If output still
says `GET STATUS application templates` or `Interesting findings: 135`, it came
from an older copied script; `python simtester.py --version` identifies the file
being executed, and the current build reports `get-data-concise-v14`.
Successful STATUS FCP data is decoded into its file descriptor and identifier,
life-cycle state, UICC characteristics, available memory, compact security
attributes, and PIN-key references. Unknown or malformed TLVs remain visible as
raw hexadecimal instead of being guessed. Output provides COMPACT and EXPANDED
views, and successful GET DATA card-recognition responses decode template `66`
and its known fields while retaining unknown tags. A `6D00` or `6E00` response
is reported together with every CLA attempted; it means that specific format is
unsupported and remains unrelated to TAR/PoR results.
Each context result now prints both `COMPACT`, a one-line operational answer, and
`EXPANDED`, the raw response plus complete field-by-field decode. This keeps full ETSI/3GPP evidence
available without forcing operators to read every TLV during a large TAR scan.

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
