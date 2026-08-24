# SIMTester (Python port)

A from-scratch Python port of SRLabs' [SIMTester](https://github.com/srlabs/simtester)
(`SIMLibrary` + `SIMTester`), a tool for testing (U)SIM cards against a set of
known OTA/RFM security weaknesses (unprotected TARs, crackable signatures,
decryption oracles, unauthenticated WIB/S@T Toolkit Application execution,
etc). Intended for testing SIM cards you own or are authorized to test.

## Layout

- `simlib/` - low level (U)SIM / smart card / OTA (TS 102.225 "Command
  Packet" & "Response Packet") toolkit. Port of the Java `SIMLibrary`
  package.
- `simtester/` - application layer: the fuzzer, TAR/APDU/file scanners, CSV
  report writer, GSM Map uploader and the CLI entry point. Port of the Java
  `SIMTester` package.

## Requirements

```
pip install -r requirements.txt
```

- [`pyscard`](https://pypi.org/project/pyscard/) talks to a PC/SC smart card
  reader (needs `libpcsclite` + a running `pcscd` on Linux). This is the only
  reader backend ported - the original's OsmocomBB/JNI provider was not
  ported (baseband-specific native code with no Python equivalent).
- `pycryptodome` provides DES/3DES for the OTA Command Packet
  signing/ciphering.
- `requests` is used for the (optional) upload to gsmmap.org.

## Usage

```
python -m simtester --help
python -m simtester -sf                     # scan the card's file system
python -m simtester -st                     # scan all OTA TARs
python -m simtester -sa -sal2               # scan APDUs (CLA + INS)
python -m simtester -of                     # OTA passthrough fuzzing
python -m simtester                         # full OTA security fuzzing (default)
```

CLI flags mirror the original Java tool (`-t`, `-k`, `-f`, `-st`, `-str`,
`-sa`, `-sf`, `-of`, `-qf`, `-poke`, `-gsmmap`, `-2g`, ...) - see `--help`.

## Notes on the port

- Byte handling uses plain Python `bytes`/`bytearray` instead of Java's
  `byte[]` / `javax.smartcardio.CommandAPDU`/`ResponseAPDU` (re-implemented
  in `simlib/apdu.py`).
- `CommandPacket`'s DES-CBC-MAC signing and DES/3DES-CBC ciphering were
  verified against independently-computed reference ciphertexts during
  development (see git history) rather than just transliterated.
- The GSM Map upload uses `requests` with the system trust store instead of
  replicating the bundled Java keystore/truststore.
- Card communication (`ChannelHandler`) uses `pyscard`; only a PC/SC reader
  is supported (`-tf PCSC`), not OsmocomBB.
