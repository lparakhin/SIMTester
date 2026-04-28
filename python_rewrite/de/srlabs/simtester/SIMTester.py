"""Compatibility shim: forwards to the single-file tool implementation."""

from python_rewrite.simtester_tools import main


if __name__ == "__main__":
    raise SystemExit(main())
