#!/usr/bin/env python3
"""StegoLab v4 — All-in-One Steganography Analysis Toolkit

This is a backward-compatible wrapper. All logic now lives in the
``stegolab`` package.  Run directly or via ``python -m stegolab.cli``.
"""
import sys
from pathlib import Path

# Ensure the package directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from stegolab.cli import main  # noqa: E402


if __name__ == "__main__":
    main()

