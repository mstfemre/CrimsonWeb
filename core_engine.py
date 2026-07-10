#!/usr/bin/env python3
"""Backward-compatible launcher for the packaged CrimsonWeb engine."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from crimsonweb.core_engine import main


if __name__ == "__main__":
    raise SystemExit(main())
