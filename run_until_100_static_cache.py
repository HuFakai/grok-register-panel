#!/usr/bin/env python3
"""Compatibility launcher for the orchestrator with static caching enabled."""

from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(str(ROOT))
os.environ["GROK_STATIC_ASSET_CACHE"] = "1"
os.environ.setdefault("GROK_STATIC_CACHE_DIR", str(ROOT / "log" / "static-asset-cache"))

sys.argv[0] = str(ROOT / "run_until_100.py")
runpy.run_path(str(ROOT / "run_until_100.py"), run_name="__main__")
