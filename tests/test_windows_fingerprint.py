# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from browser_session import (  # noqa: E402
    DEFAULT_BROWSER_OS,
    create_browser_options,
    format_fingerprint_log,
    resolve_browser_os,
)


def test_resolve_browser_os_default_is_windows():
    old = os.environ.pop("GROK_BROWSER_OS", None)
    try:
        assert resolve_browser_os() == "windows"
        assert DEFAULT_BROWSER_OS == "windows"
    finally:
        if old is None:
            os.environ.pop("GROK_BROWSER_OS", None)
        else:
            os.environ["GROK_BROWSER_OS"] = old


def test_resolve_browser_os_aliases_and_fallback():
    assert resolve_browser_os("win") == "windows"
    assert resolve_browser_os("WIN32") == "windows"
    assert resolve_browser_os("mac") == "macos"
    assert resolve_browser_os("darwin") == "macos"
    assert resolve_browser_os("lin") == "linux"
    assert resolve_browser_os("nope") == "windows"
    assert resolve_browser_os("") == "windows"


def test_resolve_browser_os_env_override(monkeypatch=None):
    old = os.environ.get("GROK_BROWSER_OS")
    os.environ["GROK_BROWSER_OS"] = "linux"
    try:
        assert resolve_browser_os() == "linux"
    finally:
        if old is None:
            os.environ.pop("GROK_BROWSER_OS", None)
        else:
            os.environ["GROK_BROWSER_OS"] = old


def test_create_browser_options_pins_windows(monkeypatch=None):
    import browser_session as bs

    old = os.environ.pop("GROK_BROWSER_OS", None)
    orig_proxies = bs._proxies
    orig_exe = bs._detect_camoufox_exe
    bs._proxies = lambda: {}
    bs._detect_camoufox_exe = lambda: ""
    try:
        opts = create_browser_options(unique_profile=False)
        assert opts["os"] == "windows"
        assert opts["block_webrtc"] is True
        assert opts["humanize"] is True
    finally:
        bs._proxies = orig_proxies
        bs._detect_camoufox_exe = orig_exe
        if old is None:
            os.environ.pop("GROK_BROWSER_OS", None)
        else:
            os.environ["GROK_BROWSER_OS"] = old


def test_format_fingerprint_log_flags_linux_leak():
    line = format_fingerprint_log(
        "windows",
        {
            "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",
            "platform": "Linux x86_64",
            "oscpu": "Linux x86_64",
            "webgl": False,
            "renderer": "",
            "fontsWin": False,
        },
    )
    assert "os=windows" in line
    assert "linux-ua" in line
    assert "no-webgl" in line
    assert "no-segoe" in line


def test_format_fingerprint_log_clean_windows():
    line = format_fingerprint_log(
        "windows",
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
            "platform": "Win32",
            "oscpu": "Windows NT 10.0; Win64; x64",
            "webgl": True,
            "renderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0)",
            "fontsWin": True,
        },
    )
    assert "platform=Win32" in line
    assert "leak=none" in line
    assert "ANGLE" in line


if __name__ == "__main__":
    test_resolve_browser_os_default_is_windows()
    test_resolve_browser_os_aliases_and_fallback()
    test_resolve_browser_os_env_override()
    test_create_browser_options_pins_windows()
    test_format_fingerprint_log_flags_linux_leak()
    test_format_fingerprint_log_clean_windows()
    print("OK windows fingerprint")
