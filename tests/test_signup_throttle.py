# -*- coding: utf-8 -*-
"""register_flow 注册限流识别（Email sign-up isn't available）。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import register_flow


class FakePage:
    def __init__(self, body_text: str, url: str = "https://accounts.x.ai/sign-up"):
        self._body = body_text
        self.url = url

    def run_js(self, _script, *args):
        return self._body


def test_page_signup_throttled_detects_variants():
    original = register_flow.active_page
    try:
        register_flow.active_page = lambda: FakePage(
            "Email\nEmail sign-up isn't available right now. Sign up another way.\nSign up"
        )
        assert register_flow.page_signup_throttled() is True

        register_flow.active_page = lambda: FakePage(
            "EMAIL SIGN-UP IS NOT AVAILABLE right now"
        )
        assert register_flow.page_signup_throttled() is True

        register_flow.active_page = lambda: FakePage(
            "Sign up with your email\nContinue\nGo back"
        )
        assert register_flow.page_signup_throttled() is False
    finally:
        register_flow.active_page = original


def test_page_notice_text_collapses_whitespace():
    original = register_flow.active_page
    try:
        register_flow.active_page = lambda: FakePage(
            "  line one\n\n  line two   with spaces  " + "x" * 300
        )
        text = register_flow.page_notice_text(limit=120)
        assert text.startswith("line one line two with spaces")
        assert len(text) <= 120
        assert "\n" not in text
    finally:
        register_flow.active_page = original


def test_page_helpers_tolerate_missing_page():
    original = register_flow.active_page
    try:
        register_flow.active_page = lambda: None
        assert register_flow.page_notice_text() == ""
        assert register_flow.page_signup_throttled() is False
    finally:
        register_flow.active_page = original


if __name__ == "__main__":
    test_page_signup_throttled_detects_variants()
    test_page_notice_text_collapses_whitespace()
    test_page_helpers_tolerate_missing_page()
    print("OK signup throttle")
