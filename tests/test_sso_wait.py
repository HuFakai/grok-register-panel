# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import register_flow as flow
import grok_register_ttk as app


class FakeClock:
    def __init__(self):
        self.value = 1_000.0

    def time(self):
        self.value += 0.25
        return self.value

    def sleep(self, seconds, _cancel=None):
        self.value += max(float(seconds), 0.0)


class FakeWait:
    def doc_loaded(self):
        return None


class FakePage:
    def __init__(self, cookie_after_nudge=None):
        self.url = "https://accounts.x.ai/sign-up?redirect=grok-com"
        self.wait = FakeWait()
        self.nudges = 0
        self.cookie_after_nudge = cookie_after_nudge
        self.goto_kwargs = []

    def cookies(self, **_kwargs):
        if self.cookie_after_nudge and self.nudges >= self.cookie_after_nudge:
            return [{"name": "sso", "value": "sso-test-value"}]
        return [{"name": "xai_anon_id", "value": "anon"}]

    def get(self, url, **kwargs):
        self.nudges += 1
        self.goto_kwargs.append(kwargs)
        self.url = url

    def run_js(self, script, *_args):
        if "return 'not-final-page'" in script:
            return "not-final-page"
        return False


def run_with_fake_page(page, callback):
    clock = FakeClock()
    originals = (
        flow.page,
        flow.active_page,
        flow.refresh_active_page,
        flow.time.time,
        dict(flow._deps),
    )
    try:
        flow.page = page
        flow.active_page = lambda: page
        flow.refresh_active_page = lambda: page
        flow.time.time = clock.time
        flow._deps["sleep_with_cancel"] = clock.sleep
        flow._deps["raise_if_cancelled"] = lambda _callback=None: None
        return callback()
    finally:
        (
            flow.page,
            flow.active_page,
            flow.refresh_active_page,
            flow.time.time,
            deps,
        ) = originals
        flow._deps.clear()
        flow._deps.update(deps)


def test_sso_retry_window_reaches_second_nudge_and_reads_cookie():
    page = FakePage(cookie_after_nudge=2)
    token = run_with_fake_page(
        page,
        lambda: flow.wait_for_sso_cookie(
            timeout=40,
            poll_interval=0.2,
            retry_count=3,
            retry_interval=3,
        ),
    )
    assert token == "sso-test-value"
    assert page.nudges == 2
    assert all(kwargs["wait_until"] == "domcontentloaded" for kwargs in page.goto_kwargs)
    assert all(4000 <= kwargs["timeout"] <= 10000 for kwargs in page.goto_kwargs)


def test_sso_timeout_uses_configured_retry_count():
    page = FakePage(cookie_after_nudge=None)
    try:
        run_with_fake_page(
            page,
            lambda: flow.wait_for_sso_cookie(
                timeout=60,
                poll_interval=0.2,
                retry_count=3,
                retry_interval=3,
            ),
        )
    except Exception as exc:
        assert "sso_timeout" in str(exc)
    else:
        raise AssertionError("missing SSO should time out")
    assert page.nudges == 3


def test_sso_policy_defaults_and_bounds():
    old = dict(app.config)
    try:
        app.config.update(
            {
                "sso_wait_timeout": 999,
                "sso_poll_interval": 0,
                "sso_retry_count": 99,
                "sso_retry_interval": 1,
            }
        )
        assert app.get_sso_wait_policy() == {
            "timeout": 180,
            "poll_interval": 0.2,
            "retry_count": 5,
            "retry_interval": 3,
        }
    finally:
        app.config.clear()
        app.config.update(old)


if __name__ == "__main__":
    test_sso_retry_window_reaches_second_nudge_and_reads_cookie()
    test_sso_timeout_uses_configured_retry_count()
    test_sso_policy_defaults_and_bounds()
    print("OK sso_wait")
