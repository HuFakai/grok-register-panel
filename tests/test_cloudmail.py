# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import cloudmail


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.text = str(payload)

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_admin_mutation_retries_one_expired_login():
    calls = {"login": 0, "add": 0}

    def fake_post(url, **_kwargs):
        if url.endswith("/api/login"):
            calls["login"] += 1
            return FakeResponse(
                {"code": 200, "data": {"token": f"jwt-{calls['login']}"}}
            )
        if url.endswith("/api/account/add"):
            calls["add"] += 1
            if calls["add"] == 1:
                return FakeResponse(
                    {"code": 401, "message": "身份认证失效,请重新登录"}
                )
            return FakeResponse({"code": 200, "data": {"accountId": 42}})
        raise AssertionError(url)

    result = cloudmail.add_address(
        fake_post,
        "https://cloudmail.example.com",
        "admin@example.com",
        "secret",
        "user@mail.example.com",
    )
    assert result["accountId"] == 42
    assert calls == {"login": 2, "add": 2}


if __name__ == "__main__":
    test_admin_mutation_retries_one_expired_login()
    print("OK cloudmail")
