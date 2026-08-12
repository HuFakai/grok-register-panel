# -*- coding: utf-8 -*-
"""Unit tests for the grok2api admin API client (webui/grok2api_api.py)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui.grok2api_api import (
    Grok2apiClient,
    Grok2apiError,
    drain_sse_to_report,
    iter_sse,
)


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: object = None, text: str = ""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self):
        if self._json_data is not None:
            return self._json_data
        raise ValueError("no json")

    def iter_lines(self, decode_unicode=True):
        return self.text.splitlines(keepends=True)


def test_iter_sse_parses_events_and_json():
    stream = [
        ": connected\n",
        "event: progress\n",
        'data: {"completed":3,"total":10,"phase":"converting"}\n',
        "\n",
        "event: complete\n",
        'data: {"created":5,"linked":1,"skipped":3}\n',
        "\n",
    ]
    events = list(iter_sse(stream))
    assert events[0] == ("progress", {"completed": 3, "total": 10, "phase": "converting"})
    assert events[1] == ("complete", {"created": 5, "linked": 1, "skipped": 3})


def test_iter_sse_falls_back_to_raw_text():
    stream = ["event: error\n", "data: something went wrong\n", "\n"]
    events = list(iter_sse(stream))
    assert events == [("error", "something went wrong")]


def test_drain_sse_complete_and_error():
    ok = FakeResponse(text="event: complete\ndata: {\"created\":1,\"skipped\":2}\n\n")
    assert drain_sse_to_report(ok, label="导入") == {"created": 1, "skipped": 2}

    err = FakeResponse(text='event: error\ndata: {"code":"accountImportFileTooLarge","message":"太大"}\n\n')
    try:
        drain_sse_to_report(err, label="导入")
    except Grok2apiError as exc:
        assert exc.code == "accountImportFileTooLarge"
        assert "太大" in str(exc)
    else:
        raise AssertionError("error event must raise")


class FakeSession:
    def __init__(self):
        self.calls = []
        self.token = ""

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if url.endswith("/auth/login"):
            return FakeResponse(
                200,
                {
                    "data": {
                        "tokens": {"accessToken": "jwt-token-123"},
                    }
                },
            )
        if "convert-to-build" in url:
            return FakeResponse(text="event: complete\ndata: {\"created\":2,\"linked\":1}\n\n")
        if "sync-to-console" in url:
            return FakeResponse(text="event: complete\ndata: {\"created\":4,\"synced\":3}\n\n")
        if "web/import" in url:
            return FakeResponse(text="event: complete\ndata: {\"created\":10,\"skipped\":1}\n\n")
        raise AssertionError(f"unexpected url: {url}")

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return FakeResponse(
            200,
            {
                "data": {
                    "items": [
                        {"id": "42", "email": "target@example.com", "provider": "grok_web"},
                        {"id": "7", "email": "other@example.com", "provider": "grok_web"},
                    ],
                    "page": 1,
                    "total": 2,
                }
            },
        )


def test_client_login_import_convert_sync():
    session = FakeSession()
    client = Grok2apiClient(
        "http://127.0.0.1:8080",
        username="admin",
        password="test-admin-pw-123",
        session=session,
    )
    # 未配置 → 登录失败
    empty = Grok2apiClient("", username="", password="", session=session)
    try:
        empty.login()
    except Grok2apiError as exc:
        assert exc.code == "notConfigured"
    else:
        raise AssertionError("empty config must raise")

    # 导入
    report = client.import_web_accounts('{"sso_token":"t1"}\n')
    assert report == {"created": 10, "skipped": 1}
    # 转 Build
    assert client.convert_to_build() == {"created": 2, "linked": 1}
    # 转 Console
    assert client.sync_to_console() == {"created": 4, "synced": 3}

    # 认证头：首次调用自动登录
    login_call = session.calls[0]
    assert login_call[1].endswith("/auth/login")
    assert login_call[2]["json"] == {"username": "admin", "password": "test-admin-pw-123"}
    import_call = session.calls[1]
    assert import_call[1].endswith("/accounts/web/import")
    assert import_call[2]["headers"]["Authorization"] == "Bearer jwt-token-123"
    assert "files" in import_call[2]
    # 转 Build body
    convert_call = session.calls[2]
    assert convert_call[2]["json"] == {"all": True, "strategy": "missing"}
    sync_call = session.calls[3]
    assert sync_call[2]["json"] == {"all": True, "strategy": "all"}


def test_find_web_account_id_matches_by_email():
    session = FakeSession()
    client = Grok2apiClient(
        "http://127.0.0.1:8080",
        username="admin",
        password="test-admin-pw-123",
        session=session,
    )
    account_id = client.find_web_account_id("TARGET@example.com", retries=1)
    assert account_id == "42"
    get_call = [c for c in session.calls if c[0] == "GET"][0]
    assert get_call[1].endswith("/api/admin/v1/accounts")
    assert get_call[2]["params"] == {
        "search": "target@example.com",
        "provider": "grok_web",
        "pageSize": 100,
    }


def test_find_web_account_id_not_found_returns_none():
    class EmptyAccountsSession(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            return FakeResponse(200, {"data": {"items": [], "total": 0}})

    session = EmptyAccountsSession()
    client = Grok2apiClient(
        "http://127.0.0.1:8080",
        username="admin",
        password="test-admin-pw-123",
        session=session,
    )
    assert client.find_web_account_id("missing@example.com", retries=2, delay=0.0) is None
    # 重试 2 次 → 2 次 GET
    gets = [c for c in session.calls if c[0] == "GET"]
    assert len(gets) == 2


def test_convert_and_sync_by_ids_bodies():
    session = FakeSession()
    client = Grok2apiClient(
        "http://127.0.0.1:8080",
        username="admin",
        password="test-admin-pw-123",
        session=session,
    )
    assert client.convert_accounts_by_ids(["42"]) == {"created": 2, "linked": 1}
    assert client.sync_accounts_by_ids(["42"]) == {"created": 4, "synced": 3}
    convert_call = [c for c in session.calls if "convert-to-build" in c[1]][-1]
    assert convert_call[2]["json"] == {
        "ids": ["42"],
        "all": False,
        "strategy": "missing",
    }
    sync_call = [c for c in session.calls if "sync-to-console" in c[1]][-1]
    assert sync_call[2]["json"] == {"ids": ["42"], "all": False, "strategy": "all"}


def test_authed_retries_once_on_401():
    class FlakySession(FakeSession):
        def __init__(self):
            super().__init__()
            self.unauthorized_done = False

        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            if url.endswith("/auth/login"):
                return FakeResponse(
                    200,
                    {
                        "data": {
                            "tokens": {"accessToken": "jwt-token-123"},
                        }
                    },
                )
            if "web/import" in url:
                if not self.unauthorized_done:
                    self.unauthorized_done = True
                    return FakeResponse(401, {}, "unauthorized")
                return FakeResponse(
                    text="event: complete\ndata: {\"created\":1,\"skipped\":0}\n\n"
                )
            raise AssertionError(f"unexpected url: {url}")

    session = FlakySession()
    client = Grok2apiClient(
        "http://127.0.0.1:8080",
        username="admin",
        password="test-admin-pw-123",
        session=session,
    )
    report = client.import_web_accounts('{"sso_token":"t1"}\n')
    assert report == {"created": 1, "skipped": 0}
    # login（401 前）+ login（401 重登）+ import 重试成功
    logins = [c for c in session.calls if c[1].endswith("/auth/login")]
    assert len(logins) == 2


if __name__ == "__main__":
    test_iter_sse_parses_events_and_json()
    test_iter_sse_falls_back_to_raw_text()
    test_drain_sse_complete_and_error()
    test_client_login_import_convert_sync()
    test_find_web_account_id_matches_by_email()
    test_find_web_account_id_not_found_returns_none()
    test_convert_and_sync_by_ids_bodies()
    test_authed_retries_once_on_401()
    print("OK grok2api api")
