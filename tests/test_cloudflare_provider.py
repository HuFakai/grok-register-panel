# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import cloudflare


class FakeResponse:
    def __init__(self, status_code, *, body="", data=None, reason=""):
        self.status_code = status_code
        self.text = body
        self._data = data
        self.reason = reason or "test response"

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code} for test request")


def _without_sleep(callback):
    previous = cloudflare.time.sleep
    cloudflare.time.sleep = lambda _seconds: None
    try:
        return callback()
    finally:
        cloudflare.time.sleep = previous


def test_address_collision_retries_with_admin_payload():
    calls = []
    responses = [
        FakeResponse(400, body="Address already exists"),
        FakeResponse(200, data={"address": "user@mail.example", "jwt": "test-jwt"}),
    ]

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return responses.pop(0)

    result = _without_sleep(
        lambda: cloudflare.create_temp_address(
            fake_post,
            "https://mail.example",
            accounts_path="/admin/new_address",
            domain="mail.example",
            randomize_subdomain=False,
            name="fixed-name",
        )
    )
    assert result == ("user@mail.example", "test-jwt")
    assert len(calls) == 2
    assert calls[0][1]["json"] == {
        "name": "fixed-name",
        "enablePrefix": False,
        "domain": "mail.example",
    }
    assert calls[1][1]["json"]["name"] != "fixed-name"
    assert "password" not in calls[0][1]["json"]


def test_nonretryable_400_is_not_retried_or_echoed():
    calls = []
    secret = "response-secret-value-123456"

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(400, body=f"Required field token={secret}")

    try:
        _without_sleep(
            lambda: cloudflare.create_temp_address(
                fake_post,
                "https://mail.example",
                domain="mail.example",
                randomize_subdomain=False,
            )
        )
    except RuntimeError as exc:
        assert secret not in str(exc)
    else:
        raise AssertionError("non-retryable HTTP 400 must fail")
    assert len(calls) == 1


def test_admin_fallback_respects_random_subdomain_opt_out():
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(
            200,
            data={"address": "user@mail.example", "jwt": "test-jwt"},
        )

    result = cloudflare.create_mailbox_fallback(
        lambda *_args, **_kwargs: None,
        fake_post,
        "https://mail.example",
        domains_path="/domains",
        accounts_path="/admin/new_address",
        token_path="/token",
        domain="mail.example",
        randomize_subdomain=False,
    )
    assert result == ("user@mail.example", "test-jwt")
    assert calls[0][1]["json"]["domain"] == "mail.example"


def _stub_wait_io(messages, deleted):
    """构造 wait_for_code 用的假 IO：列表返回 messages，删除记录到 deleted。"""

    def http_get(url, **kwargs):
        return FakeResponse(200, data={"results": list(messages)})

    def http_delete(url, **kwargs):
        deleted.append(url)
        return FakeResponse(200, data={"ok": True})

    return http_get, http_delete


def test_wait_for_code_timeout_purges_residual_mail():
    """超时（未提取到验证码）时清理邮箱残留，避免服务端邮件表持续膨胀。"""
    deleted = []
    http_get, http_delete = _stub_wait_io(
        [
            {"id": 7, "subject": "junk-a", "address": "user@mail.example"},
            {"id": 8, "subject": "junk-b", "address": "user@mail.example"},
        ],
        deleted,
    )
    try:
        cloudflare.wait_for_code(
            http_get,
            "https://mail.example",
            "tok",
            "user@mail.example",
            timeout=0,
            poll_interval=1,
            raise_if_cancelled=lambda _cb=None: None,
            sleep_with_cancel=lambda _s, _cb=None: None,
            http_delete=http_delete,
            purge_on_failure=True,
        )
    except Exception as exc:
        assert "未收到验证码邮件" in str(exc)
    else:
        raise AssertionError("timeout must raise")
    assert len(deleted) == 2, deleted
    assert all("/admin/mails/" in url for url in deleted)


def test_wait_for_code_timeout_without_purge_keeps_mail():
    """未开启 purge_on_failure（或未传 http_delete）时不删除任何邮件。"""
    deleted = []
    http_get, http_delete = _stub_wait_io(
        [{"id": 9, "subject": "junk", "address": "user@mail.example"}],
        deleted,
    )
    try:
        cloudflare.wait_for_code(
            http_get,
            "https://mail.example",
            "tok",
            "user@mail.example",
            timeout=0,
            poll_interval=1,
            raise_if_cancelled=lambda _cb=None: None,
            sleep_with_cancel=lambda _s, _cb=None: None,
            http_delete=http_delete,
            purge_on_failure=False,
        )
    except Exception as exc:
        assert "未收到验证码邮件" in str(exc)
    else:
        raise AssertionError("timeout must raise")
    assert deleted == []


def test_purge_mailbox_tolerates_delete_failures():
    """单封删除失败不中断，成功计数只算真正删掉的。"""
    deleted = []

    def http_get(url, **kwargs):
        return FakeResponse(
            200,
            data={
                "results": [
                    {"id": 1, "address": "u@mail.example"},
                    {"id": 2, "address": "u@mail.example"},
                ]
            },
        )

    def http_delete(url, **kwargs):
        if url.endswith("/1"):
            raise RuntimeError("HTTP 500 for test request")
        deleted.append(url)
        return FakeResponse(200, data={"ok": True})

    count = cloudflare.purge_mailbox(
        http_get, http_delete, "https://mail.example", "tok"
    )
    assert count == 1
    assert len(deleted) == 1


def test_purge_mailbox_stops_when_list_fails():
    """列表拉取失败（服务端故障）时立即停止，不空转。"""

    def http_get(url, **kwargs):
        raise RuntimeError("HTTP 500 for test request")

    count = cloudflare.purge_mailbox(
        http_get, lambda *_a, **_k: FakeResponse(200), "https://mail.example", "tok"
    )
    assert count == 0


if __name__ == "__main__":
    test_address_collision_retries_with_admin_payload()
    test_nonretryable_400_is_not_retried_or_echoed()
    test_admin_fallback_respects_random_subdomain_opt_out()
    test_wait_for_code_timeout_purges_residual_mail()
    test_wait_for_code_timeout_without_purge_keeps_mail()
    test_purge_mailbox_tolerates_delete_failures()
    test_purge_mailbox_stops_when_list_fails()
    print("OK cloudflare provider")
