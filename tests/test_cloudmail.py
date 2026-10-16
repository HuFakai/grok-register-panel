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


def _install_no_sleep():
    previous = cloudmail.time.sleep
    cloudmail.time.sleep = lambda _seconds: None
    return previous


def test_wait_for_code_deletes_mail_and_purges_on_success():
    previous_sleep = _install_no_sleep()
    calls = {"list": 0, "delete": []}

    def fake_post(url, **_kwargs):
        if url.endswith("/api/public/genToken"):
            return FakeResponse({"code": 200, "data": {"token": "pub-token"}})
        if url.endswith("/api/public/emailList"):
            calls["list"] += 1
            if calls["list"] == 1:
                return FakeResponse(
                    {
                        "code": 200,
                        "data": [
                            {"emailId": 101, "subject": "xAI", "content": "SpaceXAI confirmation code: 019-579"},
                        ],
                    }
                )
            return FakeResponse({"code": 200, "data": []})
        if url.endswith("/api/login"):
            return FakeResponse({"code": 200, "data": {"token": "admin-jwt"}})
        raise AssertionError(url)

    def fake_delete(url, **kwargs):
        calls["delete"].append((url, kwargs.get("params")))
        return FakeResponse({"code": 200, "data": None})

    try:
        code = cloudmail.wait_for_code(
            fake_post,
            fake_delete,
            "https://cloudmail.example.com",
            "admin@example.com",
            "secret",
            "user@mail.example.com",
            timeout=5,
            poll_interval=1,
            raise_if_cancelled=lambda _cb: None,
            sleep_with_cancel=lambda _s, _cb: None,
        )
    finally:
        cloudmail.time.sleep = previous_sleep

    assert code == "019-579"
    # 验证码到手即删该封邮件（allEmail/delete 永久删除）
    assert calls["delete"][0][0].endswith("/api/allEmail/delete")
    assert calls["delete"][0][1] == {"emailIds": "101"}
    # 残留清空后无第二次删除；本测试未跟踪 account_id，故无账号删除
    assert len(calls["delete"]) == 1


def test_wait_for_code_timeout_purges_mailbox_without_account_id():
    previous_sleep = _install_no_sleep()
    calls = {"delete": [], "account_delete": 0}

    def fake_post(url, **_kwargs):
        if url.endswith("/api/public/genToken"):
            return FakeResponse({"code": 200, "data": {"token": "pub-token"}})
        if url.endswith("/api/public/emailList"):
            return FakeResponse(
                {
                    "code": 200,
                    "data": [
                        {"emailId": 7, "subject": "late mail", "content": "no code"},
                        {"emailId": 8, "subject": "resend", "content": "still no"},
                    ],
                }
            )
        if url.endswith("/api/login"):
            return FakeResponse({"code": 200, "data": {"token": "admin-jwt"}})
        raise AssertionError(url)

    def fake_delete(url, **kwargs):
        if url.endswith("/api/allEmail/delete"):
            calls["delete"].append(kwargs.get("params"))
            return FakeResponse({"code": 200, "data": None})
        if url.endswith("/api/account/delete"):
            calls["account_delete"] += 1
            return FakeResponse({"code": 200, "data": None})
        raise AssertionError(url)

    try:
        try:
            cloudmail.wait_for_code(
                fake_post,
                fake_delete,
                "https://cloudmail.example.com",
                "admin@example.com",
                "secret",
                "orphan@mail.example.com",
                timeout=1,
                poll_interval=1,
                raise_if_cancelled=lambda _cb: None,
                sleep_with_cancel=lambda _s, _cb: None,
            )
            raise AssertionError("超时应抛异常")
        except Exception as exc:
            assert "未收到验证码" in str(exc)
        # 账号 id 未跟踪（进程重启场景）也不影响邮件清理
        assert calls["account_delete"] == 0
        assert calls["delete"] == [{"emailIds": "7,8"}]
    finally:
        cloudmail.time.sleep = previous_sleep


def test_purge_mailbox_tolerates_delete_failure():
    previous_sleep = _install_no_sleep()

    def fake_post(url, **_kwargs):
        if url.endswith("/api/public/genToken"):
            return FakeResponse({"code": 200, "data": {"token": "pub-token"}})
        if url.endswith("/api/public/emailList"):
            return FakeResponse(
                {"code": 200, "data": [{"emailId": 5, "subject": "s"}]}
            )
        if url.endswith("/api/login"):
            return FakeResponse({"code": 200, "data": {"token": "admin-jwt"}})
        raise AssertionError(url)

    def fake_delete(url, **_kwargs):
        return FakeResponse({"code": 500, "message": "boom"})

    try:
        deleted = cloudmail.purge_mailbox(
            fake_post,
            fake_delete,
            "https://cloudmail.example.com",
            "admin@example.com",
            "secret",
            "user@mail.example.com",
        )
    finally:
        cloudmail.time.sleep = previous_sleep
    assert deleted == 0


if __name__ == "__main__":
    test_admin_mutation_retries_one_expired_login()
    test_wait_for_code_deletes_mail_and_purges_on_success()
    test_wait_for_code_timeout_purges_mailbox_without_account_id()
    test_purge_mailbox_tolerates_delete_failure()
    print("OK cloudmail")
