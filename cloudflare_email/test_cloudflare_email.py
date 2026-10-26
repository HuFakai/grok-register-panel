# -*- coding: utf-8 -*-
"""核心功能测试：建号撞名重试 / catch-all 自签 / 验证码提取 / 轮询取码 / 删信。

运行：python3 test_cloudflare_email.py（或 pytest test_cloudflare_email.py -q）
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cloudflare_email as cf


class FakeResponse:
    def __init__(self, status_code=200, *, body="", data=None):
        self.status_code = status_code
        self.text = body
        self._data = data

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _without_sleep(callback):
    previous = cf.time.sleep
    cf.time.sleep = lambda _seconds: None
    try:
        return callback()
    finally:
        cf.time.sleep = previous


def _decode_payload(jwt: str) -> dict:
    part = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode("utf-8"))


def test_create_address_collision_retry():
    """admin 建号撞名 400 → 换随机名重试；payload 不含旧版 password 字段。"""
    calls = []
    responses = [
        FakeResponse(400, body="Address already exists"),
        FakeResponse(200, data={"address": "user@mail.example", "jwt": "jwt"}),
    ]

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return responses.pop(0)

    result = _without_sleep(lambda: cf.create_temp_address(
        fake_post, "https://mail.example",
        accounts_path="/admin/new_address", domain="mail.example",
        randomize_subdomain=False, name="fixed-name",
    ))
    assert result == ("user@mail.example", "jwt")
    assert len(calls) == 2
    assert calls[0][1]["json"] == {"name": "fixed-name", "enablePrefix": False, "domain": "mail.example"}
    assert calls[1][1]["json"]["name"] != "fixed-name"
    assert "password" not in calls[0][1]["json"]


def test_create_address_non_retryable_error():
    """非撞名 400 立即失败、不重试，且报错不回显响应体（可能含密钥）。"""
    calls = []
    secret = "response-secret-value-123456"

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(400, body=f"Required field token={secret}")

    try:
        _without_sleep(lambda: cf.create_temp_address(
            fake_post, "https://mail.example", domain="mail.example", randomize_subdomain=False,
        ))
    except Exception as exc:
        assert secret not in str(exc)
    else:
        raise AssertionError("非撞名 400 必须失败")
    assert len(calls) == 1


def test_catchall_email_and_token():
    """catch-all 免建号：随机账号 + 随机子域 + HS256 自签 JWT。"""
    addr, jwt = cf.cloudflare_catchall_email_and_token("secret-abc", domain="example.com")
    local, domain = addr.split("@")
    assert local and domain.endswith(".example.com") and domain != "example.com"
    header = json.loads(base64.urlsafe_b64decode(jwt.split(".")[0] + "==").decode("utf-8"))
    payload = _decode_payload(jwt)
    assert header["alg"] == "HS256"
    assert payload["address"] == addr and payload["address_id"] == 0
    # 同输入签名稳定；连续生成子域随机变化
    assert jwt == cf._sign_cloudflare_address_jwt("secret-abc", addr, 0)
    addr2, _ = cf.cloudflare_catchall_email_and_token("secret-abc", domain="example.com")
    assert addr2.split("@")[1] != domain


def test_extract_verification_code():
    """提取 XXX-YYY 码：过滤 HTML 模板伪码，锚定上下文，支持全数字新模板。"""
    assert cf.extract_verification_code("Your verification code: ABC-123") == "ABC-123"
    assert cf.extract_verification_code("gap-100 per-100 max-100 col-100", "布局报告") is None
    assert cf.extract_verification_code("SpaceXAI confirmation code: 427-599") == "427-599"
    hay = "padding:0; width:100%\nQO7-TUD is your xAI confirmation code"
    assert cf.extract_verification_code(hay) == "QO7-TUD"


def test_wait_for_code_and_delete_mail():
    """轮询提取到码后触发删信回调（拿到 mail_id）；删信走 /admin/mails/{id} + x-admin-auth。"""
    messages = [{
        "id": 7, "address": "test@example.com", "to": [{"address": "test@example.com"}],
        "subject": "Verification", "text": "Your verification code: ABC-123",
    }]
    original = (cf.get_messages, cf.get_message_detail)
    calls = []
    try:
        cf.get_messages = lambda *a, **k: messages
        cf.get_message_detail = lambda *a, **k: {"text": "Your verification code: ABC-123"}
        code = cf.wait_for_code(
            lambda *a, **k: FakeResponse(), "http://mail.example.com", "tok", "test@example.com",
            timeout=2, poll_interval=0.1, on_code_mail=calls.append,
        )
        assert code == "ABC-123" and calls == [7]
    finally:
        cf.get_messages, cf.get_message_detail = original

    deletes = []

    class Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"success": True}

    def fake_delete(url, **kwargs):
        deletes.append((url, kwargs))
        return Resp()

    assert cf.delete_mail(fake_delete, "http://mail.example.com", 42, admin_auth="admin-pass") == {"success": True}
    url, kwargs = deletes[0]
    assert url == "http://mail.example.com/admin/mails/42"
    assert kwargs["headers"]["x-admin-auth"] == "admin-pass"
    assert "Authorization" not in kwargs["headers"]


if __name__ == "__main__":
    test_create_address_collision_retry()
    test_create_address_non_retryable_error()
    test_catchall_email_and_token()
    test_extract_verification_code()
    test_wait_for_code_and_delete_mail()
    print("OK cloudflare_email")
