# -*- coding: utf-8 -*-
"""Cloudflare catch-all 免建号：自签 JWT 与随机地址生成。"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as app


def _decode_payload(jwt: str) -> dict:
    part = jwt.split(".")[1]
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def test_sign_cloudflare_address_jwt_format():
    secret = "test-secret-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    jwt = app._sign_cloudflare_address_jwt(secret, "test@example.com", 7)
    parts = jwt.split(".")
    assert len(parts) == 3, "JWT 应为三段"
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8"))
    assert header["alg"] == "HS256"
    payload = _decode_payload(jwt)
    assert payload["address"] == "test@example.com"
    assert payload["address_id"] == 7
    # 同一输入签名稳定
    jwt2 = app._sign_cloudflare_address_jwt(secret, "test@example.com", 7)
    assert jwt == jwt2


def test_catchall_email_and_token():
    old = dict(app.config)
    try:
        app.config["defaultDomains"] = "example.com"
        app.config["cloudflare_jwt_secret"] = "secret-abc"
        addr, jwt = app.cloudflare_catchall_email_and_token("secret-abc")
        # 随机账号 + 随机子域：user@sub.example.com（不局限于单一子域）
        assert addr.count("@") == 1
        local, domain = addr.split("@")
        assert local, "随机账号不能为空"
        assert domain.endswith(".example.com"), f"应为根域下随机子域: {addr}"
        assert domain != "example.com", "应带随机子域，而非根域"
        assert jwt.startswith("eyJ")  # JWT 头
        payload = _decode_payload(jwt)
        assert payload["address"] == addr
        assert payload["address_id"] == 0
        # 连续两次生成应得到不同子域（随机性）
        addr2, _ = app.cloudflare_catchall_email_and_token("secret-abc")
        assert addr2.split("@")[1] != domain, "子域应随机变化"
    finally:
        app.config.clear()
        app.config.update(old)


def test_get_email_and_token_prefers_catchall_then_falls_back():
    """配置了 jwt_secret → 免建号优先；免建号异常 → 回退 admin 建号。"""
    old = dict(app.config)
    originals = {
        "get_cloudflare_api_base": app.get_cloudflare_api_base,
        "cloudflare_create_temp_address": app.cloudflare_create_temp_address,
        "cloudflare_catchall_email_and_token": app.cloudflare_catchall_email_and_token,
    }
    try:
        app.config["email_provider"] = "cloudflare"
        app.config["defaultDomains"] = "email.example.com"
        app.config["cloudflare_jwt_secret"] = "secret-abc"
        app.config["cloudflare_api_base"] = "http://mail.example.com"

        # 免建号成功：不调用 admin 建号
        app.cloudflare_catchall_email_and_token = lambda secret, domain="": (
            "random@email.example.com", "jwt-token"
        )
        app.cloudflare_create_temp_address = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("不应调用 admin 建号")
        )
        addr, jwt = app.get_email_and_token()
        assert addr == "random@email.example.com"
        assert jwt == "jwt-token"

        # 免建号异常 → 回退 admin 建号
        def boom(secret, domain=""):
            raise RuntimeError("catch-all down")

        app.cloudflare_catchall_email_and_token = boom
        app.cloudflare_create_temp_address = lambda api_base, domain="": (
            "made@email.example.com", "admin-jwt"
        )
        addr, jwt = app.get_email_and_token()
        assert addr == "made@email.example.com"
        assert jwt == "admin-jwt"

        # 未配置 jwt_secret → 直接 admin 建号
        app.config["cloudflare_jwt_secret"] = ""
        addr, jwt = app.get_email_and_token()
        assert addr == "made@email.example.com"
    finally:
        app.config.clear()
        app.config.update(old)
        for name, value in originals.items():
            setattr(app, name, value)


def test_delete_mail_endpoint_and_auth():
    """DELETE /admin/mails/{id} + x-admin-auth 管理员密码。"""
    calls = []

    class Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"success": True}

    def fake_delete(url, **kwargs):
        calls.append((url, kwargs))
        return Resp()

    result = app.cloudflare_provider.delete_mail(
        fake_delete,
        "http://mail.example.com",
        42,
        admin_auth="admin-pass",
        custom_auth="",
    )
    assert result == {"success": True}
    url, kwargs = calls[0]
    assert url == "http://mail.example.com/admin/mails/42"
    assert kwargs["headers"]["x-admin-auth"] == "admin-pass"
    assert "Authorization" not in kwargs["headers"]


def test_wait_for_code_triggers_on_code_mail():
    """提取到验证码时回调删除（拿到 mail_id），失败不阻塞返回验证码。"""
    import email_providers.cloudflare as cf

    calls = []

    class Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return []

    def fake_get(url, **kwargs):
        return Resp()

    def no_sleep(*_a, **_k):
        return None

    def no_cancel():
        return False

    messages = [
        {
            "id": 7,
            "address": "test@example.com",
            "to": [{"address": "test@example.com"}],
            "subject": "Verification",
            "text": "Your verification code: ABC-123",
        }
    ]

    def fake_messages(http_get, api_base, token, **kw):
        return messages

    original_get_messages = cf.get_messages
    original_get_detail = cf.get_message_detail
    cf.get_messages = fake_messages
    cf.get_message_detail = lambda *a, **k: {"text": "Your verification code: ABC-123"}
    try:
        code = cf.wait_for_code(
            fake_get,
            "http://mail.example.com",
            "tok",
            "test@example.com",
            timeout=2,
            poll_interval=0.1,
            raise_if_cancelled=lambda cb: None,
            sleep_with_cancel=no_sleep,
            cancel_callback=no_cancel,
            on_code_mail=lambda mid: calls.append(mid),
        )
        assert code == "ABC-123"
        assert calls == [7], f"on_code_mail 应收到 mail_id=7: {calls}"
    finally:
        cf.get_messages = original_get_messages
        cf.get_message_detail = original_get_detail


if __name__ == "__main__":
    test_sign_cloudflare_address_jwt_format()
    test_catchall_email_and_token()
    test_get_email_and_token_prefers_catchall_then_falls_back()
    test_delete_mail_endpoint_and_auth()
    test_wait_for_code_triggers_on_code_mail()
    print("OK cloudflare catchall")
