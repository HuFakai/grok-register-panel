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
    secret = "d427bf9e533472c4d1fc175e0d29fbf7387a0b88ca0d4f508cc2a3026b5e78c0"
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
        app.config["defaultDomains"] = "email.example.com"
        app.config["cloudflare_jwt_secret"] = "secret-abc"
        addr, jwt = app.cloudflare_catchall_email_and_token("secret-abc")
        assert addr.endswith("@email.example.com"), f"域名错误: {addr}"
        assert jwt.startswith("eyJ")  # JWT 头
        payload = _decode_payload(jwt)
        assert payload["address"] == addr
        assert payload["address_id"] == 0
        # 指定域名优先
        addr2, _ = app.cloudflare_catchall_email_and_token("secret-abc", domain="mail.example.com")
        assert addr2.endswith("@mail.example.com")
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


if __name__ == "__main__":
    test_sign_cloudflare_address_jwt_format()
    test_catchall_email_and_token()
    test_get_email_and_token_prefers_catchall_then_falls_back()
    print("OK cloudflare catchall")
