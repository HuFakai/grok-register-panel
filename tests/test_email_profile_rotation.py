# -*- coding: utf-8 -*-
"""邮箱多配置档运行时轮换：round-robin 选档、字段回退、email→profile 映射。"""
from __future__ import annotations

from pathlib import Path
import sys
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as app

FAKE_PROFILES = [
    {
        "id": "profile-a",
        "provider": "cloudmail",
        "name": "A",
        "fields": {
            "cloudmail_url": "https://mail-a.example.com",
            "cloudmail_admin_email": "admin@example.com",
            "cloudmail_password": "secret-a",
            "defaultDomains": "mail-a.example.com",
        },
    },
    {
        "id": "profile-b",
        "provider": "moemail",
        "name": "B",
        "fields": {
            "moemail_api_base": "https://mail-b.example.com",
            "moemail_api_key": "key-b",
        },
    },
]


def test_round_robin_selection_and_field_fallback():
    old_active = app._email_active_profile
    old_config = dict(app.config)
    old_idx = app._email_profile_rr_idx
    try:
        app._email_active_profile = None
        app._email_profile_rr_idx = 0
        with mock.patch(
            "webui.email_provider_store.get_enabled_email_profiles",
            return_value=FAKE_PROFILES,
        ):
            first = app._pick_email_profile()
            second = app._pick_email_profile()
            third = app._pick_email_profile()
        assert first["id"] == "profile-a"
        assert second["id"] == "profile-b"
        assert third["id"] == "profile-a"  # round-robin 循环

        # profile 字段优先于顶层 config
        app.config["moemail_api_key"] = "top-level-key"
        app._email_active_profile = FAKE_PROFILES[1]
        assert app.get_moemail_api_key() == "key-b"
        assert app.get_moemail_api_base() == "https://mail-b.example.com"

        # 无启用 profiles → 回退顶层 config
        app._email_active_profile = None
        assert app.get_moemail_api_key() == "top-level-key"

        # 顶层有值但 profile 缺该字段时回退顶层
        app.config["moemail_domain"] = "fallback.example.com"
        app._email_active_profile = {
            "id": "x",
            "provider": "moemail",
            "fields": {"moemail_api_key": "k"},
        }
        assert app.get_moemail_domain() == "fallback.example.com"
    finally:
        app._email_active_profile = old_active
        app._email_profile_rr_idx = old_idx
        app.config.clear()
        app.config.update(old_config)


def test_email_to_profile_mapping_for_code_lookup():
    old_active = app._email_active_profile
    old_map = dict(app._email_to_profile)
    try:
        app._email_active_profile = None
        app._email_to_profile["user@example.com"] = "profile-b"
        with mock.patch(
            "webui.email_provider_store.get_enabled_email_profiles",
            return_value=FAKE_PROFILES,
        ):
            app._use_email_profile(app._email_to_profile["user@example.com"])
            assert app._email_active_profile["id"] == "profile-b"

            # 未知 profile id → 回退 None（顶层单配置）
            app._use_email_profile("missing")
            assert app._email_active_profile is None

            # 停用的 profile 不会恢复（get_enabled 只返回启用档）
            with mock.patch(
                "webui.email_provider_store.get_enabled_email_profiles",
                return_value=FAKE_PROFILES[:1],
            ):
                app._use_email_profile("profile-b")
                assert app._email_active_profile is None
    finally:
        app._email_active_profile = old_active
        app._email_to_profile.clear()
        app._email_to_profile.update(old_map)


def test_get_email_and_token_records_mapping():
    old_active = app._email_active_profile
    old_map = dict(app._email_to_profile)
    try:
        app._email_active_profile = None
        app._email_to_profile.clear()
        with mock.patch(
            "webui.email_provider_store.get_enabled_email_profiles",
            return_value=FAKE_PROFILES[:1],
        ), mock.patch.object(
            app, "cloudmail_get_email_and_token", return_value=("made@mail-a.example.com", "tok")
        ):
            email, _token = app.get_email_and_token()
            # 建号后记录 email→profile 映射，取验证码时恢复同一档
            assert app._email_to_profile.get(email) == "profile-a"
            app._email_active_profile = None
            app._use_email_profile(app._email_to_profile.get(email))
            assert app._email_active_profile["id"] == "profile-a"
    finally:
        app._email_active_profile = old_active
        app._email_to_profile.clear()
        app._email_to_profile.update(old_map)


if __name__ == "__main__":
    test_round_robin_selection_and_field_fallback()
    test_email_to_profile_mapping_for_code_lookup()
    test_get_email_and_token_records_mapping()
    print("OK email profile rotation")
