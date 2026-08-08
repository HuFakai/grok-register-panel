# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json
from webui import email_provider_store


class IsolatedConfig:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.previous = (
            email_provider_store.CONFIG_PATH,
            email_provider_store.LOCK_PATH,
        )
        email_provider_store.CONFIG_PATH = base / "config.json"
        email_provider_store.LOCK_PATH = base / "config.json.lock"
        return email_provider_store.CONFIG_PATH

    def __exit__(self, exc_type, exc, tb):
        email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = self.previous
        self.temp.cleanup()


def assert_config_error(callback):
    try:
        callback()
    except email_provider_store.EmailProviderConfigError:
        return
    raise AssertionError("expected EmailProviderConfigError")


def test_provider_schema_and_defaults():
    with IsolatedConfig():
        state = email_provider_store.read_email_provider_config()
        assert state["ok"] is True
        assert state["provider"] == "cloudflare"
        assert state["config_exists"] is False
        providers = {item["id"]: item for item in state["providers"]}
        assert set(providers) == {
            "cloudflare",
            "duckmail",
            "yyds",
            "mailnest",
            "cloudmail",
            "moemail",
        }
        assert providers["duckmail"]["configured"] is True
        assert providers["cloudmail"]["configured"] is False
        assert any(
            field["name"] == "cloudmail_password" and field["secret"] is True
            for field in providers["cloudmail"]["fields"]
        )


def test_secret_masking_preservation_clear_and_private_file():
    with IsolatedConfig() as config_path:
        atomic_write_json(config_path, {"unrelated_setting": 42})
        saved = email_provider_store.save_email_provider_config(
            "cloudmail",
            {
                "cloudmail_url": "https://mail.example.com/",
                "cloudmail_admin_email": "admin@example.com",
                "cloudmail_password": "test-password-value",
                "defaultDomains": "Mail.Example.com, mail.example.com",
            },
        )
        assert saved["provider"] == "cloudmail"
        assert saved["configured"] is True
        assert saved["values"]["cloudmail_password"] == ""
        assert saved["secret_configured"]["cloudmail_password"] is True
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        assert raw["cloudmail_password"] == "test-password-value"
        assert raw["cloudmail_url"] == "https://mail.example.com"
        assert raw["defaultDomains"] == "mail.example.com"
        assert raw["unrelated_setting"] == 42
        if os.name == "posix":
            assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
            assert stat.S_IMODE(email_provider_store.LOCK_PATH.stat().st_mode) == 0o600

        email_provider_store.save_email_provider_config(
            "cloudmail",
            {
                "cloudmail_url": "https://mail-two.example.com",
                "cloudmail_admin_email": "admin@example.com",
                "cloudmail_password": "",
                "defaultDomains": "mail.example.com",
            },
        )
        preserved = json.loads(config_path.read_text(encoding="utf-8"))
        assert preserved["cloudmail_password"] == "test-password-value"

        cleared = email_provider_store.save_email_provider_config(
            "cloudmail",
            {},
            clear_secrets=["cloudmail_password"],
        )
        assert cleared["secret_configured"]["cloudmail_password"] is False
        assert cleared["configured"] is False


def test_validation_rejects_unknown_fields_and_unsafe_values():
    with IsolatedConfig():
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudflare", {"proxy": "http://not-allowed.example"}
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudflare",
                {"cloudflare_api_base": "https://user:pass@mail.example.com"},
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudflare", {"cloudflare_path_accounts": "accounts"}
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudmail", {"defaultDomains": "https://mail.example.com"}
            )
        )


def test_connectivity_uses_unsaved_form_and_preserves_saved_secret():
    class Response:
        status_code = 200

    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    with IsolatedConfig() as config_path:
        email_provider_store.save_email_provider_config(
            "yyds", {"yyds_api_key": "saved-test-key", "yyds_jwt": ""}
        )
        before = config_path.read_text(encoding="utf-8")
        result = email_provider_store.test_email_provider_config(
            "yyds",
            {"yyds_api_key": "", "yyds_jwt": "", "yyds_default_domain": ""},
            http_get=fake_get,
            http_post=lambda *_args, **_kwargs: Response(),
        )
        assert result["ok"] is True
        assert result["provider"] == "yyds"
        assert calls[0][0].endswith("/v1/domains")
        assert calls[0][1]["headers"]["X-API-Key"] == "saved-test-key"
        assert config_path.read_text(encoding="utf-8") == before


def test_cloudflare_connectivity_uses_configured_port():
    import connectivity

    calls = []
    previous_tcp_open = connectivity._tcp_open
    connectivity._tcp_open = lambda host, port: calls.append((host, port)) or True
    try:
        result = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "http://mail.example.com:8793",
                "cloudflare_auth_mode": "none",
            },
            lambda *_args, **_kwargs: None,
            lambda *_args, **_kwargs: None,
        )
    finally:
        connectivity._tcp_open = previous_tcp_open

    assert result[1] is True
    assert calls == [("mail.example.com", 8793)]


class IsolatedProfiles:
    """把 profiles 存储隔离到临时目录（不污染真实 log/）。"""

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.previous = (
            email_provider_store.PROFILES_PATH,
            email_provider_store.PROFILES_LOCK_PATH,
        )
        email_provider_store.PROFILES_PATH = base / "log" / "email_provider_profiles.json"
        email_provider_store.PROFILES_LOCK_PATH = email_provider_store.PROFILES_PATH.with_suffix(
            ".lock"
        )
        return email_provider_store.PROFILES_PATH

    def __exit__(self, exc_type, exc, tb):
        email_provider_store.PROFILES_PATH, email_provider_store.PROFILES_LOCK_PATH = self.previous
        self.temp.cleanup()


def _cloudmail_fields(url="https://mail.example.com"):
    return {
        "cloudmail_url": url,
        "cloudmail_admin_email": "admin@example.com",
        "cloudmail_password": "secret-value",
        "defaultDomains": "mail.example.com, inbox.example.net",
    }


def test_profiles_crud_enable_and_secret_preservation():
    with IsolatedProfiles() as profiles_path:
        # 初始为空
        state = email_provider_store.list_email_profiles()
        assert state["summary"] == {"total": 0, "enabled": 0}

        first = email_provider_store.save_email_profile(
            "cloudmail", _cloudmail_fields(), name="主号"
        )
        first_id = first["profile"]["id"]
        assert first["profile"]["name"] == "主号"
        assert first["profile"]["configured"] is True
        assert first["profile"]["secret_configured"]["cloudmail_password"] is True
        assert first["profile"]["values"]["cloudmail_password"] == ""

        second = email_provider_store.save_email_profile(
            "moemail",
            {
                "moemail_api_base": "https://mail-two.example.com",
                "moemail_api_key": "key-two",
            },
            name="",
        )
        second_id = second["profile"]["id"]
        assert second["profile"]["name"] == "MoeMail 配置"  # 名称缺省自动生成

        state = email_provider_store.list_email_profiles()
        assert state["summary"] == {"total": 2, "enabled": 2}

        # 更新：留空 secret 保留原值；显式 clear_secrets 清除
        email_provider_store.save_email_profile(
            "cloudmail",
            {"cloudmail_admin_email": "boss@example.com"},
            profile_id=first_id,
            name="主号改名",
        )
        state = email_provider_store.list_email_profiles()
        profile = next(p for p in state["profiles"] if p["id"] == first_id)
        assert profile["name"] == "主号改名"
        assert profile["secret_configured"]["cloudmail_password"] is True
        raw = json.loads(profiles_path.read_text(encoding="utf-8"))
        stored = next(p for p in raw["profiles"] if p["id"] == first_id)
        assert stored["fields"]["cloudmail_password"] == "secret-value"

        email_provider_store.save_email_profile(
            "cloudmail",
            {},
            profile_id=first_id,
            clear_secrets=["cloudmail_password"],
        )
        state = email_provider_store.list_email_profiles()
        profile = next(p for p in state["profiles"] if p["id"] == first_id)
        assert profile["secret_configured"]["cloudmail_password"] is False
        assert profile["configured"] is False

        # 停用后运行时列表只返回启用的
        email_provider_store.set_email_profile_enabled(second_id, False)
        enabled = email_provider_store.get_enabled_email_profiles()
        assert [p["id"] for p in enabled] == [first_id]
        email_provider_store.set_email_profile_enabled(second_id, True)
        enabled = email_provider_store.get_enabled_email_profiles()
        assert [p["id"] for p in enabled] == [first_id, second_id]
        assert enabled[1]["fields"]["moemail_api_key"] == "key-two"

        # 删除
        assert email_provider_store.delete_email_profile(first_id) is True
        assert email_provider_store.delete_email_profile(first_id) is False
        state = email_provider_store.list_email_profiles()
        assert state["summary"]["total"] == 1

        # 文件权限
        if os.name == "posix":
            assert stat.S_IMODE(profiles_path.stat().st_mode) == 0o600


def test_profiles_validation_and_errors():
    with IsolatedProfiles():
        assert_config_error(
            lambda: email_provider_store.save_email_profile(
                "cloudflare", {"proxy": "http://not-allowed.example"}
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_profile("unknown", {})
        )
        assert_config_error(
            lambda: email_provider_store.delete_email_profile("missing-id")
            or email_provider_store.set_email_profile_enabled("missing-id", True)
        )
        assert_config_error(
            lambda: email_provider_store.test_email_profile("missing-id")
        )


def test_profiles_do_not_touch_legacy_config():
    """profiles 操作不得改动顶层 config.json（旧单配置完全独立）。"""
    with IsolatedProfiles():
        with IsolatedConfig() as config_path:
            email_provider_store.save_email_provider_config(
                "cloudmail", _cloudmail_fields()
            )
            before = config_path.read_text(encoding="utf-8")
            email_provider_store.save_email_profile("moemail", {"moemail_api_key": "k"})
            assert config_path.read_text(encoding="utf-8") == before
            assert email_provider_store.list_email_profiles()["has_legacy_config"] is True


if __name__ == "__main__":
    test_provider_schema_and_defaults()
    test_secret_masking_preservation_clear_and_private_file()
    test_validation_rejects_unknown_fields_and_unsafe_values()
    test_connectivity_uses_unsaved_form_and_preserves_saved_secret()
    test_cloudflare_connectivity_uses_configured_port()
    test_profiles_crud_enable_and_secret_preservation()
    test_profiles_validation_and_errors()
    test_profiles_do_not_touch_legacy_config()
    print("OK email provider store")
