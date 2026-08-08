# -*- coding: utf-8 -*-
"""配置一键导出/导入：往返一致、0600 权限、API 鉴权与版本校验。"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import config_backup
from webui import email_domain_store, email_provider_store, monitor, proxy_store
from ip_usage_store import usage_file_path


class IsolatedEnv:
    """把全部配置路径隔离到临时目录（不触碰真实配置）。"""

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.previous = (
            config_backup.ROOT,
            proxy_store.STATE_PATH,
            email_domain_store.STATE_PATH,
            email_provider_store.PROFILES_PATH,
            monitor.CONTROL_FILE,
            usage_file_path(),
        )
        config_backup.ROOT = base
        proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
        email_domain_store.STATE_PATH = base / "log" / "email_domain_pool.json"
        email_provider_store.PROFILES_PATH = base / "log" / "email_provider_profiles.json"
        monitor.CONTROL_FILE = base / "log" / "monitor_control.json"
        import ip_usage_store

        ip_usage_store._USAGE_FILE = base / "log" / "ip_usage.json"
        return base

    def __exit__(self, exc_type, exc, tb):
        import ip_usage_store

        (
            config_backup.ROOT,
            proxy_store.STATE_PATH,
            email_domain_store.STATE_PATH,
            email_provider_store.PROFILES_PATH,
            monitor.CONTROL_FILE,
            ip_usage_store._USAGE_FILE,
        ) = self.previous
        self.temp.cleanup()


def _write(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def test_export_import_round_trip_and_private_files():
    with IsolatedEnv() as base:
        # 预置各段配置
        _write(base / "config.json", {"email_provider": "cloudflare", "cloudflare_api_key": "s1"})
        _write(base / "log" / "proxy_pool.json", {"version": 1, "items": [{"url": "http://p:1", "enabled": True}]})
        _write(base / "log" / "email_domain_pool.json", {"items": [{"domain": "mail.example.com"}]})
        _write(base / "log" / "email_provider_profiles.json", {"profiles": [{"id": "a", "fields": {"k": "v"}}]})
        _write(base / "log" / "monitor_control.json", {"workers": 3, "base_ok": 5})
        _write(base / "log" / "ip_usage.json", {"counts": {"1.1.1.1": 2}, "limits": {}})

        exported = config_backup.export_all()
        assert exported["version"] == 1
        assert exported["config"]["cloudflare_api_key"] == "s1"
        assert exported["proxy_pool"]["items"][0]["url"] == "http://p:1"
        assert exported["monitor_control"]["base_ok"] == 5
        assert exported["ip_usage"]["counts"]["1.1.1.1"] == 2
        assert set(exported) >= {"config", "proxy_pool", "email_domain_pool",
                                 "email_provider_profiles", "monitor_control", "ip_usage"}

        # 模拟换环境：清空后导入
        for f in (base / "config.json", base / "log" / "proxy_pool.json",
                  base / "log" / "email_domain_pool.json",
                  base / "log" / "email_provider_profiles.json",
                  base / "log" / "monitor_control.json", base / "log" / "ip_usage.json"):
            f.unlink(missing_ok=True)

        result = config_backup.import_all(exported)
        assert result["ok"] is True
        assert set(result["written"]) == {"config", "proxy_pool", "email_domain_pool",
                                          "email_provider_profiles", "monitor_control", "ip_usage"}

        re_exported = config_backup.export_all()
        for section in ("config", "proxy_pool", "email_domain_pool",
                        "email_provider_profiles", "monitor_control", "ip_usage"):
            assert re_exported[section] == exported[section], f"{section} 往返不一致"

        # 0600 权限
        for f in (base / "config.json", base / "log" / "proxy_pool.json",
                  base / "log" / "monitor_control.json"):
            if os.name == "posix":
                assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_import_validation():
    with IsolatedEnv():
        # 非 dict
        try:
            config_backup.import_all([])
            raise AssertionError("应拒绝非 dict")
        except ValueError:
            pass
        # 版本不匹配
        try:
            config_backup.import_all({"version": 999, "config": {}})
            raise AssertionError("应拒绝未知版本")
        except ValueError as e:
            assert "版本" in str(e)


def test_config_backup_api_auth_and_round_trip():
    token = "test-config-backup-token-123"
    previous_token = os.environ.get("MONITOR_TOKEN")
    os.environ["MONITOR_TOKEN"] = token
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        def req(path, method="GET", body=None, token=token):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            if body is not None:
                headers["Content-Type"] = "application/json"
            r = urllib.request.Request(base + path, method=method, data=body, headers=headers)
            try:
                with urllib.request.urlopen(r, timeout=5) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        status, _ = req("/api/config/export", token=None)
        assert status == 401, "无 token 应 401"
        status, data = req("/api/config/export", method="GET")
        assert status == 200
        assert data["version"] == 1
        assert "config" in data and "proxy_pool" in data

        # 导入（含版本校验）
        status, result = req("/api/config/import", method="POST", token=None,
                             body=json.dumps({"version": 999}).encode("utf-8"))
        assert status == 401
        status, result = req("/api/config/import", method="POST",
                             body=json.dumps({"version": 999}).encode("utf-8"))
        assert status == 400
        status, result = req("/api/config/import", method="POST",
                             body=json.dumps(data).encode("utf-8"))
        assert status == 200
        assert result["ok"] is True
        assert "config" in result["written"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if previous_token is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous_token


if __name__ == "__main__":
    test_export_import_round_trip_and_private_files()
    test_import_validation()
    test_config_backup_api_auth_and_round_trip()
    print("OK config backup")
