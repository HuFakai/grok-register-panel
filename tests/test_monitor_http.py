# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import monitor
from webui import email_domain_store
from webui import email_provider_store
from webui import process_utils
from webui import proxy_store


def request(url: str, *, token: str = "", method: str = "GET", body: bytes | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=5)
        return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_proxy_start_prerequisites():
    original = monitor.read_proxy_pool
    original_runtime = monitor._runtime_config
    try:
        monitor._runtime_config = lambda: {}
        monitor.read_proxy_pool = lambda **_kwargs: {
            "summary": {"total": 498, "usable": 0}
        }
        assert "没有健康且启用的代理" in monitor._proxy_prerequisite_error(2)

        monitor.read_proxy_pool = lambda **_kwargs: {
            "summary": {"total": 498, "usable": 1}
        }
        assert "少于并发数 2" in monitor._proxy_prerequisite_error(2)

        monitor.read_proxy_pool = lambda **_kwargs: {
            "summary": {"total": 498, "usable": 2}
        }
        assert monitor._proxy_prerequisite_error(2) is None

        monitor.read_proxy_pool = lambda **_kwargs: {
            "summary": {"total": 0, "usable": 0}
        }
        assert monitor._proxy_prerequisite_error(3) is None

        # 开启本地回退：面板池没有健康代理也允许启动
        monitor._runtime_config = lambda: {"proxy_fallback_to_local": True}
        monitor.read_proxy_pool = lambda **_kwargs: {
            "summary": {"total": 1, "usable": 0}
        }
        assert monitor._proxy_prerequisite_error(3) is None
    finally:
        monitor.read_proxy_pool = original
        monitor._runtime_config = original_runtime


def test_kill_all_verifies_process_exit():
    original_terminate = monitor.terminate_managed_processes
    original_process_running = monitor.process_running
    try:
        monitor.terminate_managed_processes = lambda *_args, **_kwargs: [101, 102]
        monitor.process_running = lambda: {"running": False}
        result = monitor.kill_all()
        assert result["ok"] is True
        assert result["killed"] == [101, 102]

        monitor.process_running = lambda: {
            "running": True,
            "batch_running": True,
            "batch_pid": 102,
        }
        result = monitor.kill_all()
        assert result["ok"] is False
        assert "仍未退出" in result["error"]
    finally:
        monitor.terminate_managed_processes = original_terminate
        monitor.process_running = original_process_running


def test_monitor_http_auth_and_headers():
    token = "test-monitor-token-123456"
    previous = os.environ.get("MONITOR_TOKEN")
    os.environ["MONITOR_TOKEN"] = token
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        status, headers, _ = request(base + "/api/health")
        assert status == 200
        assert headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")

        status, _, body = request(base + "/api/status")
        assert status == 401
        assert json.loads(body)["ok"] is False

        status, _, body = request(base + "/api/status", token=token)
        assert status == 200
        assert "process" in json.loads(body)

        status, _, _ = request(base + "/api/recovery")
        assert status == 401
        status, _, body = request(base + "/api/recovery", token=token)
        assert status == 200
        assert "pending_count" in json.loads(body)

        status, _, body = request(base + "/api/proxies")
        assert status == 401

        status, _, _ = request(
            base + "/api/control",
            method="POST",
            body=b"not-json",
        )
        assert status == 401

        status, _, _ = request(
            base + "/api/control",
            token=token,
            method="POST",
            body=b"not-json",
        )
        assert status == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if previous is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous


def test_proxy_api_auth_mutations_and_redaction():
    token = "test-proxy-token-123456"
    secret = "proxy-secret-value-99"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        proxy_store.STATE_PATH = base_path / "log" / "proxy_pool.json"
        proxy_store.LOCK_PATH = base_path / "log" / "proxy_pool.json.lock"
        proxy_store.LEGACY_PATH = base_path / "proxies.txt"
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            payload = json.dumps(
                {"proxies": f"proxy.example:8080:worker:{secret}"}
            ).encode("utf-8")
            status, _, _ = request(
                base + "/api/proxies/import",
                method="POST",
                body=payload,
            )
            assert status == 401

            status, _, body = request(
                base + "/api/proxies/import",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            imported = json.loads(body)
            assert imported["imported_count"] == 1
            assert secret not in body.decode("utf-8")
            proxy_id = imported["imported_ids"][0]

            status, _, body = request(base + "/api/proxies", token=token)
            assert status == 200
            assert secret not in body.decode("utf-8")
            assert json.loads(body)["items"][0]["has_auth"] is True

            status, _, body = request(
                base + f"/api/proxies/{proxy_id}",
                token=token,
                method="PATCH",
                body=b'{"enabled":false}',
            )
            assert status == 200
            assert json.loads(body)["summary"]["enabled"] == 0

            status, _, body = request(
                base + "/api/proxies?page=1&page_size=25",
                token=token,
            )
            assert status == 200
            page = json.loads(body)
            assert page["pagination"]["page_size"] == 25
            assert page["items"][0]["enabled"] is False

            status, _, _ = request(
                base + f"/api/proxies/{proxy_id}",
                method="DELETE",
            )
            assert status == 401
            status, _, body = request(
                base + f"/api/proxies/{proxy_id}",
                token=token,
                method="DELETE",
            )
            assert status == 200
            assert json.loads(body)["summary"]["total"] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_email_domain_api_auth_and_mutations():
    token = "test-domain-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        email_domain_store.STATE_PATH,
        email_domain_store.LOCK_PATH,
    )
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        email_domain_store.STATE_PATH = base_path / "log" / "email_domain_pool.json"
        email_domain_store.LOCK_PATH = base_path / "log" / "email_domain_pool.json.lock"
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            status, _, _ = request(base + "/api/email-domains")
            assert status == 401

            payload = json.dumps(
                {
                    "provider": "cloudmail",
                    "domains": "mail.example.com\nmail.example.com\nbad-value",
                }
            ).encode("utf-8")
            status, _, _ = request(
                base + "/api/email-domains/import",
                method="POST",
                body=payload,
            )
            assert status == 401
            status, _, body = request(
                base + "/api/email-domains/import",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            imported = json.loads(body)
            assert imported["imported_count"] == 1
            assert imported["duplicate_count"] == 1
            assert len(imported["errors"]) == 1
            domain_id = imported["items"][0]["id"]

            status, _, body = request(base + "/api/email-domains", token=token)
            assert status == 200
            assert json.loads(body)["items"][0]["provider"] == "cloudmail"

            status, _, body = request(
                base + "/api/email-domains/settings",
                token=token,
                method="POST",
                body=b'{"failure_threshold":2,"max_active_domains":1}',
            )
            assert status == 200
            assert json.loads(body)["settings"]["failure_threshold"] == 2

            status, _, body = request(
                base + f"/api/email-domains/{domain_id}",
                token=token,
                method="PATCH",
                body=b'{"enabled":false}',
            )
            assert status == 200
            assert json.loads(body)["items"][0]["enabled"] is False

            status, _, body = request(
                base + "/api/email-domains/reset",
                token=token,
                method="POST",
                body=json.dumps({"id": domain_id}).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["items"][0]["consecutive_rejections"] == 0

            status, _, _ = request(
                base + f"/api/email-domains/{domain_id}",
                method="DELETE",
            )
            assert status == 401
            status, _, body = request(
                base + f"/api/email-domains/{domain_id}",
                token=token,
                method="DELETE",
            )
            assert status == 200
            assert json.loads(body)["summary"]["total"] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            email_domain_store.STATE_PATH, email_domain_store.LOCK_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_email_provider_api_auth_secret_masking_and_probe():
    token = "test-email-provider-token-123456"
    secret = "provider-secret-value"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        email_provider_store.CONFIG_PATH,
        email_provider_store.LOCK_PATH,
    )
    previous_test = monitor.test_email_provider_config
    calls = []
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        email_provider_store.CONFIG_PATH = base_path / "config.json"
        email_provider_store.LOCK_PATH = base_path / "config.json.lock"

        def fake_test(provider, settings, *, clear_secrets=None):
            calls.append((provider, settings, clear_secrets))
            return {
                "ok": True,
                "provider": provider,
                "provider_label": "CloudMail",
                "detail": "CloudMail HTTP 200",
                "checked_at": "2026-07-31T00:00:00Z",
            }

        monitor.test_email_provider_config = fake_test
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        payload = json.dumps(
            {
                "provider": "cloudmail",
                "settings": {
                    "cloudmail_url": "https://mail.example.com",
                    "cloudmail_admin_email": "admin@example.com",
                    "cloudmail_password": secret,
                    "defaultDomains": "mail.example.com",
                },
            }
        ).encode("utf-8")
        try:
            status, _, _ = request(base + "/api/email-provider")
            assert status == 401
            status, _, _ = request(
                base + "/api/email-provider",
                method="POST",
                body=payload,
            )
            assert status == 401

            status, _, body = request(
                base + "/api/email-provider",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            assert secret not in body.decode("utf-8")
            saved = json.loads(body)
            assert saved["provider"] == "cloudmail"
            assert saved["secret_configured"]["cloudmail_password"] is True

            status, _, body = request(base + "/api/email-provider", token=token)
            assert status == 200
            assert secret not in body.decode("utf-8")
            assert json.loads(body)["values"]["cloudmail_password"] == ""

            status, _, body = request(
                base + "/api/email-provider/test",
                token=token,
                method="POST",
                body=json.dumps(
                    {
                        "provider": "cloudmail",
                        "settings": {"cloudmail_password": ""},
                    }
                ).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["detail"] == "CloudMail HTTP 200"
            assert calls == [("cloudmail", {"cloudmail_password": ""}, None)]

            status, _, _ = request(
                base + "/api/email-provider",
                token=token,
                method="POST",
                body=b'{"provider":"cloudmail","settings":{"proxy":"bad"}}',
            )
            assert status == 400
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            monitor.test_email_provider_config = previous_test
            email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_non_loopback_requires_token():
    env = dict(os.environ)
    env.pop("MONITOR_TOKEN", None)
    env["MONITOR_HOST"] = "192.0.2.10"
    env["MONITOR_PORT"] = "0"
    result = subprocess.run(
        [sys.executable, "-m", "webui.monitor"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "MONITOR_TOKEN is required" in (result.stdout + result.stderr)


def test_log_cleanup_api_requires_auth_and_returns_summary():
    token = "test-log-cleanup-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_cleanup = monitor.cleanup_old_logs
    calls = []

    def fake_cleanup(days):
        calls.append(days)
        if int(days) < 1:
            raise ValueError("日志保留天数必须在 1-365 天之间")
        return {
            "ok": True,
            "retention_days": int(days),
            "deleted_count": 2,
            "freed_bytes": 4096,
            "deleted": ["old-a.log", "old-b.log"],
            "errors": [],
        }

    os.environ["MONITOR_TOKEN"] = token
    monitor.cleanup_old_logs = fake_cleanup
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        status, _, _ = request(
            base + "/api/logs/cleanup",
            method="POST",
            body=b'{"retention_days":7}',
        )
        assert status == 401

        status, _, body = request(
            base + "/api/logs/cleanup",
            token=token,
            method="POST",
            body=b'{"retention_days":7}',
        )
        payload = json.loads(body)
        assert status == 200
        assert payload["deleted_count"] == 2
        assert calls == [7]

        status, _, body = request(
            base + "/api/logs/cleanup",
            token=token,
            method="POST",
            body=b'{"retention_days":0}',
        )
        assert status == 400
        assert "1-365" in json.loads(body)["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        monitor.cleanup_old_logs = previous_cleanup
        if previous_token is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous_token


def test_start_reports_unavailable_process_table():
    token = "test-runtime-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_find = monitor.find_managed_processes

    def unavailable(*_args, **_kwargs):
        raise process_utils.ProcessInspectionError(
            "无法读取系统进程列表；Linux 容器请确认 /proc 已挂载"
        )

    os.environ["MONITOR_TOKEN"] = token
    monitor.find_managed_processes = unavailable
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = request(
            f"http://127.0.0.1:{server.server_port}/api/start",
            token=token,
            method="POST",
            body=b"{}",
        )
        payload = json.loads(body)
        assert status == 500
        assert "/proc" in payload["error"]
        assert "已挂载" in payload["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        monitor.find_managed_processes = previous_find
        if previous_token is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous_token


def test_ip_usage_api_delete_and_per_ip_limit():
    import browser_session
    import ip_usage_store

    token = "test-ip-usage-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_file = ip_usage_store._USAGE_FILE
    previous_lookup = browser_session.lookup_exit_meta
    previous_control = monitor.load_control
    with tempfile.TemporaryDirectory() as temp:
        ip_usage_store._USAGE_FILE = Path(temp) / "log" / "ip_usage.json"
        browser_session.lookup_exit_meta = lambda ip: {
            "status": "success",
            "country": "美国",
            "isp": "TEST ISP",
            "org": "TEST ORG",
            "as": "AS12345",
        }
        # 隔离全局上限：真实 control 文件可能设置了 ip_usage_limit
        monitor.load_control = lambda: {"ip_usage_limit": 0}
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            ip_usage_store.record_ip_usage("203.0.113.7", times=3)
            ip_usage_store.record_ip_usage("203.0.113.8", times=1)

            status, _, _ = request(base + "/api/ip-usage")
            assert status == 401
            status, _, body = request(base + "/api/ip-usage", token=token)
            assert status == 200
            payload = json.loads(body)
            items = {it["ip"]: it for it in payload["items"]}
            assert payload["total_usage"] == 4
            assert items["203.0.113.7"]["count"] == 3
            assert items["203.0.113.7"]["meta"]["country"] == "美国"
            assert items["203.0.113.7"]["meta"]["asn"] == "AS12345"
            # 未设置覆盖 → limit None，生效值回退全局（0=不限）
            assert items["203.0.113.7"]["limit"] is None
            assert items["203.0.113.7"]["limit_effective"] == 0

            # 每 IP 上限：设置 → 生效值优先；清除 → 回退全局
            status, _, _ = request(
                base + "/api/ip-usage/limit",
                method="POST",
                body=json.dumps({"ip": "203.0.113.7", "limit": 5}).encode("utf-8"),
            )
            assert status == 401
            status, _, body = request(
                base + "/api/ip-usage/limit",
                token=token,
                method="POST",
                body=json.dumps({"ip": "203.0.113.7", "limit": 5}).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["limit"] == 5
            status, _, body = request(base + "/api/ip-usage", token=token)
            items = {it["ip"]: it for it in json.loads(body)["items"]}
            assert items["203.0.113.7"]["limit"] == 5
            assert items["203.0.113.7"]["limit_effective"] == 5

            # 删除单条
            status, _, _ = request(
                base + "/api/ip-usage/delete",
                method="POST",
                body=json.dumps({"ip": "203.0.113.7"}).encode("utf-8"),
            )
            assert status == 401
            status, _, body = request(
                base + "/api/ip-usage/delete",
                token=token,
                method="POST",
                body=json.dumps({"ip": "203.0.113.7"}).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["deleted"] is True
            status, _, body = request(base + "/api/ip-usage", token=token)
            payload = json.loads(body)
            ips = [it["ip"] for it in payload["items"]]
            assert "203.0.113.7" not in ips
            assert "203.0.113.8" in ips

            # 参数校验：缺 ip / 非法 limit
            status, _, body = request(
                base + "/api/ip-usage/delete",
                token=token,
                method="POST",
                body=b"{}",
            )
            assert status == 400
            status, _, body = request(
                base + "/api/ip-usage/limit",
                token=token,
                method="POST",
                body=json.dumps({"ip": "203.0.113.8", "limit": "abc"}).encode("utf-8"),
            )
            assert status == 400
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            ip_usage_store._USAGE_FILE = previous_file
            browser_session.lookup_exit_meta = previous_lookup
            monitor.load_control = previous_control
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


if __name__ == "__main__":
    test_proxy_start_prerequisites()
    test_kill_all_verifies_process_exit()
    test_monitor_http_auth_and_headers()
    test_proxy_api_auth_mutations_and_redaction()
    test_email_domain_api_auth_and_mutations()
    test_email_provider_api_auth_secret_masking_and_probe()
    test_non_loopback_requires_token()
    test_log_cleanup_api_requires_auth_and_returns_summary()
    test_start_reports_unavailable_process_table()
    test_ip_usage_api_delete_and_per_ip_limit()
    print("OK monitor http")
