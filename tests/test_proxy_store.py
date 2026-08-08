# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import stat
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import proxy_store


class IsolatedStore:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.previous = (
            proxy_store.STATE_PATH,
            proxy_store.LOCK_PATH,
            proxy_store.LEGACY_PATH,
        )
        proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
        proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
        proxy_store.LEGACY_PATH = base / "proxies.txt"
        return base

    def __exit__(self, exc_type, exc, tb):
        proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = self.previous
        self.temp.cleanup()


def test_normalize_proxy_formats_and_rejects_paths():
    assert proxy_store.normalize_proxy("proxy.example:8080") == "http://proxy.example:8080"
    assert (
        proxy_store.normalize_proxy("proxy.example:8080:user:pass")
        == "http://user:pass@proxy.example:8080"
    )
    assert (
        proxy_store.normalize_proxy("HTTP://User:p%40ss@PROXY.EXAMPLE:8080/")
        == "http://User:p%40ss@proxy.example:8080"
    )
    try:
        proxy_store.normalize_proxy("http://proxy.example:8080/path")
    except proxy_store.ProxyValidationError:
        pass
    else:
        raise AssertionError("proxy paths must be rejected")
    assert proxy_store._probe_error_message(
        "ProxyError unable to connect to proxy http://user:secret@proxy.example:8080"
    ) == "无法连接代理"


def test_import_deduplicates_and_public_view_never_leaks_credentials():
    secret = "secret-password-77"
    with IsolatedStore():
        result = proxy_store.import_proxies(
            "\n".join(
                [
                    f"proxy.example:8080:worker:{secret}",
                    f"http://worker:{secret}@proxy.example:8080",
                    "broken-value",
                ]
            )
        )
        assert result["ok"] is True
        assert result["imported_count"] == 1
        assert result["duplicate_count"] == 0
        assert len(result["errors"]) == 1
        encoded = json.dumps(result, ensure_ascii=False)
        assert secret not in encoded
        assert "worker" not in result["items"][0]["display_url"]
        assert result["items"][0]["has_auth"] is True
        stored = proxy_store.STATE_PATH.read_text(encoding="utf-8")
        assert secret in stored
        assert stat.S_IMODE(proxy_store.STATE_PATH.stat().st_mode) == 0o600


def test_resin_session_template_is_safe_and_runtime_results_map_to_source():
    secret = "resin-secret-token"
    template = f"socks5h://Default.{{session}}:{secret}@127.0.0.1:2260"
    normalized = proxy_store.normalize_proxy(template)
    assert "%7Bsession%7D" in normalized
    try:
        proxy_store.normalize_proxy(
            f"socks5h://Default.worker:{secret}@{{session}}:2260"
        )
    except proxy_store.ProxyValidationError:
        pass
    else:
        raise AssertionError("template placeholders outside username must be rejected")

    with IsolatedStore():
        imported = proxy_store.import_proxies(template)
        proxy_id = imported["imported_ids"][0]
        proxy_store._apply_probe_result(
            proxy_id,
            {
                "ok": True,
                "exit_ip": "198.51.100.20",
                "asn": 64520,
                "asn_org": "Resin Test",
                "latency_ms": 70,
                "checked_at": "2026-08-07T00:00:00Z",
            },
        )
        public = proxy_store.read_proxy_pool()
        assert public["summary"]["usable_templates"] == 1
        assert public["items"][0]["is_template"] is True
        worker_url = normalized.replace(
            "Default.%7Bsession%7D", "Default.grokreg-w1-r2"
        )
        assert proxy_store.record_proxy_result(worker_url, "risk", "policy deny")
        runtime_view = proxy_store.read_proxy_pool()
        assert runtime_view["items"][0]["risk_count"] == 1
        assert runtime_view["items"][0]["stored_status"] == "healthy"
        assert runtime_view["items"][0]["cooldown_until"] == ""
        assert len(proxy_store.list_worker_proxies()) == 1
        assert secret not in json.dumps(public, ensure_ascii=False)


def test_probe_result_and_runtime_cooldown_control_worker_selection():
    with IsolatedStore():
        imported = proxy_store.import_proxies("proxy.example:8080:user:pass")
        proxy_id = imported["imported_ids"][0]
        assert proxy_store.list_worker_proxies() == []
        assert proxy_store.worker_proxy_snapshot()["configured"] is True

        proxy_store._apply_probe_result(
            proxy_id,
            {
                "ok": True,
                "exit_ip": "203.0.113.9",
                "asn": 64500,
                "asn_org": "Example ISP",
                "latency_ms": 321,
                "checked_at": "2026-07-30T00:00:00Z",
            },
        )
        usable = proxy_store.list_worker_proxies()
        assert len(usable) == 1
        assert "user:pass" in usable[0]

        assert proxy_store.record_proxy_result(usable[0], "network", "connect timeout")
        assert proxy_store.list_worker_proxies() == []
        state = json.loads(proxy_store.STATE_PATH.read_text(encoding="utf-8"))
        state["items"][0]["cooldown_until"] = "2000-01-01T00:00:00Z"
        proxy_store.STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
        usable_after = proxy_store.list_worker_proxies()
        assert usable_after == usable

        assert proxy_store.record_proxy_result(usable[0], "risk", "policy deny")
        public = proxy_store.read_proxy_pool()
        item = public["items"][0]
        assert item["stored_status"] == "cooldown"
        assert item["cooldown_reason"] == "risk"
        assert item["risk_count"] == 1


def test_disable_delete_and_legacy_import():
    with IsolatedStore() as base:
        proxy_store.LEGACY_PATH.write_text(
            "http://a.example:8000\nhttp://b.example:8001\n", encoding="utf-8"
        )
        assert proxy_store.read_proxy_pool()["legacy"]["count"] == 2
        result = proxy_store.import_legacy_proxies()
        assert result["imported_count"] == 2
        proxy_id = result["items"][0]["id"]
        updated = proxy_store.update_proxy(proxy_id, enabled=False)
        assert next(item for item in updated["items"] if item["id"] == proxy_id)["enabled"] is False
        deleted = proxy_store.delete_proxy(proxy_id)
        assert deleted["deleted_id"] == proxy_id
        assert deleted["summary"]["total"] == 1


def test_pagination_bulk_delete_and_large_test_batching():
    with IsolatedStore():
        values = "\n".join(
            f"proxy-{index}.example:{8000 + index}:user:pass"
            for index in range(205)
        )
        imported = proxy_store.import_proxies(values)
        assert imported["imported_count"] == 205

        first = proxy_store.read_proxy_pool(page=1, page_size=50)
        last = proxy_store.read_proxy_pool(page=5, page_size=50)
        assert first["pagination"]["pages"] == 5
        assert len(first["items"]) == 50
        assert len(last["items"]) == 5

        deleted = proxy_store.delete_proxies(
            [first["items"][0]["id"], first["items"][1]["id"]]
        )
        assert deleted["deleted_count"] == 2
        assert deleted["summary"]["total"] == 203

        original_thread = proxy_store.threading.Thread
        started = []

        class FakeThread:
            def __init__(self, *, target, args, name, daemon):
                started.append((target, args, name, daemon))

            def start(self):
                return None

        try:
            proxy_store.threading.Thread = FakeThread
            with proxy_store._TEST_LOCK:
                proxy_store._TEST_JOB["running"] = False
            job = proxy_store.start_proxy_tests()
            assert job["ok"] is True
            assert job["total"] == 203
            assert job["batch_total"] == 2
            assert len(job["testing_ids"]) == proxy_store.MAX_TEST_ITEMS
            assert len(started) == 1
        finally:
            proxy_store.threading.Thread = original_thread
            with proxy_store._TEST_LOCK:
                proxy_store._TEST_JOB.update(
                    {
                        "running": False,
                        "job_id": None,
                        "testing_ids": [],
                    }
                )


def test_async_probe_job_persists_health():
    with IsolatedStore():
        result = proxy_store.import_proxies("http://proxy.example:8080")
        proxy_id = result["imported_ids"][0]
        previous_probe = proxy_store.probe_proxy
        with proxy_store._TEST_LOCK:
            proxy_store._TEST_JOB.update(
                {
                    "running": False,
                    "job_id": None,
                    "testing_ids": [],
                }
            )
        proxy_store.probe_proxy = lambda url, timeout=8: {
            "ok": True,
            "exit_ip": "198.51.100.8",
            "asn": 64501,
            "asn_org": "Test Network",
            "latency_ms": 88,
            "checked_at": "2026-07-30T00:00:00Z",
        }
        try:
            job = proxy_store.start_proxy_tests([proxy_id])
            assert job["ok"] is True
            deadline = time.time() + 2
            while proxy_store.proxy_test_status()["running"] and time.time() < deadline:
                time.sleep(0.01)
            status = proxy_store.proxy_test_status()
            assert status["running"] is False
            assert status["healthy"] == 1
            item = proxy_store.read_proxy_pool()["items"][0]
            assert item["stored_status"] == "healthy"
            assert item["exit_ip"] == "198.51.100.8"
        finally:
            proxy_store.probe_proxy = previous_probe


if __name__ == "__main__":
    test_normalize_proxy_formats_and_rejects_paths()
    test_import_deduplicates_and_public_view_never_leaks_credentials()
    test_resin_session_template_is_safe_and_runtime_results_map_to_source()
    test_probe_result_and_runtime_cooldown_control_worker_selection()
    test_disable_delete_and_legacy_import()
    test_pagination_bulk_delete_and_large_test_batching()
    test_async_probe_job_persists_health()
    print("OK proxy store")
