# -*- coding: utf-8 -*-
"""Unit tests for grok2api upload orchestration (webui/grok2api_upload.py)."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import grok2api_upload as up


def test_collect_web_accounts_dedupes_across_tasks():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        root_file = root / "grok2api_web_accounts.jsonl"
        root_file.write_text(
            json.dumps({"provider": "grok_web", "email": "a@x.com", "sso_token": "T1", "tier": "auto"})
            + "\n"
            + json.dumps({"provider": "grok_web", "email": "b@x.com", "sso_token": "T2"})
            + "\n",
            encoding="utf-8",
        )
        task_dir = root / "tasks" / "task1"
        task_dir.mkdir(parents=True)
        (task_dir / "grok2api_web_accounts.jsonl").write_text(
            json.dumps({"provider": "grok_web", "email": "a@x.com", "sso_token": "T1"})  # 重复 T1
            + "\n"
            + json.dumps({"provider": "grok_web", "email": "c@x.com", "sso_token": "T3"})
            + "\n",
            encoding="utf-8",
        )
        records = up.collect_web_accounts(root)
        assert len(records) == 3
        tokens = {r["sso_token"] for r in records}
        assert tokens == {"T1", "T2", "T3"}
        # 坏行忽略（只影响该文件，其他任务文件仍可读）
        (root_file).write_text("not-json\n", encoding="utf-8")
        records2 = up.collect_web_accounts(root)
        assert {r["sso_token"] for r in records2} == {"T1", "T3"}


def test_chunk_records_splits_by_size():
    records = [{"sso_token": f"T{i}"} for i in range(25)]
    chunks = list(up.chunk_records(records, size=10))
    assert len(chunks) == 3
    assert chunks[0].count("\n") == 10
    assert chunks[2].count("\n") == 5


def test_configured_and_report_roundtrip():
    with tempfile.TemporaryDirectory() as temp:
        report_path = Path(temp) / "report.json"
        config = {
            "grok2api_admin_url": "http://127.0.0.1:8080",
            "grok2api_admin_user": "admin",
            "grok2api_admin_password": "test-admin-pw-123",
        }
        assert up.configured(config) is True
        assert up.configured({}) is False
        assert up.configured({"grok2api_admin_url": "x"}) is False

        report = up.run_upload(
            {},
            report_path=report_path,
            accounts_dir=Path(temp) / "accounts",
        )
        assert report["ok"] is False
        assert "未配置" in report.get("error", "")
        assert up.read_report(report_path).get("configured") is False


def test_run_upload_full_flow():
    import webui.grok2api_upload as upload_mod
    from webui import grok2api_api

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        accounts = root / "accounts"
        accounts.mkdir()
        (accounts / "grok2api_web_accounts.jsonl").write_text(
            json.dumps({"provider": "grok_web", "email": "a@x.com", "sso_token": "T1", "tier": "auto"})
            + "\n",
            encoding="utf-8",
        )
        report_path = root / "report.json"
        config = {
            "grok2api_admin_url": "http://127.0.0.1:8080",
            "grok2api_admin_user": "admin",
            "grok2api_admin_password": "test-admin-pw-123",
        }

        class FakeClient:
            def __init__(self, *a, **k):
                pass

            def login(self):
                pass

            def import_web_accounts(self, content):
                assert "T1" in content
                return {"created": 1, "updated": 0, "skipped": 0}

            def convert_to_build(self):
                return {"created": 1, "linked": 1, "skipped": 0}

            def sync_to_console(self):
                return {"created": 1, "synced": 1, "syncFailed": 0}

        previous_client = upload_mod.Grok2apiClient
        upload_mod.Grok2apiClient = FakeClient
        try:
            report = upload_mod.run_upload(config, report_path=report_path, accounts_dir=accounts)
        finally:
            upload_mod.Grok2apiClient = previous_client

        assert report["ok"] is True
        assert report["total_accounts"] == 1
        assert report["imported"]["created"] == 1
        assert report["converted"]["created"] == 1
        assert report["synced"]["created"] == 1
        assert "test-admin-pw-123" not in json.dumps(report)


def test_upload_status_reads_report():
    with tempfile.TemporaryDirectory() as temp:
        report_path = Path(temp) / "report.json"
        report_path.write_text(
            json.dumps({"ok": True, "imported": {"created": 3}}),
            encoding="utf-8",
        )
        previous = up.REPORT_FILE
        up.REPORT_FILE = report_path
        try:
            status = up.upload_status(report_path)
            assert status["last_report"]["imported"]["created"] == 3
        finally:
            up.REPORT_FILE = previous


if __name__ == "__main__":
    test_collect_web_accounts_dedupes_across_tasks()
    test_chunk_records_splits_by_size()
    test_configured_and_report_roundtrip()
    test_run_upload_full_flow()
    test_upload_status_reads_report()
    print("OK grok2api upload")
