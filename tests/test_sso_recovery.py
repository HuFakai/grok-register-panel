# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sso_to_auth_json import (
    _pending_queue_files,
    consume_successful_records,
    existing_cpa_emails,
    load_sso_records,
    parse_sso_line,
    should_create_default_out_dir,
    token_to_grok2api_build_entry,
    write_grok2api_auth,
)


TOKEN_A = "a" * 80
TOKEN_B = "b" * 80


def test_parser_preserves_email_and_password():
    record = parse_sso_line(f"person@example.com----pass123----{TOKEN_A}")
    assert record is not None
    assert record.email == "person@example.com"
    assert record.password == "pass123"
    assert record.sso == TOKEN_A


def test_queue_dedup_and_consume():
    with tempfile.TemporaryDirectory() as temp:
        queue = Path(temp) / "sso_pending.txt"
        queue.write_text(
            f"first@example.com----{TOKEN_A}\n"
            f"first@example.com----merged-pass----{TOKEN_A}\n"
            f"second@example.com----pw----{TOKEN_B}\n",
            encoding="utf-8",
        )
        records = load_sso_records(path=str(queue))
        assert len(records) == 2
        assert records[0].email == "first@example.com"
        assert records[0].password == "merged-pass"
        remaining = consume_successful_records(queue, {TOKEN_A})
        assert remaining == 1
        assert TOKEN_A not in queue.read_text(encoding="utf-8")
        assert TOKEN_B in queue.read_text(encoding="utf-8")
        if os.name == "posix":
            assert stat.S_IMODE(queue.stat().st_mode) == 0o600


def test_cpa_only_batch_does_not_create_auth_out():
    args = SimpleNamespace(
        out=None,
        out_dir=None,
        cpa_auth_dir="/tmp/cpa",
        cpa_remote_url=None,
        grok2api_auth_dir=None,
        merge=False,
    )
    assert should_create_default_out_dir(args, 2) is False


def test_existing_cpa_email_detection():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "xai-person@example.com.json").write_text(
            json.dumps({"email": "Person@Example.com"}),
            encoding="utf-8",
        )
        assert existing_cpa_emails(root) == {"person@example.com"}


def test_latest_grok2api_build_import_shape():
    entry = token_to_grok2api_build_entry(
        {
            "access_token": TOKEN_A,
            "refresh_token": TOKEN_B,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
        email="person@example.com",
    )
    assert entry["provider"] == "grok_build"
    assert entry["client_id"]
    assert entry["access_token"] == TOKEN_A
    assert entry["refresh_token"] == TOKEN_B
    assert entry["email"] == "person@example.com"
    assert entry["expires_at"].endswith("Z")

    with tempfile.TemporaryDirectory() as temp:
        auth_dir = Path(temp) / "grok2api_auth"
        path = write_grok2api_auth(
            auth_dir,
            {
                "access_token": TOKEN_A,
                "refresh_token": TOKEN_B,
                "expires_in": 3600,
            },
            email="person@example.com",
        )
        assert json.loads(path.read_text(encoding="utf-8"))["provider"] == "grok_build"
        bulk = auth_dir / "grok2api_build_accounts.jsonl"
        values = [json.loads(line) for line in bulk.read_text(encoding="utf-8").splitlines()]
        assert len(values) == 1
        assert values[0]["email"] == "person@example.com"
        if os.name == "posix":
            assert stat.S_IMODE(bulk.stat().st_mode) == 0o600


def test_pending_only_loads_only_sso_pending_across_task_folders():
    with tempfile.TemporaryDirectory() as temp:
        accounts = Path(temp) / "accounts"
        task1 = accounts / "tasks" / "20260807-100000-n40"
        task2 = accounts / "tasks" / "20260807-110000-n40"
        task1.mkdir(parents=True)
        task2.mkdir(parents=True)
        (task1 / "sso_pending.txt").write_text(
            f"first@example.com----{TOKEN_A}\n", encoding="utf-8"
        )
        (task2 / "sso_pending.txt").write_text(
            f"second@example.com----{TOKEN_B}\n", encoding="utf-8"
        )
        # 任务目录内的账号文件不应在 pending-only 模式下被加载
        (task1 / "first@example.com.txt").write_text(
            f"first@example.com----pw----{TOKEN_A}\n", encoding="utf-8"
        )
        records = load_sso_records(accounts_dir=str(accounts), pending_only=True)
        assert len(records) == 2
        assert {r.email for r in records} == {"first@example.com", "second@example.com"}
        targets = _pending_queue_files(records, None)
        assert len(targets) == 2
        assert all(p.name == "sso_pending.txt" for p in targets)
        # 逐文件消费：TOKEN_A 只从 task1 队列移除
        for target in targets:
            consume_successful_records(target, {TOKEN_A})
        assert TOKEN_A not in (task1 / "sso_pending.txt").read_text(encoding="utf-8")
        assert TOKEN_B in (task2 / "sso_pending.txt").read_text(encoding="utf-8")


if __name__ == "__main__":
    test_parser_preserves_email_and_password()
    test_queue_dedup_and_consume()
    test_cpa_only_batch_does_not_create_auth_out()
    test_existing_cpa_email_detection()
    test_latest_grok2api_build_import_shape()
    test_pending_only_loads_only_sso_pending_across_task_folders()
    print("OK sso recovery")
