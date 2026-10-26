# -*- coding: utf-8 -*-
"""Outlook 卡池面板管理操作的单元测试（临时目录隔离，不碰真实卡池）。"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import outlook_pool_ops as ops


def make_row(i: int, domain: str = "hotmail.com") -> str:
    return f"user{i}@{domain}----pw{i}----client-{i}----M.C5xx_refresh{i}"


def test_import_dedup_and_stats():
    with tempfile.TemporaryDirectory() as temp:
        pending = str(Path(temp) / "pending.txt")
        used = str(Path(temp) / "used.txt")
        text = "\n".join([make_row(1), make_row(2), make_row(1)])  # 第三行重复
        result = ops.outlook_pool_import(text, pending, used)
        assert result["added"] == 2 and result["skipped_duplicate"] == 1
        stats = ops.outlook_pool_stats(pending, used)
        assert stats["pending"] == 2 and stats["available"] == 2 and stats["used"] == 0
        # 邮箱统一小写后仍判重
        result2 = ops.outlook_pool_import(make_row(1).upper(), pending, used)
        assert result2["added"] == 0


def test_import_strips_refresh_tail_pollution():
    with tempfile.TemporaryDirectory() as temp:
        pending = str(Path(temp) / "pending.txt")
        used = str(Path(temp) / "used.txt")
        raw = "tail@hotmail.com----pw----cid----M.C5xx_token$$"
        ops.outlook_pool_import(raw, pending, used)
        lines = Path(pending).read_text(encoding="utf-8").strip().splitlines()
        assert lines[0].endswith("M.C5xx_token")
        assert "$$" not in lines[0]


def test_import_rejects_bad_row():
    with tempfile.TemporaryDirectory() as temp:
        pending = str(Path(temp) / "pending.txt")
        used = str(Path(temp) / "used.txt")
        try:
            ops.outlook_pool_import("only-two----fields", pending, used)
        except ops.OutlookPoolError as exc:
            assert "行格式无效" in str(exc)
        else:
            raise AssertionError("expected OutlookPoolError")


def test_rows_mask_email_and_state():
    with tempfile.TemporaryDirectory() as temp:
        pending = str(Path(temp) / "pending.txt")
        used = str(Path(temp) / "used.txt")
        ops.outlook_pool_import("\n".join([make_row(1), make_row(2)]), pending, used)
        # 模拟 user1 被消费进已用（直接搬行，与 create_mailbox 行为一致）
        lines = Path(pending).read_text(encoding="utf-8").strip().splitlines()
        kept = [line for line in lines if not line.startswith("user1@")]
        Path(pending).write_text("\n".join(kept) + "\n", encoding="utf-8")
        Path(used).write_text(make_row(1) + "\n", encoding="utf-8")
        data = ops.outlook_pool_rows(pending, used)
        emails = {row["email"]: row for row in data["rows"]}
        assert emails["user1@hotmail.com"]["state"] == "used"
        assert emails["user2@hotmail.com"]["state"] == "pending"
        # 脱敏：不泄露完整 local part
        assert "user1@hotmail.com" not in emails["user1@hotmail.com"]["email_masked"]
        assert ops._mask_email("u1@hotmail.com").startswith("u")


def test_delete_pending_keeps_used():
    with tempfile.TemporaryDirectory() as temp:
        pending = str(Path(temp) / "pending.txt")
        used = str(Path(temp) / "used.txt")
        ops.outlook_pool_import("\n".join([make_row(1), make_row(2), make_row(3)]), pending, used)
        result = ops.outlook_pool_delete(["user1@hotmail.com", "user2@HOTMAIL.com"], pending, used)
        assert result["deleted_pending"] == 2
        stats = ops.outlook_pool_stats(pending, used)
        assert stats["pending"] == 1
        # 已用邮箱默认保留
        Path(used).write_text(make_row(9) + "\n", encoding="utf-8")
        result2 = ops.outlook_pool_delete(["user9@hotmail.com"], pending, used)
        assert result2["deleted_pending"] == 0
        assert result2["skipped_used"] == 1
        assert "user9@hotmail.com" in Path(used).read_text(encoding="utf-8")


def test_export_returns_raw_lines():
    with tempfile.TemporaryDirectory() as temp:
        pending = str(Path(temp) / "pending.txt")
        used = str(Path(temp) / "used.txt")
        ops.outlook_pool_import(make_row(1) + "\n" + make_row(2), pending, used)
        data = ops.outlook_pool_export(pending, used)
        assert "user1@hotmail.com" in data["text"] and "user2@hotmail.com" in data["text"]
        assert data["text"].count("\n") == 2


if __name__ == "__main__":
    test_import_dedup_and_stats()
    test_import_strips_refresh_tail_pollution()
    test_import_rejects_bad_row()
    test_rows_mask_email_and_state()
    test_delete_pending_keeps_used()
    test_export_returns_raw_lines()
    print("OK outlook pool ops")
