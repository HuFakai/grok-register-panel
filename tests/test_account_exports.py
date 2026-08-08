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

from account_exports import (
    GROK2API_JSONL_FILENAME,
    GROK2API_SSO_FILENAME,
    MASTER_FILENAME,
    TASKS_SUBDIR,
    consolidate_account_exports,
    save_account_record,
)


TOKEN_A = "a" * 80
TOKEN_B = "b" * 80
TOKEN_C = "c" * 80


def test_save_updates_master_and_current_grok2api_imports():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "accounts"
        save_account_record(root, "Second@Example.com", "pw-2", TOKEN_B)
        save_account_record(root, "first@example.com", "pw-1", TOKEN_A)
        result = save_account_record(root, "first@example.com", "new-pw", TOKEN_C)

        assert result["count"] == 2
        master = (root / MASTER_FILENAME).read_text(encoding="utf-8").splitlines()
        assert master == [
            f"first@example.com----new-pw----{TOKEN_C}",
            f"second@example.com----pw-2----{TOKEN_B}",
        ]
        assert (root / GROK2API_SSO_FILENAME).read_text(encoding="utf-8").splitlines() == [
            TOKEN_C,
            TOKEN_B,
        ]
        entries = [
            json.loads(line)
            for line in (root / GROK2API_JSONL_FILENAME).read_text(encoding="utf-8").splitlines()
        ]
        assert entries[0] == {
            "provider": "grok_web",
            "name": "first@example.com",
            "email": "first@example.com",
            "sso_token": TOKEN_C,
            "tier": "auto",
        }
        if os.name == "posix":
            for name in (MASTER_FILENAME, GROK2API_SSO_FILENAME, GROK2API_JSONL_FILENAME):
                assert stat.S_IMODE((root / name).stat().st_mode) == 0o600


def test_round_consolidation_recovers_individual_account_files():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "accounts"
        root.mkdir()
        (root / "legacy@example.com.txt").write_text(
            f"legacy@example.com----legacy-pw----{TOKEN_A}\n",
            encoding="utf-8",
        )
        result = consolidate_account_exports(root)
        assert result["count"] == 1
        assert (root / MASTER_FILENAME).read_text(encoding="utf-8") == (
            f"legacy@example.com----legacy-pw----{TOKEN_A}\n"
        )


def test_save_with_task_subdir_writes_into_task_folder():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "accounts"
        save_account_record(
            root, "alpha@example.com", "pw-a", TOKEN_A, task_subdir="20260807-100000-n40"
        )
        save_account_record(
            root, "beta@example.com", "pw-b", TOKEN_B, task_subdir="20260807-100000-n40"
        )
        # 根目录不生成账号文件和聚合文件
        assert not (root / "alpha@example.com.txt").exists()
        assert not (root / MASTER_FILENAME).exists()
        # 任务目录自包含：账号 txt + 任务级聚合
        task_dir = root / TASKS_SUBDIR / "20260807-100000-n40"
        assert (task_dir / "alpha@example.com.txt").exists()
        assert (task_dir / "beta@example.com.txt").exists()
        master = (task_dir / MASTER_FILENAME).read_text(encoding="utf-8").splitlines()
        assert len(master) == 2
        assert master[0].startswith("alpha@example.com----")
        assert master[1].startswith("beta@example.com----")
        assert (task_dir / GROK2API_SSO_FILENAME).is_file()
        assert (task_dir / GROK2API_JSONL_FILENAME).is_file()


def test_consolidate_refreshes_each_task_folder_and_legacy_files():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "accounts"
        # 旧格式：根目录遗留账号文件（无任务目录）
        root.mkdir()
        (root / "legacy@example.com.txt").write_text(
            f"legacy@example.com----legacy-pw----{TOKEN_A}\n",
            encoding="utf-8",
        )
        # 新格式：两个任务目录各存账号（任务级聚合在任务目录内）
        save_account_record(
            root, "task1@example.com", "pw-1", TOKEN_B, task_subdir="20260807-100000-n40"
        )
        save_account_record(
            root, "task2@example.com", "pw-2", TOKEN_C, task_subdir="20260807-110000-n40"
        )
        result = consolidate_account_exports(root)
        assert result["tasks"] == 2
        assert result["count"] == 3  # 2 任务 + 1 遗留
        # 每个任务目录聚合文件与账号一致
        task1 = root / TASKS_SUBDIR / "20260807-100000-n40"
        task2 = root / TASKS_SUBDIR / "20260807-110000-n40"
        assert "task1@example.com" in (task1 / MASTER_FILENAME).read_text(encoding="utf-8")
        assert "task2@example.com" in (task2 / MASTER_FILENAME).read_text(encoding="utf-8")
        assert "task1@example.com" not in (task2 / MASTER_FILENAME).read_text(encoding="utf-8")
        # 根目录遗留仍刷新根目录聚合（兼容旧数据）
        assert (root / MASTER_FILENAME).read_text(encoding="utf-8") == (
            f"legacy@example.com----legacy-pw----{TOKEN_A}\n"
        )


def test_task_subdir_rejects_unsafe_names():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "accounts"
        try:
            save_account_record(
                root, "x@example.com", "pw", TOKEN_A, task_subdir=".."
            )
            raise AssertionError("非法任务目录名应当被拒绝")
        except ValueError:
            pass


if __name__ == "__main__":
    test_save_updates_master_and_current_grok2api_imports()
    test_round_consolidation_recovers_individual_account_files()
    test_save_with_task_subdir_writes_into_task_folder()
    test_consolidate_refreshes_each_task_folder_and_legacy_files()
    test_task_subdir_rejects_unsafe_names()
    print("OK account exports")
