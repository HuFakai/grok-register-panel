# -*- coding: utf-8 -*-
"""register_results.jsonl 轮转与归档摘要：轮转后全量计数不丢失。"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import results_store


class IsolatedResults:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.previous = (
            results_store._RESULTS_FILE,
            results_store._ARCHIVE_SUMMARY_FILE,
            results_store.MAX_RESULTS_BYTES,
        )
        results_store._RESULTS_FILE = base / "log" / "register_results.jsonl"
        results_store._ARCHIVE_SUMMARY_FILE = base / "log" / "register_results_archive.json"
        results_store.MAX_RESULTS_BYTES = 1024  # 小阈值便于触发轮转
        return base

    def __exit__(self, exc_type, exc, tb):
        (
            results_store._RESULTS_FILE,
            results_store._ARCHIVE_SUMMARY_FILE,
            results_store.MAX_RESULTS_BYTES,
        ) = self.previous
        self.temp.cleanup()


def _line(status: str) -> str:
    return json.dumps({"status": status, "ts": "2026-08-08T00:00:00Z"}, ensure_ascii=False) + "\n"


def test_count_and_append():
    with IsolatedResults():
        assert results_store.count_results() == {"ok": 0, "fail": 0, "risk": 0}
        assert results_store.ok_count() == 0
        results_store.append_result_line({"status": "ok", "ts": "x"})
        results_store.append_result_line({"status": "fail", "ts": "x"})
        assert results_store.count_results()["ok"] == 1
        assert results_store.count_results()["fail"] == 1


def test_rotation_keeps_total_counts():
    with IsolatedResults():
        # 写入 120 行（远超市字节数阈值 1024，行文本 > 8 字节）
        for i in range(120):
            results_store.append_result_line({"status": "ok" if i % 3 else "risk", "ts": "x"})

        rotated = results_store.rotate_if_needed()
        assert rotated is True
        # 归档文件存在，当前文件被清空
        archive = sorted(
            results_store._RESULTS_FILE.parent.glob("register_results-*.jsonl")
        )
        assert len(archive) == 1

        # 轮转后全量计数不变（当前文件 + 归档摘要）
        after = results_store.count_results()
        assert after["ok"] + after["risk"] == 120
        assert results_store.ok_count() == after["ok"]

        # 追加新行继续累计
        results_store.append_result_line({"status": "ok", "ts": "x"})
        assert results_store.count_results()["ok"] == after["ok"] + 1


def test_rotation_idempotent_and_noop_when_small():
    with IsolatedResults():
        assert results_store.rotate_if_needed() is False  # 无文件
        results_store.append_result_line({"status": "ok", "ts": "x"})
        assert results_store.rotate_if_needed() is False  # 未超阈值
        results_store.append_result_line({"status": "fail", "ts": "x"})
        results_store.rotate_if_needed()
        results_store.rotate_if_needed()  # 当前文件为空，再次调用无操作
        assert results_store.count_results()["ok"] == 1
        assert results_store.count_results()["fail"] == 1


def test_count_skips_garbage_lines():
    with IsolatedResults():
        path = results_store._RESULTS_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            _line("ok") + "not-json\n" + _line("fail") + '{"status":"weird"}\n',
            encoding="utf-8",
        )
        counts = results_store.count_results()
        assert counts["ok"] == 1
        assert counts["fail"] == 1


if __name__ == "__main__":
    test_count_and_append()
    test_rotation_keeps_total_counts()
    test_rotation_idempotent_and_noop_when_small()
    test_count_skips_garbage_lines()
    print("OK results store")
