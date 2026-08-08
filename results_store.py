"""register_results.jsonl 的统计、归档轮转与累计摘要。

- 注册进程（grok_register_ttk.py）逐条追加写 register_results.jsonl；
- 本模块提供全量 ok/fail/risk 计数（供任务完成数、run_until_100 完成判定、
  Web 面板 success_stats 使用）；
- 文件超阈值自动归档为 register_results-<ts>.jsonl，并把归档前的计数
  累计进 register_results_archive.json 摘要，保证轮转后计数不丢失、
  任务完成数不跳变（也是"数据库评估"中文件方案的配套治理）。
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from secure_files import atomic_write_json, exclusive_file_lock

_LOG_DIR = Path(__file__).resolve().parent / "log"
_RESULTS_FILE = _LOG_DIR / "register_results.jsonl"
_ARCHIVE_SUMMARY_FILE = _LOG_DIR / "register_results_archive.json"
# 当前 jsonl 超过该字节数时归档（同时保证全量统计只读 ≤ 该大小的文件）
MAX_RESULTS_BYTES = 5 * 1024 * 1024
_LOCK = threading.Lock()


def results_file_path() -> Path:
    return _RESULTS_FILE


def archive_summary_path() -> Path:
    return _ARCHIVE_SUMMARY_FILE


def _read_archive_summary() -> dict[str, int]:
    try:
        data = json.loads(_ARCHIVE_SUMMARY_FILE.read_text(encoding="utf-8"))
        summary = data.get("counts") or {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
    result: dict[str, int] = {}
    for key in ("ok", "fail", "risk"):
        try:
            result[key] = max(0, int(summary.get(key, 0)))
        except (TypeError, ValueError):
            result[key] = 0
    return result


def _count_current_file(path: Path) -> dict[str, int]:
    """全量统计当前 jsonl（轮转保证文件 ≤ MAX_RESULTS_BYTES）。"""
    counts = {"ok": 0, "fail": 0, "risk": 0}
    if not path.is_file():
        return counts
    try:
        with path.open("rb") as f:
            for line in f:
                try:
                    obj = json.loads(line.decode("utf-8", errors="replace"))
                except Exception:
                    continue
                status = str(obj.get("status") or "")
                if status in counts:
                    counts[status] += 1
    except OSError:
        pass
    return counts


def rotate_if_needed() -> bool:
    """当前 jsonl 超阈值时归档并累计摘要；返回是否发生了轮转。

    与 append_result_line 共用 .lock 文件锁，避免轮转 rename 与
    注册进程追加写之间产生竞态（新行写进归档文件）。
    """
    if not _RESULTS_FILE.is_file():
        return False
    try:
        if _RESULTS_FILE.stat().st_size < MAX_RESULTS_BYTES:
            return False
    except OSError:
        return False
    # 注意：调用方 count_results() 已持有 _LOCK；这里只取文件锁，避免
    # 非重入线程锁自锁。独立调用（仅测试）时由文件锁保证原子性。
    with exclusive_file_lock(_RESULTS_FILE.with_suffix(".lock")):
        counts = _count_current_file(_RESULTS_FILE)
        summary = _read_archive_summary()
        for key in ("ok", "fail", "risk"):
            summary[key] = summary.get(key, 0) + counts[key]
        archive_path = _RESULTS_FILE.with_name(
            f"register_results-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
        )
        try:
            _RESULTS_FILE.rename(archive_path)
        except OSError:
            return False
        atomic_write_json(
            _ARCHIVE_SUMMARY_FILE,
            {
                "counts": summary,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        )
        return True


def count_results() -> dict[str, int]:
    """全量计数 = 当前 jsonl（全量读，轮转保证 ≤5MB）+ 归档摘要。"""
    with _LOCK:
        rotate_if_needed()
        counts = _count_current_file(_RESULTS_FILE)
        summary = _read_archive_summary()
    for key in ("ok", "fail", "risk"):
        counts[key] += summary.get(key, 0)
    return counts


def ok_count() -> int:
    """累计注册成功数（任务完成判定与展示的统一口径）。"""
    return count_results().get("ok", 0)


def append_result_line(record: dict) -> None:
    """注册进程写入一条结果（保持 jsonl 行格式）。"""
    _RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_file_lock(_RESULTS_FILE.with_suffix(".lock")):
        with _RESULTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
