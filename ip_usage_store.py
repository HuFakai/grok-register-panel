"""IP 出口使用次数持久化统计（跨任务、跨进程累计）。

每个账号槽位（成功或最终失败）在该出口 IP 上计 1 次，内部重试不计。
数据落盘到 log/ip_usage.json，注册进程与 Web 面板均可读写，用于：
- 代理池页面显示每个 IP 的历史使用次数
- 单 IP 累计使用上限（ip_usage_limit）判定换 IP
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from secure_files import atomic_write_json, exclusive_file_lock

_USAGE_FILE = Path(__file__).resolve().parent / "log" / "ip_usage.json"
_USAGE_LOCK = threading.Lock()
_KEY_COUNTS = "counts"
_KEY_UPDATED = "updated_at"


def usage_file_path() -> Path:
    return _USAGE_FILE


def _load_counts() -> dict[str, int]:
    try:
        data = json.loads(_USAGE_FILE.read_text(encoding="utf-8"))
        raw = data.get(_KEY_COUNTS) or {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
    counts: dict[str, int] = {}
    for ip, value in raw.items():
        try:
            counts[str(ip).strip()] = max(0, int(value))
        except (TypeError, ValueError):
            continue
    return counts


def record_ip_usage(exit_ip: str, times: int = 1) -> int:
    """某出口 IP 使用次数 +times（默认 1），返回累计值。

    原子写盘；空 IP 直接忽略。
    """
    ip = str(exit_ip or "").strip()
    if not ip:
        return 0
    increment = max(1, int(times or 1))
    with _USAGE_LOCK:
        _USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with exclusive_file_lock(_USAGE_FILE.with_suffix(".lock")):
            counts = _load_counts()
            counts[ip] = counts.get(ip, 0) + increment
            atomic_write_json(
                _USAGE_FILE,
                {
                    _KEY_COUNTS: counts,
                    _KEY_UPDATED: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
            )
            return counts[ip]


def get_ip_usage(exit_ip: str) -> int:
    """返回某出口 IP 的累计使用次数（无记录为 0）。"""
    ip = str(exit_ip or "").strip()
    if not ip:
        return 0
    with _USAGE_LOCK:
        return _load_counts().get(ip, 0)


def get_all_ip_usage() -> dict[str, int]:
    """返回 {出口IP: 累计次数} 全量映射（代理池页面展示用）。"""
    with _USAGE_LOCK:
        return dict(_load_counts())


def get_total_usage() -> int:
    """所有 IP 使用次数合计（展示用）。"""
    with _USAGE_LOCK:
        return sum(_load_counts().values())


def reset_ip_usage() -> None:
    """清空统计（仅测试/手动维护用）。"""
    with _USAGE_LOCK:
        try:
            _USAGE_FILE.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
