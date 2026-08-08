"""IP 出口使用次数持久化统计（跨任务、跨进程累计）。

每个账号槽位（成功或最终失败）在该出口 IP 上计 1 次，内部重试不计。
数据落盘到 log/ip_usage.json，注册进程与 Web 面板均可读写，用于：
- 代理池页面显示每个 IP 的历史使用次数
- 单 IP 累计使用上限（ip_usage_limit）判定换 IP
- 每 IP 单独覆盖上限、删除单条记录、IP 元数据（国家/服务商/延迟）

文件结构：
{
  "counts": {ip: n},              # 累计次数
  "limits": {ip: n},              # 每 IP 覆盖上限（n>0；删除覆盖时移除键）
  "meta":   {ip: {country, isp, org, asn, latency_ms, updated_at}},
  "updated_at": "..."
}
旧格式只有 counts/updated_at，读取时自动兼容。
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
_KEY_LIMITS = "limits"
_KEY_META = "meta"
_KEY_UPDATED = "updated_at"


def usage_file_path() -> Path:
    return _USAGE_FILE


def _clean_meta(meta: dict) -> dict:
    """只保留已知字段的整数值/短字符串，避免脏数据写盘。"""
    allowed = {
        "country": str,
        "country_code": str,
        "isp": str,
        "org": str,
        "asn": str,
        "latency_ms": int,
        "updated_at": str,
    }
    out: dict = {}
    for key, cast in allowed.items():
        raw = meta.get(key)
        if raw is None:
            continue
        try:
            if cast is int:
                out[key] = max(0, int(raw))
            else:
                text = str(raw).strip()
                if text:
                    out[key] = text[:80]
        except (TypeError, ValueError):
            continue
    return out


def _load_all() -> dict:
    """读取完整数据结构（兼容只有 counts 的旧格式）。"""
    try:
        data = json.loads(_USAGE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        return {}

    counts: dict[str, int] = {}
    raw_counts = data.get(_KEY_COUNTS) or {}
    if isinstance(raw_counts, dict):
        for ip, value in raw_counts.items():
            try:
                counts[str(ip).strip()] = max(0, int(value))
            except (TypeError, ValueError):
                continue

    limits: dict[str, int] = {}
    raw_limits = data.get(_KEY_LIMITS) or {}
    if isinstance(raw_limits, dict):
        for ip, value in raw_limits.items():
            try:
                n = int(value)
                if n > 0:
                    limits[str(ip).strip()] = n
            except (TypeError, ValueError):
                continue

    meta: dict[str, dict] = {}
    raw_meta = data.get(_KEY_META) or {}
    if isinstance(raw_meta, dict):
        for ip, value in raw_meta.items():
            if isinstance(value, dict):
                cleaned = _clean_meta(value)
                if cleaned:
                    meta[str(ip).strip()] = cleaned
    return {_KEY_COUNTS: counts, _KEY_LIMITS: limits, _KEY_META: meta}


def _load_counts() -> dict[str, int]:
    return _load_all().get(_KEY_COUNTS, {})


def _write_all(counts: dict, limits: dict, meta: dict) -> None:
    _USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        _USAGE_FILE,
        {
            _KEY_COUNTS: counts,
            _KEY_LIMITS: limits,
            _KEY_META: meta,
            _KEY_UPDATED: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )


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
            data = _load_all()
            counts = data[_KEY_COUNTS]
            counts[ip] = counts.get(ip, 0) + increment
            _write_all(counts, data[_KEY_LIMITS], data[_KEY_META])
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


# ---- 每 IP 覆盖上限 ----


def get_per_ip_limit(exit_ip: str) -> int | None:
    """返回该 IP 的单独上限覆盖；未设置/被清除返回 None（回退全局）。"""
    ip = str(exit_ip or "").strip()
    if not ip:
        return None
    with _USAGE_LOCK:
        return _load_all().get(_KEY_LIMITS, {}).get(ip)


def set_ip_usage_limit(exit_ip: str, limit: int) -> None:
    """设置某 IP 单独上限；limit<=0 表示清除覆盖、回退全局上限。"""
    ip = str(exit_ip or "").strip()
    if not ip:
        return
    with _USAGE_LOCK:
        with exclusive_file_lock(_USAGE_FILE.with_suffix(".lock")):
            data = _load_all()
            limits = data[_KEY_LIMITS]
            if int(limit or 0) > 0:
                limits[ip] = max(1, min(int(limit), 100000))
            else:
                limits.pop(ip, None)
            _write_all(data[_KEY_COUNTS], limits, data[_KEY_META])


# ---- 单条删除 ----


def delete_ip_usage(exit_ip: str) -> bool:
    """删除某 IP 的累计次数、上限覆盖与元数据，返回是否删除了记录。"""
    ip = str(exit_ip or "").strip()
    if not ip:
        return False
    with _USAGE_LOCK:
        with exclusive_file_lock(_USAGE_FILE.with_suffix(".lock")):
            data = _load_all()
            counts = data[_KEY_COUNTS]
            limits = data[_KEY_LIMITS]
            meta = data[_KEY_META]
            removed = ip in counts or ip in limits or ip in meta
            counts.pop(ip, None)
            limits.pop(ip, None)
            meta.pop(ip, None)
            if removed:
                _write_all(counts, limits, meta)
            return removed


# ---- IP 元数据（国家/服务商/延迟） ----


def get_ip_usage_meta(exit_ip: str) -> dict:
    """返回某 IP 的元数据（无则空 dict）。"""
    ip = str(exit_ip or "").strip()
    if not ip:
        return {}
    with _USAGE_LOCK:
        meta = _load_all().get(_KEY_META, {}).get(ip)
        return dict(meta) if isinstance(meta, dict) else {}


def set_ip_usage_meta(exit_ip: str, meta: dict) -> None:
    """保存某 IP 元数据（合并写入，只保留已知字段）。"""
    ip = str(exit_ip or "").strip()
    if not ip:
        return
    cleaned = _clean_meta(meta)
    if not cleaned:
        return
    cleaned["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _USAGE_LOCK:
        with exclusive_file_lock(_USAGE_FILE.with_suffix(".lock")):
            data = _load_all()
            meta_map = data[_KEY_META]
            merged = dict(meta_map.get(ip) or {})
            merged.update(cleaned)
            meta_map[ip] = merged
            _write_all(data[_KEY_COUNTS], data[_KEY_LIMITS], meta_map)


# ---- 全量详情（IP 使用页面） ----


def get_all_ip_usage_detail() -> list[dict]:
    """返回 [{ip, count, limit, meta}]，按累计次数降序；供 IP 使用页面展示。"""
    with _USAGE_LOCK:
        data = _load_all()
        counts = data[_KEY_COUNTS]
        limits = data[_KEY_LIMITS]
        meta = data[_KEY_META]
        items = []
        for ip, count in counts.items():
            items.append(
                {
                    "ip": ip,
                    "count": count,
                    "limit": limits.get(ip),
                    "meta": dict(meta.get(ip) or {}),
                }
            )
        # 只有上限/元数据但没有计数的 IP 也展示（如手动设置的覆盖）
        for ip in set(limits) | set(meta):
            if ip not in counts:
                items.append(
                    {
                        "ip": ip,
                        "count": 0,
                        "limit": limits.get(ip),
                        "meta": dict(meta.get(ip) or {}),
                    }
                )
        items.sort(key=lambda it: (-it["count"], it["ip"]))
        return items
