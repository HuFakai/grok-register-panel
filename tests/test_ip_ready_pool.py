# -*- coding: utf-8 -*-
"""Unit tests for the ready-IP pool (webui/ip_ready_pool.py)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import browser_session
import ip_usage_store
import webui.ip_ready_pool as pool


def _use_temp_pool(tmp: str):
    previous = pool._POOL_FILE
    pool._POOL_FILE = Path(tmp) / "ip_ready_pool.json"
    return previous


def _seed_item(
    *,
    expanded_url: str = "http://Default.ipool-1-0:TOKEN@1.2.3.4:2261",
    exit_ip: str = "10.0.0.1",
    used: int = 0,
    limit: int = 10,
    usable: bool = True,
    expires_at: float | None = None,
    consumer: str = "",
) -> dict:
    now = pool.time.time()
    return {
        "id": pool._item_id(expanded_url),
        "template_url": "http://Default.{session}:TOKEN@1.2.3.4:2261",
        "expanded_url": expanded_url,
        "exit_ip": exit_ip,
        "used": used,
        "limit": limit,
        "usable": usable,
        "checked_at": now,
        "expires_at": now + 600 if expires_at is None else expires_at,
        "consumer": consumer,
        "consumed_at": 0.0 if not consumer else now,
    }


def test_pick_marks_in_use_and_excludes():
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        try:
            pool._write_items(
                [
                    _seed_item(expanded_url="http://Default.a:TOKEN@h:2261", exit_ip="10.0.0.1"),
                    _seed_item(expanded_url="http://Default.b:TOKEN@h:2261", exit_ip="10.0.0.2"),
                ]
            )
            picked = pool.pick_usable("W1")
            assert picked is not None
            assert picked["exit_ip"] == "10.0.0.1"
            assert picked["consumer"] == "W1"
            # 再次 pick 不再返回已占用项
            second = pool.pick_usable("W2")
            assert second is not None
            assert second["exit_ip"] == "10.0.0.2"
            assert pool.pick_usable("W3") is None
            # exclude_ips 生效
            pool._write_items(
                [_seed_item(expanded_url="http://Default.c:TOKEN@h:2261", exit_ip="10.0.0.9")]
            )
            assert pool.pick_usable("W4", frozenset({"10.0.0.9"})) is None
        finally:
            pool._POOL_FILE = previous


def test_pick_skips_unusable_expired_and_preserves_usable():
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        try:
            pool._write_items(
                [
                    _seed_item(
                        expanded_url="http://Default.u1:TOKEN@h:2261",
                        exit_ip="10.0.0.1",
                        usable=False,
                    ),
                    _seed_item(
                        expanded_url="http://Default.u2:TOKEN@h:2261",
                        exit_ip="10.0.0.2",
                        expires_at=pool.time.time() - 1,
                    ),
                    _seed_item(expanded_url="http://Default.u3:TOKEN@h:2261", exit_ip="10.0.0.3"),
                ]
            )
            picked = pool.pick_usable("W1")
            assert picked is not None
            assert picked["exit_ip"] == "10.0.0.3"
        finally:
            pool._POOL_FILE = previous


def test_remove_item():
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        try:
            item = _seed_item(expanded_url="http://Default.a:TOKEN@h:2261", exit_ip="10.0.0.1")
            pool._write_items([item])
            assert pool.remove_item(item["id"]) is True
            assert pool._read_items() == []
            assert pool.remove_item(item["id"]) is False
        finally:
            pool._POOL_FILE = previous


def test_refresh_cleans_expired_and_recomputes_usable():
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        previous_usage_file = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        try:
            now = pool.time.time()
            pool._write_items(
                [
                    _seed_item(
                        expanded_url="http://Default.e1:TOKEN@h:2261",
                        exit_ip="10.0.0.1",
                        expires_at=now - 1,
                    ),
                    _seed_item(
                        expanded_url="http://Default.e2:TOKEN@h:2261",
                        exit_ip="10.0.0.2",
                        consumer="W9",
                    ),
                    _seed_item(expanded_url="http://Default.e3:TOKEN@h:2261", exit_ip="10.0.0.3"),
                ]
            )
            # 10.0.0.3 已到上限（覆盖上限 10）→ refresh 后变不可用
            ip_usage_store.record_ip_usage("10.0.0.3", times=10)
            ip_usage_store.set_ip_usage_limit("10.0.0.3", 10)
            stats = pool.refresh_pool()
            assert stats["total"] == 2  # 过期项被清理
            assert stats["in_use"] == 1  # W9 占用项保留
            items = pool._read_items()
            by_ip = {it["exit_ip"]: it for it in items}
            assert by_ip["10.0.0.3"]["usable"] is False
        finally:
            pool._POOL_FILE = previous
            ip_usage_store._USAGE_FILE = previous_usage_file


def test_probe_one_builds_item():
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        previous_usage_file = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        previous_resolve = browser_session._resolve_proxy_exit_ip
        previous_blocked = browser_session.is_blocked_exit_ip
        previous_limit = pool._usage_limit
        try:
            ip_usage_store.record_ip_usage("10.0.0.7", times=4)
            browser_session._resolve_proxy_exit_ip = lambda *a, **k: "10.0.0.7"
            browser_session.is_blocked_exit_ip = lambda *a, **k: (False, "")
            pool._usage_limit = lambda ip: 10
            item = pool.probe_one(
                "http://Default.{session}:TOKEN@1.2.3.4:2261",
                "http://Default.ipool-2-0:TOKEN@1.2.3.4:2261",
                ttl=600,
            )
            assert item is not None
            assert item["exit_ip"] == "10.0.0.7"
            assert item["used"] == 4
            assert item["limit"] == 10
            assert item["usable"] is True
            assert item["expires_at"] > item["checked_at"]
        finally:
            pool._POOL_FILE = previous
            ip_usage_store._USAGE_FILE = previous_usage_file
            browser_session._resolve_proxy_exit_ip = previous_resolve
            browser_session.is_blocked_exit_ip = previous_blocked
            pool._usage_limit = previous_limit


def test_probe_one_marks_over_limit_and_blocked():
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        previous_usage_file = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        previous_resolve = browser_session._resolve_proxy_exit_ip
        previous_blocked = browser_session.is_blocked_exit_ip
        previous_limit = pool._usage_limit
        try:
            browser_session._resolve_proxy_exit_ip = lambda *a, **k: "10.0.0.8"
            browser_session.is_blocked_exit_ip = lambda *a, **k: (False, "")
            pool._usage_limit = lambda ip: 10

            ip_usage_store.record_ip_usage("10.0.0.8", times=5)
            item = pool.probe_one("http://Default.{session}:TOKEN@h:2261", "http://Default.p1:TOKEN@h:2261")
            assert item is not None and item["usable"] is True

            # 计数达到上限 → 不可用
            ip_usage_store.record_ip_usage("10.0.0.8", times=5)
            item = pool.probe_one("http://Default.{session}:TOKEN@h:2261", "http://Default.p2:TOKEN@h:2261")
            assert item is not None and item["usable"] is False
            assert item["used"] == 10 and item["limit"] == 10

            # 黑名单 → 不入池
            browser_session.is_blocked_exit_ip = lambda *a, **k: (True, "AS5650")
            assert pool.probe_one("http://Default.{session}:TOKEN@h:2261", "http://Default.p3:TOKEN@h:2261") is None

            # 探测失败 → 不入池
            browser_session.is_blocked_exit_ip = lambda *a, **k: (False, "")

            def _boom(*a, **k):
                raise RuntimeError("no ip")

            browser_session._resolve_proxy_exit_ip = _boom
            assert pool.probe_one("http://Default.{session}:TOKEN@h:2261", "http://Default.p4:TOKEN@h:2261") is None
        finally:
            pool._POOL_FILE = previous
            ip_usage_store._USAGE_FILE = previous_usage_file
            browser_session._resolve_proxy_exit_ip = previous_resolve
            browser_session.is_blocked_exit_ip = previous_blocked
            pool._usage_limit = previous_limit


def test_probe_one_skips_soft_blacklisted():
    """空页临时冷却/永久拉黑的出口不入可用池。"""
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        previous_usage_file = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        previous_resolve = browser_session._resolve_proxy_exit_ip
        previous_blocked = browser_session.is_blocked_exit_ip
        previous_limit = pool._usage_limit
        try:
            browser_session._resolve_proxy_exit_ip = lambda *a, **k: "10.0.0.77"
            browser_session.is_blocked_exit_ip = lambda *a, **k: (False, "")
            pool._usage_limit = lambda ip: 30

            # 首次空页 → 临时冷却 → 探测不入池
            ip_usage_store.record_blank_page("10.0.0.77")
            assert (
                pool.probe_one(
                    "http://Default.{session}:TOKEN@h:2261",
                    "http://Default.cool1:TOKEN@h:2261",
                )
                is None
            )
            # 冷却清除后恢复入池
            ip_usage_store.clear_soft_blacklist("10.0.0.77")
            item = pool.probe_one(
                "http://Default.{session}:TOKEN@h:2261",
                "http://Default.cool2:TOKEN@h:2261",
            )
            assert item is not None and item["usable"] is True

            # 累计 2 次空页 → 永久拉黑 → 探测不入池
            browser_session._resolve_proxy_exit_ip = lambda *a, **k: "10.0.0.78"
            ip_usage_store.record_blank_page("10.0.0.78")
            ip_usage_store.record_blank_page("10.0.0.78")
            assert ip_usage_store.get_ip_usage("10.0.0.78") == ip_usage_store.SOFT_BLACKLIST_COUNT
            assert (
                pool.probe_one(
                    "http://Default.{session}:TOKEN@h:2261",
                    "http://Default.cool3:TOKEN@h:2261",
                )
                is None
            )
        finally:
            pool._POOL_FILE = previous
            ip_usage_store._USAGE_FILE = previous_usage_file
            browser_session._resolve_proxy_exit_ip = previous_resolve
            browser_session.is_blocked_exit_ip = previous_blocked
            pool._usage_limit = previous_limit


def test_probe_round_dedupes_and_merges():
    with tempfile.TemporaryDirectory() as tmp:
        previous = _use_temp_pool(tmp)
        from webui import proxy_store as ps

        previous_snapshot = ps.worker_proxy_snapshot
        previous_probe = pool.probe_one
        try:
            ps.worker_proxy_snapshot = lambda: {
                "configured": True,
                "urls": ["http://Default.{session}:TOKEN@1.2.3.4:2261"],
            }
            seen = {}

            def fake_probe(template_url, expanded_url, ttl, log_callback=None):
                seen[expanded_url] = seen.get(expanded_url, 0) + 1
                now = pool.time.time()
                return {
                    "id": pool._item_id(expanded_url),
                    "template_url": template_url,
                    "expanded_url": expanded_url,
                    "exit_ip": "10.0.0.9",
                    "used": 0,
                    "limit": 10,
                    "usable": True,
                    "checked_at": now,
                    "expires_at": now + 600,
                    "consumer": "",
                    "consumed_at": 0.0,
                }

            pool.probe_one = fake_probe
            stats = pool.probe_round(target_count=4, concurrency=2, ttl=600)
            assert stats["total"] == 4
            # 每身份只探测一次（同轮内无重复）
            assert all(v == 1 for v in seen.values())
            # 第二轮用新身份继续补充（跨轮 stamp 变化），池只增不减
            stats = pool.probe_round(target_count=4, concurrency=2, ttl=600)
            assert stats["total"] == 8
            assert all(v == 1 for v in seen.values())
            # 池空时（无代理模板）不报错、不清空已有项
            ps.worker_proxy_snapshot = lambda: {"configured": False, "urls": []}
            stats = pool.probe_round(target_count=4, concurrency=2, ttl=600)
            assert stats["total"] == 8
        finally:
            pool._POOL_FILE = previous
            ps.worker_proxy_snapshot = previous_snapshot
            pool.probe_one = previous_probe


if __name__ == "__main__":
    test_pick_marks_in_use_and_excludes()
    test_pick_skips_unusable_expired_and_preserves_usable()
    test_remove_item()
    test_refresh_cleans_expired_and_recomputes_usable()
    test_probe_one_builds_item()
    test_probe_one_marks_over_limit_and_blocked()
    test_probe_one_skips_soft_blacklisted()
    test_probe_round_dedupes_and_merges()
    print("OK ip ready pool")
