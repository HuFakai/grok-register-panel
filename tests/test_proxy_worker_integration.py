# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register
from webui import proxy_store


def test_worker_hot_reload_only_changes_next_account_proxy():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    previous_workers = register.config.get("register_workers")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            proxy_store.LEGACY_PATH.write_text(
                "http://legacy.example:7890\n",
                encoding="utf-8",
            )
            register.config["proxy"] = "http://legacy.example:7890"
            register.config["register_workers"] = 2

            assert register.load_proxy_pool(str(proxy_store.LEGACY_PATH)) == [
                "http://legacy.example:7890"
            ]

            imported = proxy_store.import_proxies(
                "a.example:8000:user:pass\nb.example:8001:user:pass"
            )
            assert register.load_proxy_pool() == []
            # 未开启本地回退时：未知/未探测代理不得下发到 worker
            register.config["proxy_fallback_to_local"] = False
            try:
                register.pick_proxy_for_worker(0, 0)
            except RuntimeError as exc:
                assert "没有健康且启用的代理" in str(exc)
            else:
                raise AssertionError("unknown managed proxies must not reach workers")

            # 开启本地回退后：无健康代理改用 config.proxy（留空则直连）
            register.config["proxy_fallback_to_local"] = True
            assert register.pick_proxy_for_worker(0, 0) == "http://legacy.example:7890"
            register.config["proxy_fallback_to_local"] = False

            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"198.51.100.{10 + offset}",
                        "asn": 64510 + offset,
                        "asn_org": "Worker Test",
                        "latency_ms": 100 + offset,
                        "checked_at": "2026-07-30T00:00:00Z",
                    },
                )

            current = register.pick_proxy_for_worker(0, 0)
            register.set_thread_proxy(current)
            assert "a.example:8000" in current
            proxy_store.record_proxy_result(current, "risk", "policy deny")

            # State changes do not mutate the current account's bound proxy.
            assert register.get_thread_proxy() == current
            next_account = register.pick_proxy_for_worker(0, 1)
            assert next_account != current
            assert "b.example:8001" in next_account
        finally:
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy
            register.config["register_workers"] = previous_workers
            register.config.pop("proxy_fallback_to_local", None)


def test_resin_template_expands_per_worker_and_rotation():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            imported = proxy_store.import_proxies(
                "socks5h://Default.{account}:token@127.0.0.1:2260"
            )
            proxy_store._apply_probe_result(
                imported["imported_ids"][0],
                {
                    "ok": True,
                    "exit_ip": "198.51.100.21",
                    "asn": 64521,
                    "asn_org": "Resin Test",
                    "latency_ms": 80,
                    "checked_at": "2026-08-07T00:00:00Z",
                },
            )
            register._proxy_worker_assignments.clear()
            first = register.pick_proxy_for_worker(0, 0)
            second_worker = register.pick_proxy_for_worker(1, 0)
            next_round = register.pick_proxy_for_worker(0, 1)
            assert "Default.grokreg-w1-r0" in first
            assert "Default.grokreg-w2-r0" in second_worker
            assert "Default.grokreg-w1-r1" in next_round
            assert len({first, second_worker, next_round}) == 3
        finally:
            register._proxy_worker_assignments.clear()
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths


def test_pick_proxy_skips_other_worker_lease():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            register.config["proxy"] = "http://legacy.example:7890"
            imported = proxy_store.import_proxies(
                "a.example:8000:user:pass\nb.example:8001:user:pass"
            )
            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"198.51.100.{10 + offset}",
                        "asn": 64510 + offset,
                        "asn_org": "Worker Test",
                        "latency_ms": 100 + offset,
                        "checked_at": "2026-07-30T00:00:00Z",
                    },
                )
            register.release_proxy_lease()
            first = register.pick_proxy_for_worker(0, 0)
            # (1+1) % 2 == 0 would collide with worker 0 without leases
            second = register.pick_proxy_for_worker(1, 1)
            assert first != second
        finally:
            register.release_proxy_lease()
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy


def test_pick_proxy_risk_rotate_skips_self_and_others():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            register.config["proxy"] = "http://legacy.example:7890"
            imported = proxy_store.import_proxies(
                "a.example:8000:user:pass\n"
                "b.example:8001:user:pass\n"
                "c.example:8002:user:pass"
            )
            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"198.51.100.{10 + offset}",
                        "asn": 64510 + offset,
                        "asn_org": "Worker Test",
                        "latency_ms": 100 + offset,
                        "checked_at": "2026-07-30T00:00:00Z",
                    },
                )
            register.release_proxy_lease()
            w0 = register.pick_proxy_for_worker(0, 0)
            w1 = register.pick_proxy_for_worker(1, 0)
            rotated = register.pick_proxy_for_worker(0, 1)
            assert rotated != w0
            assert rotated != w1
        finally:
            register.release_proxy_lease()
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy


def test_pick_proxy_prefers_ip_unused_for_40_minutes():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            register.config["proxy"] = "http://legacy.example:7890"
            imported = proxy_store.import_proxies(
                "127.0.0.1:8003\n127.0.0.1:8004\n127.0.0.1:8005"
            )
            from datetime import datetime, timedelta, timezone

            now = datetime.now(timezone.utc)
            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"203.0.113.{offset + 1}",
                        "asn": 64510 + offset,
                        "asn_org": "Home",
                        "latency_ms": 100,
                        "checked_at": "2026-08-15T00:00:00Z",
                    },
                )
            state = json.loads(proxy_store.STATE_PATH.read_text(encoding="utf-8"))
            # first two IPs used 2 minutes ago; third used 50 minutes ago
            state["items"][0]["last_used_at"] = (now - timedelta(minutes=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            state["items"][1]["last_used_at"] = (now - timedelta(minutes=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            state["items"][2]["last_used_at"] = (now - timedelta(minutes=50)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            proxy_store.STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
            register.release_proxy_lease()
            picked = register.pick_proxy_for_worker(0, 0)
            assert picked.endswith(":8005")
        finally:
            register.release_proxy_lease()
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy


def test_reserve_signup_submit_slot_staggers():
    register._next_submit_at = 0.0
    first = register.reserve_signup_submit_slot(7)
    second = register.reserve_signup_submit_slot(7)
    third = register.reserve_signup_submit_slot(7)
    assert first == 0
    assert 6 <= second <= 8
    assert 13 <= third <= 16


if __name__ == "__main__":
    test_worker_hot_reload_only_changes_next_account_proxy()
    test_resin_template_expands_per_worker_and_rotation()
    test_pick_proxy_skips_other_worker_lease()
    test_pick_proxy_risk_rotate_skips_self_and_others()
    test_pick_proxy_prefers_ip_unused_for_40_minutes()
    test_reserve_signup_submit_slot_staggers()
    print("OK proxy worker integration")
