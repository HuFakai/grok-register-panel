# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import monitor


def test_ip_policy_control_round_trip_and_bounds():
    previous = monitor.CONTROL_FILE
    with tempfile.TemporaryDirectory() as tmp:
        monitor.CONTROL_FILE = Path(tmp) / "monitor_control.json"
        try:
            defaults = monitor.load_control()
            # 开关与 Sticky 时长已移除
            assert "ip_registration_limit_enabled" not in defaults
            assert "ip_rotation_seconds" not in defaults
            assert defaults["ip_failure_rotate_threshold"] == 3
            assert defaults["accounts_per_ip"] == 2

            saved = monitor.save_control(
                {
                    "accounts_per_ip": 0,  # 0=不限
                    "ip_failure_rotate_threshold": 8,
                    "ip_usage_limit": 50,
                }
            )
            assert saved["accounts_per_ip"] == 0
            assert saved["ip_failure_rotate_threshold"] == 8
            assert saved["ip_usage_limit"] == 50

            bounded = monitor.save_control(
                {
                    "accounts_per_ip": 999,
                    "ip_failure_rotate_threshold": 999,
                    "ip_usage_limit": 999999,
                }
            )
            assert bounded["accounts_per_ip"] == 20
            assert bounded["ip_failure_rotate_threshold"] == 20
            assert bounded["ip_usage_limit"] == 100000

            # 未知 key 直接丢弃（包括已删除的开关/时长）
            dropped = monitor.save_control(
                {
                    "ip_registration_limit_enabled": False,
                    "ip_rotation_seconds": 150,
                    "accounts_per_ip": 5,
                }
            )
            assert "ip_registration_limit_enabled" not in dropped
            assert "ip_rotation_seconds" not in dropped
            assert dropped["accounts_per_ip"] == 5
        finally:
            monitor.CONTROL_FILE = previous


def test_batch_and_add_count_have_no_upper_bound():
    previous = monitor.CONTROL_FILE
    with tempfile.TemporaryDirectory() as tmp:
        monitor.CONTROL_FILE = Path(tmp) / "monitor_control.json"
        try:
            big = monitor.save_control(
                {
                    "batch_count": 100000,
                    "add_count": 500000,
                }
            )
            assert big["batch_count"] == 100000
            assert big["add_count"] == 500000

            floor = monitor.save_control(
                {
                    "batch_count": 0,
                    "add_count": -5,
                }
            )
            assert floor["batch_count"] == 1
            assert floor["add_count"] == 1
        finally:
            monitor.CONTROL_FILE = previous


def test_base_ok_persists_through_save_control():
    """base_ok 必须落盘：snapshot 依赖它计算本次任务增量（ok_count - base_ok）。"""
    previous = monitor.CONTROL_FILE
    with tempfile.TemporaryDirectory() as tmp:
        monitor.CONTROL_FILE = Path(tmp) / "monitor_control.json"
        try:
            saved = monitor.save_control(
                {
                    "add_count": 1800,
                    "base_cpa": 0,
                    "target_cpa": 1800,
                    "base_ok": 1633,
                }
            )
            assert saved.get("base_ok") == 1633, "save_control 丢掉了 base_ok"
            loaded = monitor.load_control()
            assert loaded.get("base_ok") == 1633, "base_ok 未落盘，面板会回退 CPA 口径"
            assert loaded.get("target_cpa") == 1800
            assert loaded.get("add_count") == 1800
        finally:
            monitor.CONTROL_FILE = previous


if __name__ == "__main__":
    test_ip_policy_control_round_trip_and_bounds()
    test_batch_and_add_count_have_no_upper_bound()
    test_base_ok_persists_through_save_control()
    print("OK monitor_control")
