# -*- coding: utf-8 -*-
"""注册限流拉黑闭环：限流不计失败 + 出口拉黑/超限 + 池项禁用。"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register
import ip_usage_store
import results_store
import webui.ip_health as ip_health
import webui.ip_ready_pool as pool


def test_ban_exit_blocks_pick_and_unbans_on_success():
    with tempfile.TemporaryDirectory() as tmp:
        old_health = ip_health._HEALTH_FILE
        old_meta = ip_health._ipapi_meta
        ip_health._HEALTH_FILE = Path(tmp) / "ip_health.json"
        ip_health._ipapi_meta = lambda ip: {}
        try:
            ip_health.record_exit_result(
                "1.2.3.4", True, proxy_url="http://u:p@1.2.3.4:1"
            )
            assert "1.2.3.4" not in ip_health.bad_ips()
            assert [e["ip"] for e in ip_health.trusted_exits()] == ["1.2.3.4"]

            ip_health.ban_exit("1.2.3.4", reason="signup-throttle")
            assert "1.2.3.4" in ip_health.bad_ips()
            assert ip_health.trusted_exits() == []
            assert ip_health.stats()["trusted"] == 0
            health = ip_health.get_exit_health("1.2.3.4")
            assert health["banned"] is True
            assert health["ban_reason"] == "signup-throttle"

            # 该出口再次注册成功 → 自动解封（避免手动恢复）
            ip_health.record_exit_result("1.2.3.4", True)
            assert "1.2.3.4" not in ip_health.bad_ips()
            assert [e["ip"] for e in ip_health.trusted_exits()] == ["1.2.3.4"]
        finally:
            ip_health._HEALTH_FILE = old_health
            ip_health._ipapi_meta = old_meta


def test_block_exit_disables_pool_items():
    with tempfile.TemporaryDirectory() as tmp:
        old_pool = pool._POOL_FILE
        pool._POOL_FILE = Path(tmp) / "ip_ready_pool.json"
        try:
            now = pool.time.time()
            items = [
                {
                    "id": "a", "exit_ip": "5.6.7.8",
                    "expanded_url": "http://x@5.6.7.8:1",
                    "usable": True, "trusted": True, "checked_at": now,
                    "expires_at": now + 600, "consumer": "", "consumed_at": 0.0,
                },
                {
                    "id": "b", "exit_ip": "5.6.7.8",
                    "expanded_url": "http://y@5.6.7.8:2",
                    "usable": True, "trusted": False, "checked_at": now,
                    "expires_at": now + 600, "consumer": "", "consumed_at": 0.0,
                },
            ]
            pool._write_items(items)
            assert pool.pick_usable("test") is not None
            # 上面 pick 占用了 a 项，先重置再验证 block 后完全不可取
            pool._write_items(items)
            assert pool.block_exit("5.6.7.8", reason="signup-throttle") is True
            assert pool.pick_usable("test") is None
            state = {it["id"]: it for it in pool._read_items()}
            assert state["a"]["usable"] is False and state["a"]["trusted"] is False
            assert state["b"]["usable"] is False
            assert state["b"]["blocked_reason"] == "signup-throttle"
        finally:
            pool._POOL_FILE = old_pool


def test_throttle_not_counted_as_fail():
    with tempfile.TemporaryDirectory() as tmp:
        old_result = register._RESULT_LOG_PATH
        old_results_file = results_store._RESULTS_FILE
        old_archive = results_store._ARCHIVE_SUMMARY_FILE
        register._RESULT_LOG_PATH = str(Path(tmp) / "register_results.jsonl")
        results_store._RESULTS_FILE = Path(register._RESULT_LOG_PATH)
        results_store._ARCHIVE_SUMMARY_FILE = Path(tmp) / "register_results_archive.json"
        try:
            register.record_register_result(
                "throttle",
                "a@b.c",
                kind="throttle",
                detail="Email sign-up isn't available",
            )
            assert results_store.count_results() == {"ok": 0, "fail": 0, "risk": 0}
            assert Path(register._RESULT_LOG_PATH).is_file()
            register.record_register_result("fail", "a@b.c", kind="other", detail="boom")
            assert results_store.count_results()["fail"] == 1
        finally:
            register._RESULT_LOG_PATH = old_result
            results_store._RESULTS_FILE = old_results_file
            results_store._ARCHIVE_SUMMARY_FILE = old_archive


def test_throttle_branch_is_immediate_and_blacklists():
    source = (ROOT / "grok_register_ttk.py").read_text(encoding="utf-8")
    assert "退避 {backoff}s 后同槽位换口重试" not in source
    assert "sleep_with_cancel(backoff" not in source
    assert "已拉黑并置超限" in source
    assert "soft_blacklist_ip(active_ip)" in source
    assert "ban_exit(" in source
    assert "ip_ready_pool.block_exit(" in source
    assert '"throttle"' in source
    # 判定与处置都收敛到共享辅助函数，CLI worker 与 GUI 两条路径口径一致
    assert source.count("is_signup_throttle(") >= 3
    assert source.count("handle_signup_throttle(") >= 3
    mon = (ROOT / "webui" / "monitor.py").read_text(encoding="utf-8")
    assert 'elif st == "throttle":' in mon


def test_is_signup_throttle_markers():
    assert register.is_signup_throttle(
        "Email sign-up isn't available（邮箱注册被限流，稍后重试）"
    )
    assert register.is_signup_throttle("Email sign-up isn’t available right now.")
    assert register.is_signup_throttle("邮箱注册被限流")
    assert not register.is_signup_throttle("验证码超时")
    assert not register.is_signup_throttle(None)


def test_handle_signup_throttle_blacklists_everywhere():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        old_usage = ip_usage_store._USAGE_FILE
        old_health = ip_health._HEALTH_FILE
        old_meta = ip_health._ipapi_meta
        old_pool = pool._POOL_FILE
        old_result = register._RESULT_LOG_PATH
        old_results_file = results_store._RESULTS_FILE
        old_archive = results_store._ARCHIVE_SUMMARY_FILE
        ip_usage_store._USAGE_FILE = tmp_path / "ip_usage.json"
        ip_health._HEALTH_FILE = tmp_path / "ip_health.json"
        ip_health._ipapi_meta = lambda ip: {}
        pool._POOL_FILE = tmp_path / "ip_ready_pool.json"
        register._RESULT_LOG_PATH = str(tmp_path / "register_results.jsonl")
        results_store._RESULTS_FILE = Path(register._RESULT_LOG_PATH)
        results_store._ARCHIVE_SUMMARY_FILE = tmp_path / "archive.json"
        try:
            now = pool.time.time()
            pool._write_items([
                {
                    "id": "t1", "exit_ip": "9.9.9.9",
                    "expanded_url": "http://u:p@9.9.9.9:2261",
                    "usable": True, "trusted": True, "checked_at": now,
                    "expires_at": now + 600, "consumer": "", "consumed_at": 0.0,
                }
            ])
            logs = []
            handled = register.handle_signup_throttle(
                "9.9.9.9",
                email="a@b.c",
                detail="Email sign-up isn't available",
                worker="W1",
                log_callback=logs.append,
            )
            assert handled == "9.9.9.9"
            # 累计使用置超限 → 取口跳过
            assert ip_usage_store.get_ip_usage("9.9.9.9") == ip_usage_store.SOFT_BLACKLIST_COUNT
            assert ip_usage_store.is_soft_blacklisted("9.9.9.9")
            # 健康档案拉黑
            assert ip_health.get_exit_health("9.9.9.9")["banned"] is True
            assert "9.9.9.9" in ip_health.bad_ips()
            # 池项下线，不再被取到
            assert pool.pick_usable("test") is None
            # 只留审计行，不计失败
            assert results_store.count_results() == {"ok": 0, "fail": 0, "risk": 0}
            assert any("不计失败" in line for line in logs)
        finally:
            ip_usage_store._USAGE_FILE = old_usage
            ip_health._HEALTH_FILE = old_health
            ip_health._ipapi_meta = old_meta
            pool._POOL_FILE = old_pool
            register._RESULT_LOG_PATH = old_result
            results_store._RESULTS_FILE = old_results_file
            results_store._ARCHIVE_SUMMARY_FILE = old_archive


if __name__ == "__main__":
    test_ban_exit_blocks_pick_and_unbans_on_success()
    test_block_exit_disables_pool_items()
    test_throttle_not_counted_as_fail()
    test_throttle_branch_is_immediate_and_blacklists()
    test_is_signup_throttle_markers()
    test_handle_signup_throttle_blacklists_everywhere()
    print("OK ip ban flow")
