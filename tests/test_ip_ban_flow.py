# -*- coding: utf-8 -*-
"""注册限流拉黑闭环：限流不计失败 + 出口拉黑/超限 + 池项禁用。"""
from __future__ import annotations

import json
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
            # 成功即短冷静期：暂时不参与取口，冷静期结束自动回到可用可信池
            assert ip_health.cooldown_remaining("1.2.3.4") > 0
            assert ip_health.available_trusted_exits() == []
            with ip_health._HEALTH_LOCK:
                data = ip_health._read()
                data["exits"]["1.2.3.4"]["cooldown_until"] = 0
                ip_health._write(data)
            assert [e["ip"] for e in ip_health.available_trusted_exits()] == ["1.2.3.4"]

            # 成功过的出口遇到限流不再终身拉黑，只进最长冷静期
            ip_health.ban_exit("1.2.3.4", reason="signup-throttle")
            assert "1.2.3.4" not in ip_health.bad_ips()
            health = ip_health.get_exit_health("1.2.3.4")
            assert not health.get("banned")
            assert health["cooldown_reason"] == "signup-throttle"
            assert ip_health.cooldown_remaining("1.2.3.4") > 3600
            assert ip_health.trusted_exits()[0]["ip"] == "1.2.3.4"
            assert ip_health.stats()["available_trusted"] == 0

            # 从未成功过的出口仍然单次拉黑
            ip_health.ban_exit("8.8.8.8", reason="signup-throttle")
            assert "8.8.8.8" in ip_health.bad_ips()
            assert ip_health.get_exit_health("8.8.8.8")["banned"] is True

            # 该出口再次注册成功 → 自动解封（避免手动恢复）
            ip_health.record_exit_result("8.8.8.8", True)
            assert "8.8.8.8" not in ip_health.bad_ips()
            assert "8.8.8.8" in [e["ip"] for e in ip_health.trusted_exits()]
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
            # 限流不计失败：健康档案的失败计数保持 0
            assert int(ip_health.get_exit_health("9.9.9.9").get("fails") or 0) == 0
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


def test_failure_cooldown_escalates_for_known_good_ip():
    with tempfile.TemporaryDirectory() as tmp:
        old_health = ip_health._HEALTH_FILE
        old_meta = ip_health._ipapi_meta
        ip_health._HEALTH_FILE = Path(tmp) / "ip_health.json"
        ip_health._ipapi_meta = lambda ip: {}
        try:
            ip_health.record_exit_result("7.7.7.7", True)
            assert ip_health.cooldown_remaining("7.7.7.7") <= 900
            assert ip_health.get_exit_health("7.7.7.7")["fail_streak"] == 0

            def _clear_cooldown(ip):
                with ip_health._HEALTH_LOCK:
                    data = ip_health._read()
                    data["exits"][ip]["cooldown_until"] = 0
                    ip_health._write(data)

            _clear_cooldown("7.7.7.7")
            ip_health.record_exit_result("7.7.7.7", False)
            first = ip_health.cooldown_remaining("7.7.7.7")
            assert 3000 < first <= 3600
            assert ip_health.get_exit_health("7.7.7.7")["fail_streak"] == 1

            _clear_cooldown("7.7.7.7")
            ip_health.record_exit_result("7.7.7.7", False)
            second = ip_health.cooldown_remaining("7.7.7.7")
            assert second > first
            assert ip_health.get_exit_health("7.7.7.7")["fail_streak"] == 2
            # 成功过的出口即使连续失败也不会进 bad_ips
            assert "7.7.7.7" not in ip_health.bad_ips()

            ip_health.record_exit_result("7.7.7.7", True)
            health = ip_health.get_exit_health("7.7.7.7")
            assert health["fail_streak"] == 0
            assert ip_health.cooldown_remaining("7.7.7.7") <= 900
        finally:
            ip_health._HEALTH_FILE = old_health
            ip_health._ipapi_meta = old_meta


def test_pick_usable_prefers_trusted_switch():
    with tempfile.TemporaryDirectory() as tmp:
        old_pool = pool._POOL_FILE
        old_health = ip_health._HEALTH_FILE
        pool._POOL_FILE = Path(tmp) / "ip_ready_pool.json"
        ip_health._HEALTH_FILE = Path(tmp) / "ip_health.json"
        try:
            now = pool.time.time()
            base = {
                "usable": True, "checked_at": now, "expires_at": now + 600,
                "consumer": "", "consumed_at": 0.0, "used": 0, "limit": 10,
            }
            pool._write_items([
                {**base, "id": "p", "exit_ip": "10.1.1.1",
                 "expanded_url": "http://Default.p:TOKEN@h:1", "trusted": False},
                {**base, "id": "t", "exit_ip": "10.1.1.2",
                 "expanded_url": "http://Default.t:TOKEN@h:1", "trusted": True},
            ])
            assert pool.pick_usable("W1", prefer_trusted=False)["exit_ip"] == "10.1.1.1"
            pool._write_items([
                {**base, "id": "p", "exit_ip": "10.1.1.1",
                 "expanded_url": "http://Default.p:TOKEN@h:1", "trusted": False},
                {**base, "id": "t", "exit_ip": "10.1.1.2",
                 "expanded_url": "http://Default.t:TOKEN@h:1", "trusted": True},
            ])
            assert pool.pick_usable("W2", prefer_trusted=True)["exit_ip"] == "10.1.1.2"
        finally:
            pool._POOL_FILE = old_pool
            ip_health._HEALTH_FILE = old_health


def test_pool_skips_cooling_and_reports_alternative():
    with tempfile.TemporaryDirectory() as tmp:
        old_pool = pool._POOL_FILE
        old_health = ip_health._HEALTH_FILE
        old_meta = ip_health._ipapi_meta
        pool._POOL_FILE = Path(tmp) / "ip_ready_pool.json"
        ip_health._HEALTH_FILE = Path(tmp) / "ip_health.json"
        ip_health._ipapi_meta = lambda ip: {}
        try:
            now = pool.time.time()
            pool._write_items([
                {"id": "a", "exit_ip": "10.2.2.1", "expanded_url": "http://a",
                 "usable": True, "trusted": True, "checked_at": now,
                 "expires_at": now + 600, "consumer": "", "consumed_at": 0.0},
                {"id": "b", "exit_ip": "10.2.2.2", "expanded_url": "http://b",
                 "usable": True, "trusted": False, "checked_at": now,
                 "expires_at": now + 600, "consumer": "", "consumed_at": 0.0},
            ])
            ip_health.cool_exit("10.2.2.1", 600, reason="test")
            assert pool.pick_usable("W1")["exit_ip"] == "10.2.2.2"
            assert pool.has_usable_alternative("10.2.2.2") is False
        finally:
            pool._POOL_FILE = old_pool
            ip_health._HEALTH_FILE = old_health
            ip_health._ipapi_meta = old_meta


def test_trusted_priority_threshold_reads_live_config():
    with tempfile.TemporaryDirectory() as tmp:
        old_health = ip_health._HEALTH_FILE
        old_pool = pool._POOL_FILE
        old_config_file = register.CONFIG_FILE
        old_meta = ip_health._ipapi_meta
        ip_health._HEALTH_FILE = Path(tmp) / "log" / "ip_health.json"
        pool._POOL_FILE = Path(tmp) / "log" / "ip_ready_pool.json"
        register.CONFIG_FILE = str(Path(tmp) / "config.json")
        ip_health._ipapi_meta = lambda ip: {}
        try:
            for ip in ("9.9.9.1", "9.9.9.2"):
                ip_health.record_exit_result(ip, True)
                with ip_health._HEALTH_LOCK:
                    data = ip_health._read()
                    data["exits"][ip]["cooldown_until"] = 0
                    ip_health._write(data)
            assert len(ip_health.available_trusted_exits()) == 2

            def _write_config(min_trusted: int):
                (Path(tmp) / "config.json").write_text(
                    json.dumps({"ip_trusted_priority_min": min_trusted}),
                    encoding="utf-8",
                )

            # 阈值 3：可信可用仅 2，按策略先用可用池
            _write_config(3)
            assert register.trusted_priority_min() == 3
            assert register.trusted_priority_active() is False
            # 面板把阈值降到 2：无需重启，立即切到可信优先
            _write_config(2)
            assert register.trusted_priority_active() is True
            # 0=关闭策略
            _write_config(0)
            assert register.trusted_priority_active() is False
        finally:
            ip_health._HEALTH_FILE = old_health
            pool._POOL_FILE = old_pool
            register.CONFIG_FILE = old_config_file
            ip_health._ipapi_meta = old_meta


def test_verify_due_sessions_marks_alive_and_demotes_after_dead_streak():
    with tempfile.TemporaryDirectory() as tmp:
        old_health = ip_health._HEALTH_FILE
        old_pool = pool._POOL_FILE
        old_verify = ip_health.verify_exit_session
        old_meta = ip_health._ipapi_meta
        ip_health._HEALTH_FILE = Path(tmp) / "log" / "ip_health.json"
        pool._POOL_FILE = Path(tmp) / "log" / "ip_ready_pool.json"
        ip_health._ipapi_meta = lambda ip: {}
        try:
            ip_health.record_exit_result(
                "6.6.6.6", True, proxy_url="http://Default.t:TOKEN@h:2261"
            )
            with ip_health._HEALTH_LOCK:
                data = ip_health._read()
                data["exits"]["6.6.6.6"]["cooldown_until"] = 0
                data["exits"]["6.6.6.6"]["session_checked_at"] = 0
                ip_health._write(data)

            ip_health.verify_exit_session = lambda e, timeout=8.0: (True, "6.6.6.6")
            result = ip_health.verify_due_sessions(max_age=0, limit=5)
            assert result == {"checked": 1, "alive": 1, "dead": 0}
            assert ip_health.get_exit_health("6.6.6.6")["session_alive"] is True
            assert pool.get_pool_state()["stats"]["trusted"] == 1

            # 连续两次失效达到降级线：不再算可信，且池项下放不可用
            ip_health.verify_exit_session = lambda e, timeout=8.0: (False, "6.6.6.7")
            for _ in range(2):
                with ip_health._HEALTH_LOCK:
                    data = ip_health._read()
                    data["exits"]["6.6.6.6"]["session_checked_at"] = 0
                    ip_health._write(data)
                ip_health.verify_due_sessions(max_age=0, limit=5)
            health = ip_health.get_exit_health("6.6.6.6")
            assert health["session_alive"] is False
            assert health["session_dead_streak"] == 2
            assert "6.6.6.6" not in [
                e["ip"] for e in ip_health.trusted_exits()
            ]
            items = pool.get_pool_state()["items"]
            assert all(
                not it["trusted"] for it in items if it["exit_ip"] == "6.6.6.6"
            )
        finally:
            ip_health._HEALTH_FILE = old_health
            pool._POOL_FILE = old_pool
            ip_health.verify_exit_session = old_verify
            ip_health._ipapi_meta = old_meta


def test_legacy_banned_flag_ignored_for_successful_exit():
    with tempfile.TemporaryDirectory() as tmp:
        old_health = ip_health._HEALTH_FILE
        old_meta = ip_health._ipapi_meta
        old_usage = ip_usage_store._USAGE_FILE
        ip_health._HEALTH_FILE = Path(tmp) / "ip_health.json"
        ip_health._ipapi_meta = lambda ip: {}
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        try:
            ip_health.record_exit_result(
                "5.5.5.5", True, proxy_url="http://Default.t:TOKEN@h:2261"
            )
            # 旧版本限流误伤：使用计数被置永久软拉黑哨兵
            ip_usage_store.soft_blacklist_ip("5.5.5.5")
            assert ip_usage_store.is_soft_blacklisted("5.5.5.5")
            # 模拟旧版本数据：成功过但仍残留 banned 标记
            with ip_health._HEALTH_LOCK:
                data = ip_health._read()
                data["exits"]["5.5.5.5"]["banned"] = True
                data["exits"]["5.5.5.5"]["ban_reason"] = "signup-throttle"
                data["exits"]["5.5.5.5"]["cooldown_until"] = 0
                ip_health._write(data)
            assert "5.5.5.5" not in ip_health.bad_ips()
            assert "5.5.5.5" in [e["ip"] for e in ip_health.trusted_exits()]
            assert ip_health.stats()["trusted"] == 1
            # 读取可信出口时纠正旧哨兵，成功过的 IP 恢复可用
            assert ip_health.trusted_exits()[0]["ip"] == "5.5.5.5"
            assert not ip_usage_store.is_soft_blacklisted("5.5.5.5")
            assert ip_usage_store.get_ip_usage("5.5.5.5") == 0
            # 从未成功的 banned 仍有效
            ip_health.ban_exit("4.4.4.4", reason="signup-throttle")
            assert "4.4.4.4" in ip_health.bad_ips()
        finally:
            ip_health._HEALTH_FILE = old_health
            ip_health._ipapi_meta = old_meta
            ip_usage_store._USAGE_FILE = old_usage


if __name__ == "__main__":
    test_ban_exit_blocks_pick_and_unbans_on_success()
    test_block_exit_disables_pool_items()
    test_throttle_not_counted_as_fail()
    test_throttle_branch_is_immediate_and_blacklists()
    test_is_signup_throttle_markers()
    test_handle_signup_throttle_blacklists_everywhere()
    test_failure_cooldown_escalates_for_known_good_ip()
    test_pick_usable_prefers_trusted_switch()
    test_pool_skips_cooling_and_reports_alternative()
    test_trusted_priority_threshold_reads_live_config()
    test_verify_due_sessions_marks_alive_and_demotes_after_dead_streak()
    test_legacy_banned_flag_ignored_for_successful_exit()
    print("OK ip ban flow")
