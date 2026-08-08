# -*- coding: utf-8 -*-
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as app


def test_rotation_policy_defaults_and_bounds():
    old = dict(app.config)
    try:
        app.config["accounts_per_ip"] = "2"
        assert app.get_ip_rotation_policy() == 2

        # 0=不限每 IP 账号数
        app.config["accounts_per_ip"] = "0"
        assert app.get_ip_rotation_policy() == 0

        app.config["accounts_per_ip"] = "999"
        assert app.get_ip_rotation_policy() == 20

        app.config["accounts_per_ip"] = "-3"
        assert app.get_ip_rotation_policy() == 0
    finally:
        app.config.clear()
        app.config.update(old)


def test_failure_threshold_bounds():
    old = dict(app.config)
    try:
        app.config["ip_failure_rotate_threshold"] = "3"
        assert app.get_ip_rotation_mode() == 3

        app.config["ip_failure_rotate_threshold"] = "0"
        assert app.get_ip_rotation_mode() == 1

        app.config["ip_failure_rotate_threshold"] = "999"
        assert app.get_ip_rotation_mode() == 20
    finally:
        app.config.clear()
        app.config.update(old)


def test_account_boundary_rotation_reason():
    common = dict(
        used_on_ip=1,
        accounts_per_ip=2,
        ip_usage=0,
        ip_usage_limit=0,
        consecutive_failures=2,
        failure_threshold=3,
    )
    # accounts_per_ip>0：配额满优先返回；连续失败阈值始终生效
    assert "配额" in app.ip_rotation_reason_after_slot(
        used_on_ip=2, accounts_per_ip=2,
        ip_usage=0, ip_usage_limit=0,
        consecutive_failures=0, failure_threshold=3,
    )
    assert app.ip_rotation_reason_after_slot(
        **common,
    ) == ""
    assert app.ip_rotation_reason_after_slot(
        used_on_ip=1, accounts_per_ip=2,
        ip_usage=0, ip_usage_limit=0,
        consecutive_failures=3, failure_threshold=3,
    ) == "连续失败 3/3"
    # accounts_per_ip=0：不判配额，只判连续失败
    assert app.ip_rotation_reason_after_slot(
        used_on_ip=999, accounts_per_ip=0,
        ip_usage=0, ip_usage_limit=0,
        consecutive_failures=1, failure_threshold=3,
    ) == ""
    assert app.ip_rotation_reason_after_slot(
        used_on_ip=999, accounts_per_ip=0,
        ip_usage=0, ip_usage_limit=0,
        consecutive_failures=3, failure_threshold=3,
    ) == "连续失败 3/3"


def test_ip_usage_limit_rotation_reason():
    # ip_usage_limit>0 且累计达到上限 → 必须换 IP（与配额/失败阈值无关）
    reason = app.ip_rotation_reason_after_slot(
        used_on_ip=0, accounts_per_ip=0,
        ip_usage=50, ip_usage_limit=50,
        consecutive_failures=0, failure_threshold=3,
    )
    assert reason == "IP累计使用 50/50"
    assert app.ip_rotation_reason_after_slot(
        used_on_ip=0, accounts_per_ip=0,
        ip_usage=49, ip_usage_limit=50,
        consecutive_failures=0, failure_threshold=3,
    ) == ""
    # 0=不限
    assert app.ip_rotation_reason_after_slot(
        used_on_ip=0, accounts_per_ip=0,
        ip_usage=999, ip_usage_limit=0,
        consecutive_failures=0, failure_threshold=3,
    ) == ""
    # 配额优先于累计使用
    assert "配额" in app.ip_rotation_reason_after_slot(
        used_on_ip=2, accounts_per_ip=2,
        ip_usage=99, ip_usage_limit=50,
        consecutive_failures=0, failure_threshold=3,
    )


def test_get_ip_usage_limit_bounds():
    old = dict(app.config)
    try:
        app.config["ip_usage_limit"] = "50"
        assert app.get_ip_usage_limit() == 50
        app.config["ip_usage_limit"] = "0"
        assert app.get_ip_usage_limit() == 0
        app.config["ip_usage_limit"] = "999999"
        assert app.get_ip_usage_limit() == 100000
        app.config["ip_usage_limit"] = "-5"
        assert app.get_ip_usage_limit() == 0
    finally:
        app.config.clear()
        app.config.update(old)


def test_page_load_timeout_classified_as_failure():
    assert app.classify_failure(
        Exception("打开注册页失败: Page.goto: Timeout 60000ms exceeded.\nCall log:\n  - navigating to ...")
    ) == app.FAIL_PAGE_LOAD
    assert app.classify_failure(
        Exception("Page.goto: Timeout 30000ms exceeded")
    ) == app.FAIL_PAGE_LOAD
    # 普通失败不误判
    assert app.classify_failure(Exception("验证码阶段失败")) == app.FAIL_CODE
    assert app.classify_failure(Exception("sso_timeout：等待超时")) == app.FAIL_SSO


def test_verified_rotation_retries_until_ip_changes():
    originals = {
        name: getattr(app, name)
        for name in (
            "proxy_count_for_worker",
            "pick_proxy_for_worker",
            "set_thread_proxy",
            "stop_browser",
            "start_browser",
            "get_exit_ip",
        )
    }
    seen = iter(["1.1.1.1", "2.2.2.2"])
    logs = []
    try:
        app.proxy_count_for_worker = lambda worker_id: 3
        app.pick_proxy_for_worker = (
            lambda worker_id, rotate_idx: f"http://user:pass@proxy:{10000 + rotate_idx}"
        )
        app.set_thread_proxy = lambda proxy: None
        app.stop_browser = lambda: None
        app.start_browser = lambda log_callback=None: (None, None)
        app.get_exit_ip = lambda: next(seen)

        idx, ip, _ = app.rotate_browser_to_new_exit(
            0,
            0,
            "1.1.1.1",
            app.time.monotonic(),
            log_callback=logs.append,
            cancel_callback=lambda: False,
        )
        assert idx == 2
        assert ip == "2.2.2.2"
        assert all("pass" not in line for line in logs)
    finally:
        for name, value in originals.items():
            setattr(app, name, value)


def test_worker_proxy_assignments_do_not_collide_during_rotation():
    original_load = app.load_proxy_pool
    original_mark = app._mark_managed_proxy_used
    try:
        app.load_proxy_pool = lambda: ["proxy-a", "proxy-b", "proxy-c"]
        app._mark_managed_proxy_used = lambda _proxy: None
        with app._proxy_pool_lock:
            app._proxy_worker_assignments.clear()
        assert app.pick_proxy_for_worker(0, 0) == "proxy-a"
        assert app.pick_proxy_for_worker(1, 0) == "proxy-b"
        assert app.pick_proxy_for_worker(0, 1) == "proxy-c"
    finally:
        app.release_proxy_for_worker(0)
        app.release_proxy_for_worker(1)
        app.load_proxy_pool = original_load
        app._mark_managed_proxy_used = original_mark


def test_ip_quota_is_shared_and_exclusive_across_workers():
    quota = app.ConcurrentIpQuota(2)
    assert quota.claim(0, "1.1.1.1") == (True, 0, "")
    claimed, used, reason = quota.claim(1, "1.1.1.1")
    assert claimed is False
    assert used == 0
    assert "W1" in reason

    assert quota.complete(0, "1.1.1.1") == 1
    quota.release(0)
    assert quota.claim(1, "1.1.1.1") == (True, 1, "")
    assert quota.complete(1, "1.1.1.1") == 2
    quota.release(1)

    claimed, used, reason = quota.claim(0, "1.1.1.1")
    assert claimed is False
    assert used == 2
    assert "配额" in reason


def test_ip_quota_limit_zero_means_unlimited():
    quota = app.ConcurrentIpQuota(0)
    # 同一 worker 同一 IP：不限制账号数，永远放行
    for _ in range(5):
        claimed, used, reason = quota.claim(0, "1.1.1.1")
        assert claimed is True
        assert reason == ""
        assert used == quota.used("1.1.1.1")
        assert quota.complete(0, "1.1.1.1") >= 1
    # 其他 worker 占用时仍拒绝（同一出口不并发复用）
    claimed, _, reason = quota.claim(1, "1.1.1.1")
    assert claimed is False
    assert "W1" in reason
    # 释放后其他 worker 可认领（即使计数已超过任何限制）
    quota.release(0)
    assert quota.claim(1, "1.1.1.1")[0] is True
    assert quota.claim(1, "1.1.1.1")[0] is True


if __name__ == "__main__":
    test_rotation_policy_defaults_and_bounds()
    test_failure_threshold_bounds()
    test_account_boundary_rotation_reason()
    test_ip_usage_limit_rotation_reason()
    test_get_ip_usage_limit_bounds()
    test_page_load_timeout_classified_as_failure()
    test_verified_rotation_retries_until_ip_changes()
    test_worker_proxy_assignments_do_not_collide_during_rotation()
    test_ip_quota_is_shared_and_exclusive_across_workers()
    test_ip_quota_limit_zero_means_unlimited()
    print("OK ip_rotation_policy")
