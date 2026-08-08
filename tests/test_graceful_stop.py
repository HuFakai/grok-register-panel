# -*- coding: utf-8 -*-
"""优雅停止：CliStopController 两级语义 + terminate graceful 参数。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as app
from webui import process_utils


def test_cli_stop_controller_two_tier_semantics():
    c = app.CliStopController()
    assert c.should_stop() is False
    assert c.should_abort() is False

    # 优雅停止（第一次信号）：只置 stop——槽位边界生效，流程内不中断
    c.stop()
    assert c.should_stop() is True
    assert c.should_abort() is False, "优雅停止不应触发 abort（当前槽位继续跑完）"

    # 强制中断（第二次信号）：置 abort
    c.abort()
    assert c.should_stop() is True
    assert c.should_abort() is True


def test_worker_flow_uses_abort_semantics():
    """worker 槽位流程内的 cancel 应使用 should_abort（优雅停止不中断当前槽位）。"""
    src = Path(ROOT / "grok_register_ttk.py").read_text(encoding="utf-8")
    # 槽位流程内 5 个调用点都应传 should_abort
    flow_calls = [
        "open_signup_page(",
        "fill_email_and_submit(",
        "fill_code_and_submit(",
        "fill_profile_and_submit(",
        "wait_for_sso_cookie(",
    ]
    # 截取 worker 槽位 try 块（含 5 个调用）所在区域：找 should_abort 出现的调用段
    block = src[src.index("def worker(wid)"):]
    for name in flow_calls:
        idx = block.index(name)
        window = block[idx:idx + 400]
        assert "should_abort" in window, f"{name} 应使用 should_abort（优雅停止不中断）"
    # 槽位边界仍用 should_stop（不再领新槽位）
    assert "while not controller.should_stop() and not worker_stop:" in src


def test_terminate_graceful_parameter():
    """terminate_managed_processes 接受 graceful 参数（优雅长等待兜底）。"""
    import inspect

    sig = inspect.signature(process_utils.terminate_managed_processes)
    assert "graceful" in sig.parameters
    assert sig.parameters["graceful"].default is False
    assert process_utils.GRACEFUL_STOP_TIMEOUT >= 60, "优雅等待上限应覆盖单槽位时长"


if __name__ == "__main__":
    test_cli_stop_controller_two_tier_semantics()
    test_worker_flow_uses_abort_semantics()
    test_terminate_graceful_parameter()
    print("OK graceful stop")
