# -*- coding: utf-8 -*-
"""全局测试隔离：禁止任何用例读写真实的 IP 状态文件。

`log/ip_health.json` / `log/ip_ready_pool.json` / `log/ip_usage.json` 是
生产运行数据（含可信出口与累计用量），若测试进程直接读写，取口/轮换策略
会被真实数据污染，导致用例断言随机失败或污染运行状态。这里用 autouse
fixture 把它们指向每个用例独立的临时路径，用例内部如需自建数据可继续
覆写对应模块的路径常量。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolate_ip_state(tmp_path):
    import ip_usage_store
    from webui import ip_health, ip_ready_pool

    previous_health = ip_health._HEALTH_FILE
    previous_pool = ip_ready_pool._POOL_FILE
    previous_usage = ip_usage_store._USAGE_FILE
    log_dir = tmp_path / "log"
    ip_health._HEALTH_FILE = tmp_path / "log" / "ip_health.json"
    ip_ready_pool._POOL_FILE = log_dir / "ip_ready_pool.json"
    ip_usage_store._USAGE_FILE = log_dir / "ip_usage.json"
    try:
        yield
    finally:
        ip_health._HEALTH_FILE = previous_health
        ip_ready_pool._POOL_FILE = previous_pool
        ip_usage_store._USAGE_FILE = previous_usage
