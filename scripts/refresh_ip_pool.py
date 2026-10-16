#!/usr/bin/env python3
"""手动触发一轮可用 IP 池探测（与面板后台补池线程共用 webui.ip_ready_pool）。

用法：
    python3 scripts/refresh_ip_pool.py [count]
    count 可选：本轮探测目标身份数（默认读 config.json 的 ip_pool_target，
    未配置用 20）。执行后打印池统计。

适合不想启动面板、或想手动补充可用 IP 池时使用；worker 换口仍会自动
优先消费 log/ip_ready_pool.json 中的可用项。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _config() -> dict:
    try:
        return json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main() -> int:
    cfg = _config()
    target = int(cfg.get("ip_pool_target") or 20)
    if len(sys.argv) > 1:
        try:
            target = max(1, int(sys.argv[1]))
        except ValueError:
            print(f"invalid count: {sys.argv[1]}", file=sys.stderr)
            return 2
    from webui.ip_ready_pool import get_pool_state, probe_round, refresh_pool

    print(f"[ip-pool] target={target}", flush=True)
    stats = refresh_pool()
    print(
        f"[ip-pool] before: usable={stats.get('usable')} total={stats.get('total')} "
        f"over_limit={stats.get('over_limit')} in_use={stats.get('in_use')}",
        flush=True,
    )
    stats = probe_round(
        target_count=target,
        concurrency=int(cfg.get("ip_pool_probe_concurrency") or 12),
        ttl=float(cfg.get("ip_pool_identity_ttl") or 600),
    )
    print(
        f"[ip-pool] after:  usable={stats.get('usable')} total={stats.get('total')} "
        f"over_limit={stats.get('over_limit')} in_use={stats.get('in_use')}",
        flush=True,
    )
    state = get_pool_state()
    usable = [it for it in state["items"] if it["usable"] and not it["consumer"]]
    for it in sorted(usable, key=lambda x: x["ttl_remaining"], reverse=True)[:20]:
        print(
            f"  ok {it['exit_ip']:<16} used={it['used']}/{it['limit'] or '∞':<4} "
            f"ttl={it['ttl_remaining']}s",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
