#!/usr/bin/env python3
"""恢复被误软拉黑的 IP（counts 被置 99999）。

背景：早期"单次空页即永久软拉黑"策略过于激进，把大量长期正常工作的 IP
误杀。本脚本把"register_results 中注册成功过"的被拉黑 IP 计数恢复为 0
（重新可用），仅保留"从未成功过"的继续拉黑。

用法：
    python3 scripts/unblacklist_ip.py [--dry-run]

默认只打印将恢复的清单；加 --dry-run 不做任何修改。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    from secure_files import exclusive_file_lock
    from ip_usage_store import _KEY_COUNTS, _KEY_LIMITS, _KEY_META, _KEY_SOFT, _load_all, _write_all

    usage_file = ROOT / "log" / "ip_usage.json"

    # 收集注册成功过的 IP
    ok_ips = set()
    results_file = ROOT / "log" / "register_results.jsonl"
    if results_file.is_file():
        for line in results_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("status") == "ok" and r.get("exit_ip"):
                ok_ips.add(str(r["exit_ip"]).strip())

    with exclusive_file_lock(usage_file.with_suffix(".lock")):
        data = _load_all()
        counts = data[_KEY_COUNTS]
        restored: list[str] = []
        kept: list[str] = []
        for ip, count in list(counts.items()):
            if count >= 99999:
                if ip in ok_ips:
                    restored.append(ip)
                else:
                    kept.append(ip)
        if not dry_run:
            for ip in restored:
                counts[ip] = 0
            _write_all(counts, data[_KEY_LIMITS], data[_KEY_META], data[_KEY_SOFT])

    print(f"register_results 中成功过的 IP: {len(ok_ips)}")
    print(f"被软拉黑 IP: {len(restored) + len(kept)}")
    print(f"  恢复为可用（成功过）: {len(restored)}")
    print(f"  保留拉黑（从未成功）: {len(kept)}")
    if dry_run:
        print("（--dry-run 模式，未修改）")
    else:
        print(f"已恢复 {len(restored)} 个 IP，计数置 0，重新可用")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
