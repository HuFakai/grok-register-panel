#!/usr/bin/env python3
"""Batch-check grok.com account risk state from an SSO list.

Usage:
  python scripts/check_sso_state.py --sso sso_list.txt
  python scripts/check_sso_state.py --sso sso_list.txt --from-config config.json
  python scripts/check_sso_state.py --sso-cookie 'eyJ...'
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sso_to_auth_json import load_sso_records, run_check_sso_state  # noqa: E402
from secure_files import atomic_write_json  # noqa: E402
import json


def _proxy_from_config(path: str, current: str) -> str:
    if current or not path:
        return current
    try:
        cfg = json.loads(Path(path).expanduser().read_text(encoding="utf-8") or "{}")
    except Exception:
        return current
    return str(cfg.get("proxy") or "").strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Check grok.com botFlag / policy deny from SSO")
    ap.add_argument("--sso", metavar="FILE", help="sso list file")
    ap.add_argument("--sso-cookie", metavar="JWT", help="single sso cookie")
    ap.add_argument("--accounts-dir", metavar="DIR", help="scan accounts/*.txt")
    ap.add_argument("--from-config", metavar="FILE", help="read proxy from config.json")
    ap.add_argument("--proxy", default="", help="HTTP proxy")
    ap.add_argument("--delay", type=float, default=0.4, help="seconds between checks")
    ap.add_argument("--export", metavar="FILE", help="flagged jsonl (no token)")
    ap.add_argument("--clean-export", metavar="FILE", help="clean raw sso lines")
    ap.add_argument("--report-json", metavar="FILE", help="full summary JSON")
    args = ap.parse_args()

    args.proxy = _proxy_from_config(args.from_config or "", args.proxy)
    records = load_sso_records(
        path=args.sso,
        single=args.sso_cookie,
        accounts_dir=args.accounts_dir,
    )
    if not records:
        ap.error("需要 --sso、--sso-cookie 或 --accounts-dir")

    summary = run_check_sso_state(
        records,
        proxy=args.proxy,
        delay=args.delay,
        export=args.export,
        clean_export=args.clean_export,
    )
    if args.report_json:
        atomic_write_json(args.report_json, summary)
        print(f"报告 → {args.report_json}")
    print(
        f"sso 状态检查: total={summary['total']} "
        f"flagged={summary['flagged_count']} clean={summary['clean_count']} "
        f"unknown={summary['unknown_count']} err={summary['error_count']} "
        f"botFlagDist={summary['bot_flag_dist']}"
    )
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
