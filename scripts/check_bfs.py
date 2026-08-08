#!/usr/bin/env python3
"""Batch-scan CPA / Grok2API auth files for xAI JWT ``bfs`` claim.

Usage:
  python scripts/check_bfs.py
  python scripts/check_bfs.py --dir cpa_auth --export log/bfs_flagged.jsonl
  python scripts/check_bfs.py --token 'eyJ...'
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json, atomic_write_text  # noqa: E402
from sso_to_auth_json import scan_cpa_auth_dir_bfs  # noqa: E402
from webui.bfs_ops import check_token_text, run_bfs_scan  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan auth files / JWT for bfs claim")
    ap.add_argument("--dir", metavar="DIR", help="Single auth directory containing JSON auth files")
    ap.add_argument("--export", metavar="FILE", help="Write flagged rows as jsonl")
    ap.add_argument("--report", metavar="FILE", help="Write full summary JSON")
    ap.add_argument("--token", metavar="JWT", help="Check one JWT/SSO string")
    ap.add_argument("--include-clean", action="store_true", help="Include clean rows in report")
    ap.add_argument("--limit", type=int, default=0, help="Max files per directory")
    args = ap.parse_args()

    if args.token:
        info = check_token_text(args.token)
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0 if info.get("ok") else 1

    if args.dir:
        summary = scan_cpa_auth_dir_bfs(
            args.dir, limit=args.limit, include_clean=args.include_clean
        )
    else:
        summary = run_bfs_scan(limit=args.limit, include_clean=args.include_clean)

    if args.export:
        path = Path(args.export)
        rows = [it for it in (summary.get("items") or []) if it.get("has_bfs")]
        atomic_write_text(
            path,
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
            + ("\n" if rows else "")
        )
        print(f"export → {path} ({len(rows)} bfs)")

    if args.report:
        path = Path(args.report)
        atomic_write_json(path, summary)
        print(f"report → {path}")

    print(
        f"total={summary.get('total')} bfs={summary.get('bfs_count')} "
        f"clean={summary.get('clean_count')} err={summary.get('error_count')} "
        f"rate={summary.get('bfs_rate')}% dist={summary.get('bfs_value_dist')}"
    )
    return 0 if summary.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
