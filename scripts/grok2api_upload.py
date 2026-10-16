#!/usr/bin/env python3
"""后台执行一次 grok2api Web SSO 上传（导入 + 转 Build + 转 Console）。

由面板/批次收尾通过 subprocess 拉起（独立进程，不阻塞注册 worker）。
用法：
    python3 scripts/grok2api_upload.py [--from-config config.json]
        [--report-json log/grok2api_upload_report.json]
        [--accounts-dir accounts] [--log log/grok2api_upload.log]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webui.grok2api_upload import run_upload  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload Web SSO accounts to grok2api")
    parser.add_argument("--from-config", default=str(ROOT / "config.json"))
    parser.add_argument("--report-json", default="")
    parser.add_argument("--accounts-dir", default=str(ROOT / "accounts"))
    parser.add_argument("--log", default="")
    args = parser.parse_args()

    if args.log:
        logging.basicConfig(
            filename=args.log,
            level=logging.INFO,
            format="[%(asctime)s] %(levelname)s %(message)s",
        )
    else:
        logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
    logger = logging.getLogger("grok2api_upload")

    import json as _json

    try:
        config = _json.loads(Path(args.from_config).read_text(encoding="utf-8"))
    except Exception:
        config = {}
    result = run_upload(
        config,
        report_path=args.report_json or None,
        accounts_dir=args.accounts_dir or None,
        logger=logger,
    )
    print(
        _json.dumps(
            {k: v for k, v in result.items() if k != "errors"},
            ensure_ascii=False,
        ),
        flush=True,
    )
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
