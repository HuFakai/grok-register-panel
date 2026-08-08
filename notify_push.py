#!/usr/bin/env python3
"""任务完成推送提醒。

向 push.zizheng7zfb.com 推送「任务完成」消息，重复发送 N 次、间隔固定秒数，
防止单次推送丢失。失败只记录日志，绝不抛异常，不影响注册主流程。

Token 来源（按优先级）：
  1. 环境变量 PUSH_TOKEN
  2. config.json 的 push_token 字段
  3. 调用方显式传入的 token 参数

可被 run_until_100 / run_batch_headless 在任务完成时自动调用，也可命令行手动触发：
  python notify_push.py --title "任务完成" --content "..."
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Callable

DEFAULT_URL = "https://push.zizheng7zfb.com/api/push"
DEFAULT_TITLE = "任务完成"
DEFAULT_CONTENT = "当前任务已完成，请尽快开始新的注册任务。"
DEFAULT_RETRIES = 3
DEFAULT_INTERVAL = 5.0
DEFAULT_TIMEOUT = 10.0

ROOT = Path(__file__).resolve().parent


def _load_push_token() -> str:
    env = str(os.environ.get("PUSH_TOKEN", "") or "").strip()
    if env:
        return env
    try:
        data = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        tok = str(data.get("push_token") or "").strip()
        if tok:
            return tok
    except Exception:
        pass
    return ""


def notify_task_done(
    title: str = DEFAULT_TITLE,
    content: str = DEFAULT_CONTENT,
    *,
    url: str | None = None,
    token: str | None = None,
    retries: int | None = None,
    interval: float | None = None,
    timeout: float | None = None,
    log: Callable[[str], object] = print,
) -> bool:
    """发送任务完成推送。返回是否至少一次成功。失败不抛异常。

    默认重复 3 次、间隔 5 秒，可被环境变量 PUSH_RETRIES / PUSH_INTERVAL 覆盖。
    """
    url = url or os.environ.get("PUSH_URL", DEFAULT_URL)
    tok = str(token or _load_push_token()).strip()
    try:
        retries = int(retries if retries is not None else os.environ.get("PUSH_RETRIES", DEFAULT_RETRIES))
    except (TypeError, ValueError):
        retries = DEFAULT_RETRIES
    retries = max(1, retries)
    try:
        interval = float(interval if interval is not None else os.environ.get("PUSH_INTERVAL", DEFAULT_INTERVAL))
    except (TypeError, ValueError):
        interval = DEFAULT_INTERVAL
    try:
        timeout = float(timeout if timeout is not None else os.environ.get("PUSH_TIMEOUT", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT

    if not tok or tok == "your_token":
        log("[notify] 未配置 push_token（PUSH_TOKEN 环境变量或 config.json.push_token），跳过推送")
        return False

    payload = json.dumps(
        {"title": title, "content": content, "type": "text"},
        ensure_ascii=False,
    ).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {tok}",
        "Content-Type": "application/json",
    }

    any_ok = False
    for i in range(1, retries + 1):
        ok = False
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                body = resp.read(512)
                if 200 <= int(status) < 300:
                    ok = True
                    any_ok = True
                log(f"[notify] 第 {i}/{retries} 次 HTTP {status}: {body[:200]!r}")
        except Exception as exc:  # noqa: BLE001 - 推送不能影响主流程
            log(f"[notify] 第 {i}/{retries} 次推送失败: {exc}")
        if i < retries:
            time.sleep(interval)

    if any_ok:
        log("[notify] 推送完成")
    else:
        log(f"[notify] 推送失败（{retries} 次均未成功）")
    return any_ok


def _main() -> int:
    import argparse

    p = argparse.ArgumentParser(description="任务完成推送提醒")
    p.add_argument("--title", default=DEFAULT_TITLE, help="推送标题")
    p.add_argument("--content", default=DEFAULT_CONTENT, help="推送内容")
    args = p.parse_args()
    return 0 if notify_task_done(args.title, args.content) else 1


if __name__ == "__main__":
    raise SystemExit(_main())
