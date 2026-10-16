"""Grok2API Web SSO 上传编排：收集账号 → 导入 → 转 Build → 转 Console。

输入源：注册面板自动生成的 `grok2api_web_accounts.jsonl`（任务级 + 根级聚合），
每行即文档 §2.5 的导入对象（provider/name/email/sso_token/tier）。

流程（一条龙，后台脚本调用）：
  login → import_web_accounts（≤10000/批）→ convert_to_build（missing）→
  sync_to_console（all）→ 写 log/grok2api_upload_report.json

上传只读 accounts 目录 + 调远程 API，不写 cpa，与注册 worker 完全解耦。
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Iterable

from secure_files import atomic_write_json, ensure_private_dir
from webui.grok2api_api import (
    IMPORT_CHUNK_SIZE,
    Grok2apiClient,
    Grok2apiError,
)

ROOT = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = ROOT / "accounts"
REPORT_FILE = ROOT / "log" / "grok2api_upload_report.json"

_CONFIG_KEYS = (
    "grok2api_admin_url",
    "grok2api_admin_user",
    "grok2api_admin_password",
)


def load_config(config_path: str | os.PathLike[str] | None = None) -> dict:
    path = Path(config_path) if config_path else ROOT / "config.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def upload_config(config: dict) -> dict:
    return {
        key: str(config.get(key) or "").strip() for key in _CONFIG_KEYS
    }


def configured(config: dict) -> bool:
    cfg = upload_config(config)
    return bool(cfg["grok2api_admin_url"] and cfg["grok2api_admin_user"] and cfg["grok2api_admin_password"])


def collect_web_accounts(accounts_dir: str | os.PathLike[str] | None = None) -> list[dict]:
    """扫描任务级与根级 grok2api_web_accounts.jsonl，按 sso_token 去重。"""
    root = Path(accounts_dir) if accounts_dir else ACCOUNTS_DIR
    seen: set[str] = set()
    records: list[dict] = []
    files: list[Path] = []
    root_file = root / "grok2api_web_accounts.jsonl"
    if root_file.is_file():
        files.append(root_file)
    tasks_dir = root / "tasks"
    if tasks_dir.is_dir():
        files.extend(sorted(tasks_dir.glob("*/grok2api_web_accounts.jsonl")))
    for path in files:
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(item, dict):
                    continue
                token = str(item.get("sso_token") or item.get("token") or "").strip()
                if not token or token in seen:
                    continue
                seen.add(token)
                item["sso_token"] = token
                records.append(item)
        except OSError:
            continue
    return records


def chunk_records(records: list[dict], size: int = IMPORT_CHUNK_SIZE) -> Iterable[str]:
    for start in range(0, len(records), size):
        chunk = records[start : start + size]
        yield "".join(
            json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
            for item in chunk
        )


def run_upload(
    config: dict,
    *,
    report_path: str | os.PathLike[str] | None = None,
    accounts_dir: str | os.PathLike[str] | None = None,
    logger: logging.Logger | None = None,
) -> dict:
    """执行一次上传：login → import → convert → sync，写 report 并返回。"""
    started = time.time()
    report: dict = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "configured": configured(config),
        "total_accounts": 0,
        "ok": False,
        "errors": [],
    }
    if not configured(config):
        report["error"] = "grok2api 未配置（grok2api_admin_url/user/password）"
        _write_report(report_path, report)
        return report

    cfg = upload_config(config)
    client = Grok2apiClient(
        cfg["grok2api_admin_url"],
        username=cfg["grok2api_admin_user"],
        password=cfg["grok2api_admin_password"],
        logger=logger,
    )

    # 1) 收集 Web 账号
    records = collect_web_accounts(accounts_dir)
    report["total_accounts"] = len(records)
    if logger:
        logger.info("收集到 %d 个 Web 账号", len(records))

    # 2) 导入（分块）
    imported = {"created": 0, "updated": 0, "skipped": 0}
    try:
        client.login()
        for chunk in chunk_records(records):
            chunk_report = client.import_web_accounts(chunk)
            for key in imported:
                imported[key] = imported.get(key, 0) + int(chunk_report.get(key) or 0)
            if logger:
                logger.info("导入分块完成: %s", json.dumps(chunk_report, ensure_ascii=False))
        report["imported"] = imported
        if logger:
            logger.info("Web 导入完成: %s", json.dumps(imported, ensure_ascii=False))
    except Grok2apiError as exc:
        report["errors"].append(f"导入失败: {exc}")
        report["imported"] = imported
        report["error"] = str(exc)
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
        _write_report(report_path, report)
        return report

    # 3) 转 Build
    try:
        converted = client.convert_to_build()
        report["converted"] = converted
        if logger:
            logger.info("转 Build 完成: %s", json.dumps(converted, ensure_ascii=False))
    except Grok2apiError as exc:
        report["converted"] = {"error": str(exc)}
        report["errors"].append(f"转 Build 失败: {exc}")
        if logger:
            logger.warning("转 Build 失败: %s", exc)

    # 4) 转 Console
    try:
        synced = client.sync_to_console()
        report["synced"] = synced
        if logger:
            logger.info("转 Console 完成: %s", json.dumps(synced, ensure_ascii=False))
    except Grok2apiError as exc:
        report["synced"] = {"error": str(exc)}
        report["errors"].append(f"转 Console 失败: {exc}")
        if logger:
            logger.warning("转 Console 失败: %s", exc)

    report["ok"] = not report["errors"]
    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
    _write_report(report_path, report)
    return report


def _write_report(report_path: str | os.PathLike[str] | None, report: dict) -> None:
    path = Path(report_path) if report_path else REPORT_FILE
    try:
        ensure_private_dir(path.parent)
        atomic_write_json(path, report)
    except Exception:
        pass


def read_report(report_path: str | os.PathLike[str] | None = None) -> dict:
    path = Path(report_path) if report_path else REPORT_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def upload_status(report_path: str | os.PathLike[str] | None = None) -> dict:
    """面板展示：最近一次 report + 配置就绪度。"""
    report = read_report(report_path)
    config = load_config()
    return {
        "configured": configured(config),
        "last_report": report,
    }


if __name__ == "__main__":
    # 直接运行：python3 -m webui.grok2api_upload [config.json] [report.json]
    _args = sys.argv[1:]
    _cfg = load_config(_args[0] if _args else None)
    _report = _args[1] if len(_args) > 1 else None
    _logger = logging.getLogger("grok2api_upload")
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
    result = run_upload(_cfg, report_path=_report, logger=_logger)
    print(json.dumps({k: v for k, v in result.items() if k != "errors"}, ensure_ascii=False))
    sys.exit(0 if result.get("ok") else 1)
