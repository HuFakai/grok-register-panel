"""全部配置一键导出/导入（换环境一键恢复）。

汇总 config.json、代理池、邮箱域名池、邮箱多配置档、控制参数、
IP 使用限制为单个 JSON；导入时写回各文件（0600 私有权限）。

注意：导出文件包含代理密码、邮箱密钥等敏感凭据，请妥善保管，
不要提交到公开仓库。
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from secure_files import atomic_write_json, ensure_private_dir

ROOT = Path(__file__).resolve().parent.parent
BACKUP_VERSION = 1

# 各配置段的导出/导入顺序（写入顺序固定，便于 diff）
_SECTIONS = (
    "config",
    "proxy_pool",
    "email_domain_pool",
    "email_provider_profiles",
    "monitor_control",
    "ip_usage",
)


def _target_paths() -> dict[str, Path]:
    """各配置段对应的落盘路径（延迟 import 避免模块循环依赖）。"""
    from webui import email_domain_store, email_provider_store, monitor, proxy_store
    from ip_usage_store import usage_file_path

    return {
        "config": ROOT / "config.json",
        "proxy_pool": Path(proxy_store.STATE_PATH),
        "email_domain_pool": Path(email_domain_store.STATE_PATH),
        "email_provider_profiles": Path(email_provider_store.PROFILES_PATH),
        "monitor_control": Path(monitor.CONTROL_FILE),
        "ip_usage": usage_file_path(),
    }


def export_all() -> dict:
    """汇总全部配置段为单个 dict（含版本与导出时间）。"""
    paths = _target_paths()
    data: dict = {
        "version": BACKUP_VERSION,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    for section in _SECTIONS:
        path = paths[section]
        try:
            raw = json.loads(path.read_text(encoding="utf-8") or "{}")
            data[section] = raw if isinstance(raw, dict) else {}
        except Exception:
            data[section] = {}
    return data


def import_all(data: object) -> dict:
    """写回全部配置段；返回各段写入/跳过状态。"""
    if not isinstance(data, dict):
        raise ValueError("导入内容必须是 JSON 对象")
    if int(data.get("version") or 0) != BACKUP_VERSION:
        raise ValueError(f"不支持的备份版本: {data.get('version')}")
    paths = _target_paths()
    written: list[str] = []
    skipped: list[str] = []
    for section in _SECTIONS:
        payload = data.get(section)
        if not isinstance(payload, dict):
            skipped.append(section)
            continue
        path = paths[section]
        ensure_private_dir(path.parent)
        atomic_write_json(path, payload)
        written.append(section)
    return {
        "ok": True,
        "written": written,
        "skipped": skipped,
        "note": "已写回配置，请重启面板/注册进程生效；导出文件含敏感凭据请妥善保管",
    }
