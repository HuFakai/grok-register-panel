"""Async grok2api upload jobs（后台 subprocess，不阻塞注册 worker）。

与 recovery_ops 同模式：Popen 拉起 scripts/grok2api_upload.py，写 PID +
独立日志，process_utils 管理。上传只读 accounts 目录 + 调远程 grok2api，
不写本地 cpa，因此注册任务运行期间也允许执行（不互斥）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime_platform import popen_group_kwargs, runtime_python

try:
    from secure_files import best_effort_fchmod, ensure_private_dir
    from webui.process_utils import (
        find_managed_processes,
        write_pid_file,
    )
except ImportError:  # running from webui/
    from secure_files import best_effort_fchmod, ensure_private_dir
    from process_utils import (  # type: ignore
        find_managed_processes,
        write_pid_file,
    )

LOG_DIR = ROOT / "log"
REPORT_FILE = LOG_DIR / "grok2api_upload_report.json"
PID_FILE = LOG_DIR / "grok2api_upload.pid"
UPLOAD_SCRIPT = ROOT / "scripts" / "grok2api_upload.py"
VENV_PY = runtime_python(ROOT)
CONFIG_FILE = ROOT / "config.json"
PROCESS_NAME = "grok2api_upload.py"


def _running_processes() -> list[dict]:
    return find_managed_processes(ROOT, (PROCESS_NAME,))


def upload_status() -> dict:
    """面板展示：是否运行 + 最近 report + 配置就绪度。"""
    from webui.grok2api_upload import read_report, upload_status as _cfg_status

    running = _running_processes()
    status = _cfg_status(REPORT_FILE)
    return {
        "running": bool(running),
        "pid": running[0]["pid"] if running else None,
        "configured": status.get("configured", False),
        "last_report": status.get("last_report") or {},
    }


def start_upload() -> dict:
    """启动一次后台上传；已在跑或配置缺失则拒绝。"""
    existing = _running_processes()
    if existing:
        return {"ok": False, "error": "grok2api 上传已在运行", "pid": existing[0]["pid"]}
    if not VENV_PY.is_file():
        return {"ok": False, "error": f"missing runtime python: {VENV_PY}"}
    if not CONFIG_FILE.is_file():
        return {"ok": False, "error": f"missing config: {CONFIG_FILE}"}

    from webui.grok2api_upload import configured, load_config

    config = load_config(CONFIG_FILE)
    if not configured(config):
        return {
            "ok": False,
            "error": "grok2api 未配置（grok2api_admin_url/user/password）",
        }

    ensure_private_dir(LOG_DIR)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"grok2api-upload-{timestamp}.log"
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        best_effort_fchmod(fd, 0o600)
    except OSError:
        pass
    output = os.fdopen(fd, "w", encoding="utf-8")
    command = [
        str(VENV_PY),
        "-u",
        str(UPLOAD_SCRIPT),
        "--from-config",
        str(CONFIG_FILE),
        "--report-json",
        str(REPORT_FILE),
        "--log",
        str(log_path),
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=str(ROOT),
            stdout=output,
            stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            **popen_group_kwargs(),
        )
    finally:
        output.close()
    write_pid_file(PID_FILE, process.pid)
    return {
        "ok": True,
        "running": True,
        "pid": process.pid,
        "log": log_path.name,
    }


def stop_upload() -> dict:
    """终止后台上传进程（SIGTERM，短 grace 后 SIGKILL）。"""
    from webui.process_utils import terminate_managed_processes

    killed = terminate_managed_processes(
        ROOT,
        (PROCESS_NAME,),
        grace_seconds=5.0,
    )
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
    except OSError:
        pass
    return {"ok": True, "killed": killed}


def trigger_auto_upload() -> bool:
    """注册批次收尾调用：配置了 grok2api_auto_upload 且就绪时启动上传。

    返回 True 表示已触发；任何异常静默吞掉（不阻塞批次收尾/通知）。
    """
    try:
        from webui.grok2api_upload import configured, load_config

        config = load_config(CONFIG_FILE)
        if not config.get("grok2api_auto_upload"):
            return False
        if not configured(config):
            return False
        result = start_upload()
        return bool(result.get("ok"))
    except Exception:
        return False
