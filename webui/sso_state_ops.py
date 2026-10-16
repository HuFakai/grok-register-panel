"""SSO account-state (botFlag / policy deny) scan for the live panel."""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secure_files import (
    atomic_write_json,
    create_private_text,
    ensure_private_dir,
    exclusive_file_lock,
)
from sso_to_auth_json import (
    SsoInput,
    load_sso_records,
    parse_sso_line,
    run_check_sso_state,
)

try:
    from webui.security_utils import mask_email, redact_log_line, redact_proxy
except ImportError:
    from security_utils import mask_email, redact_log_line, redact_proxy  # type: ignore

ACCOUNTS_DIR = ROOT / "accounts"
PENDING_FILE = ACCOUNTS_DIR / "sso_pending.txt"
RISK_FILE = ACCOUNTS_DIR / "sso_risk_rejected.txt"
CONFIG_FILE = ROOT / "config.json"
LOG_DIR = ROOT / "log"
REPORT_FILE = LOG_DIR / "sso_state_report.json"
FLAGGED_EXPORT = LOG_DIR / "sso_flagged.jsonl"
CLEAN_EXPORT = LOG_DIR / "sso_clean.txt"

MAX_RECORDS = 2000
VALID_SOURCES = ("paste", "pending", "accounts", "risk")

_lock = threading.Lock()
_cancel = threading.Event()
_thread: threading.Thread | None = None
_state: dict = {
    "running": False,
    "started_at": "",
    "finished_at": "",
    "error": "",
    "cancelled": False,
    "source": "",
    "proxy": "",
    "progress": 0,
    "total": 0,
    "summary": {},
    "items": [],
    "run_id": "",
}


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _run_claim_file() -> Path:
    return LOG_DIR / "sso_state_scan.claim"


def _run_claim_lock() -> Path:
    return LOG_DIR / "sso_state_scan.claim.lock"


def _claim_run(run_id: str) -> bool:
    ensure_private_dir(LOG_DIR)
    claim_file = _run_claim_file()
    with exclusive_file_lock(_run_claim_lock()):
        if claim_file.is_file():
            try:
                current = json.loads(claim_file.read_text(encoding="utf-8"))
                pid = int(current.get("pid") or 0)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pid = 0
            if _pid_alive(pid):
                return False
            claim_file.unlink(missing_ok=True)
        try:
            create_private_text(
                claim_file,
                json.dumps({"run_id": run_id, "pid": os.getpid()}) + "\n",
            )
        except FileExistsError:
            return False
    return True


def _release_run(run_id: str) -> None:
    claim_file = _run_claim_file()
    with exclusive_file_lock(_run_claim_lock()):
        if not claim_file.is_file():
            return
        try:
            current = json.loads(claim_file.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return
        if str(current.get("run_id") or "") == run_id:
            claim_file.unlink(missing_ok=True)


def _nonempty_line_count(path: Path) -> int:
    try:
        return sum(
            1
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    except OSError:
        return 0


def _account_txt_count() -> int:
    if not ACCOUNTS_DIR.is_dir():
        return 0
    # 跳过生成聚合文件与旁路记录（accounts_all.txt / grok2api_web_sso.txt /
    # sso_pending / sso_risk_rejected / mail_credentials 等），只数真实账号文件
    try:
        from account_exports import IGNORED_ACCOUNT_FILENAMES as _ignored
    except Exception:
        _ignored = {
            "mail_credentials.txt",
            "sso_risk_rejected.txt",
            "sso_bfs_flagged.txt",
            "sso_pending.txt",
            "accounts_all.txt",
            "grok2api_web_sso.txt",
        }
    n = 0
    for path in ACCOUNTS_DIR.glob("*.txt"):
        if path.name in _ignored:
            continue
        n += _nonempty_line_count(path)
    return n


def _config_proxy() -> str:
    if not CONFIG_FILE.is_file():
        return ""
    try:
        cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8") or "{}")
    except Exception:
        return ""
    return str(cfg.get("proxy") or "").strip()


def _public_row(row: dict) -> dict:
    return {
        "index": int(row.get("index") or 0),
        "email": mask_email(str(row.get("email") or "")),
        "bot_flag_source": row.get("bot_flag_source"),
        "bot_flag_details": str(row.get("bot_flag_details") or "")[:240],
        "risk": row.get("risk"),
        "policy": str(row.get("policy") or ""),
        "event": str(row.get("event") or ""),
        "denied": bool(row.get("denied")),
        "found": bool(row.get("found")),
        "status_code": row.get("status_code"),
        "verdict": str(row.get("verdict") or ""),
        "error": redact_log_line(str(row.get("error") or ""))[:240],
    }


def _public_summary(summary: dict) -> dict:
    if not isinstance(summary, dict):
        return {}
    return {
        "ok": bool(summary.get("ok", True)),
        "scanned_at": summary.get("scanned_at") or "",
        "total": int(summary.get("total") or 0),
        "flagged_count": int(summary.get("flagged_count") or 0),
        "clean_count": int(summary.get("clean_count") or 0),
        "unknown_count": int(summary.get("unknown_count") or 0),
        "error_count": int(summary.get("error_count") or 0),
        "denied_count": int(summary.get("denied_count") or 0),
        "bot_flag_dist": dict(summary.get("bot_flag_dist") or {}),
        "export_path": str(summary.get("export_path") or ""),
        "export_count": int(summary.get("export_count") or 0),
        "clean_export_path": str(summary.get("clean_export_path") or ""),
        "clean_export_count": int(summary.get("clean_export_count") or 0),
        "cancelled": bool(summary.get("cancelled")),
    }


def _load_saved_report() -> dict:
    if not REPORT_FILE.is_file():
        return {}
    try:
        data = json.loads(REPORT_FILE.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    items = [dict(it) for it in (data.get("items") or []) if isinstance(it, dict)]
    out = _public_summary(data)
    out["items"] = items[-500:]
    out["source"] = str(data.get("source") or "")
    out["proxy"] = redact_proxy(str(data.get("proxy") or ""))
    out["run_id"] = str(data.get("run_id") or "")
    return out


def parse_paste(text: str) -> list[SsoInput]:
    records: list[SsoInput] = []
    for raw in str(text or "").splitlines():
        parsed = parse_sso_line(raw, source="paste")
        if parsed:
            records.append(parsed)
    return records


def parse_quarantine_line(line: str, source: str = "risk") -> SsoInput | None:
    """Parse email----sso----details lines written by the risk/bfs quarantine files."""
    raw = str(line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    if "----" in raw:
        parts = [part.strip() for part in raw.split("----")]
        if len(parts) >= 2:
            email = parts[0]
            sso = ""
            for part in parts[1:]:
                if part.startswith(("eyJ", "sso=")) and len(part) >= 24:
                    sso = part[4:] if part.startswith("sso=") else part
                    break
            if not sso:
                sso = parts[1]
            parsed = parse_sso_line(f"{email}----{sso}", source=source)
            if parsed:
                return parsed
    return parse_sso_line(raw, source=source)


def _records_from_quarantine(path: Path) -> list[SsoInput]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    records: list[SsoInput] = []
    seen: set[str] = set()
    for line in lines:
        parsed = parse_quarantine_line(line, source=path.name)
        if not parsed or parsed.sso in seen:
            continue
        seen.add(parsed.sso)
        records.append(parsed)
    return records


def _load_source_records(source: str, paste: str) -> list[SsoInput]:
    if source == "paste":
        return parse_paste(paste)
    if source == "pending":
        if not PENDING_FILE.is_file():
            return []
        return load_sso_records(path=str(PENDING_FILE))
    if source == "risk":
        if not RISK_FILE.is_file():
            return []
        return _records_from_quarantine(RISK_FILE)
    if source == "accounts":
        return load_sso_records(accounts_dir=str(ACCOUNTS_DIR))
    return []


def source_counts() -> dict:
    return {
        "pending": _nonempty_line_count(PENDING_FILE),
        "accounts": _account_txt_count(),
        "risk": _nonempty_line_count(RISK_FILE),
    }


def sso_state_status() -> dict:
    saved = _load_saved_report()
    with _lock:
        running = bool(_state["running"])
        live_items = [_public_row(it) for it in _state.get("items") or []]
        live_summary = _public_summary(_state.get("summary") or {})
        live_run_id = str(_state.get("run_id") or "")
        use_live = running or bool(live_run_id)
        snapshot = {
            "ok": True,
            "running": running,
            "started_at": _state.get("started_at") or "",
            "finished_at": _state.get("finished_at") or "",
            "error": _state.get("error") or "",
            "cancelled": bool(_state.get("cancelled")),
            "source": (_state.get("source") if use_live else saved.get("source")) or "",
            "proxy": redact_proxy(str((_state.get("proxy") if use_live else saved.get("proxy")) or "")),
            "progress": int(_state.get("progress") or 0),
            "total": int(_state.get("total") or 0),
            "run_id": live_run_id or str(saved.get("run_id") or ""),
            "historical": not use_live and bool(saved),
            "summary": live_summary if use_live else {k: saved.get(k) for k in (
                "ok", "scanned_at", "total", "flagged_count", "clean_count",
                "unknown_count", "error_count", "denied_count", "bot_flag_dist",
                "export_path", "export_count", "clean_export_path",
                "clean_export_count", "cancelled",
            ) if k in saved},
            "items": live_items if use_live else saved.get("items") or [],
        }
    snapshot["sources"] = source_counts()
    snapshot["default_proxy"] = redact_proxy(_config_proxy())
    snapshot["report_path"] = str(REPORT_FILE) if REPORT_FILE.exists() else ""
    snapshot["flagged_export"] = str(FLAGGED_EXPORT) if FLAGGED_EXPORT.exists() else ""
    snapshot["clean_export"] = str(CLEAN_EXPORT) if CLEAN_EXPORT.exists() else ""
    return snapshot


def _persist_report(summary: dict, *, source: str, proxy: str, run_id: str) -> None:
    ensure_private_dir(LOG_DIR)
    payload = dict(summary)
    payload["source"] = source
    payload["proxy"] = redact_proxy(proxy)
    payload["run_id"] = run_id
    payload["items"] = [_public_row(it) for it in (summary.get("items") or [])]
    atomic_write_json(REPORT_FILE, payload)


def _run_job(
    records: list[SsoInput],
    *,
    source: str,
    proxy: str,
    delay: float,
    run_id: str,
) -> None:
    def _on_item(row, _record, summary):
        with _lock:
            _state["progress"] = int(summary.get("total") or 0)
            _state["summary"] = dict(summary)
            _state["items"] = list(summary.get("items") or [])
        _persist_report(summary, source=source, proxy=proxy, run_id=run_id)

    try:
        summary = run_check_sso_state(
            records,
            proxy=proxy,
            delay=delay,
            export=FLAGGED_EXPORT,
            clean_export=CLEAN_EXPORT,
            log=lambda _message: None,
            on_item=_on_item,
            cancel_callback=_cancel.is_set,
        )
        _persist_report(summary, source=source, proxy=proxy, run_id=run_id)
        with _lock:
            _state["summary"] = dict(summary)
            _state["items"] = list(summary.get("items") or [])
            _state["progress"] = int(summary.get("total") or 0)
            _state["cancelled"] = bool(summary.get("cancelled"))
            _state["error"] = ""
    except Exception as exc:
        with _lock:
            _state["error"] = redact_log_line(str(exc))[:240]
            _state["cancelled"] = _cancel.is_set()
    finally:
        _release_run(run_id)
        with _lock:
            _state["running"] = False
            _state["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def start_sso_state_scan(
    *,
    source: str = "paste",
    text: str = "",
    delay: float = 0.4,
    proxy: str = "",
) -> dict:
    normalized = str(source or "paste").strip().lower()
    if normalized not in VALID_SOURCES:
        return {"ok": False, "error": f"unknown source: {normalized}"}
    try:
        wait = max(0.0, min(10.0, float(delay)))
    except (TypeError, ValueError):
        return {"ok": False, "error": "invalid delay"}

    records = _load_source_records(normalized, text)
    if not records:
        return {"ok": False, "error": "没有可用的 sso 记录"}
    if len(records) > MAX_RECORDS:
        return {
            "ok": False,
            "error": f"一次最多检查 {MAX_RECORDS} 条，当前 {len(records)}",
        }

    resolved_proxy = str(proxy or "").strip() or _config_proxy()
    run_id = secrets.token_hex(8)
    with _lock:
        if _state["running"]:
            return {"ok": False, "error": "sso 风控扫描已在运行", "running": True}
        if not _claim_run(run_id):
            return {"ok": False, "error": "另一面板进程正在执行 sso 风控扫描", "running": True}
        _cancel.clear()
        _state.update(
            {
                "running": True,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "finished_at": "",
                "error": "",
                "cancelled": False,
                "source": normalized,
                "proxy": resolved_proxy,
                "progress": 0,
                "total": len(records),
                "summary": {},
                "items": [],
                "run_id": run_id,
            }
        )

    thread = threading.Thread(
        target=_run_job,
        kwargs={
            "records": records,
            "source": normalized,
            "proxy": resolved_proxy,
            "delay": wait,
            "run_id": run_id,
        },
        name="sso-state-scan",
        daemon=True,
    )
    global _thread
    _thread = thread
    thread.start()
    return {
        "ok": True,
        "running": True,
        "total": len(records),
        "source": normalized,
        "delay": wait,
        "proxy": redact_proxy(resolved_proxy),
        "run_id": run_id,
    }


def stop_sso_state_scan() -> dict:
    _cancel.set()
    thread = _thread
    if thread and thread.is_alive():
        thread.join(timeout=2.0)
    with _lock:
        running = bool(_state["running"])
    return {"ok": True, "stopping": running, "running": running}


def read_sso_state_export(kind: str) -> dict:
    normalized = str(kind or "flagged").strip().lower()
    if normalized not in {"flagged", "clean"}:
        return {"ok": False, "error": "kind must be flagged or clean"}
    saved = _load_saved_report()
    rows = [
        row
        for row in (saved.get("items") or [])
        if isinstance(row, dict) and str(row.get("verdict") or "") == normalized
    ]
    if not saved:
        return {"ok": False, "error": "export not found", "kind": normalized}
    text = "".join(
        json.dumps(
            {key: row.get(key) for key in (
                "index", "email", "bot_flag_source", "bot_flag_details", "risk",
                "policy", "event", "denied", "found", "status_code", "verdict",
                "error",
            )},
            ensure_ascii=False,
        ) + "\n"
        for row in rows
    )
    return {
        "ok": True,
        "kind": normalized,
        "bytes": len(text.encode("utf-8")),
        "lines": len(rows),
        "content": text,
        "redacted": True,
    }
