"""BFS (JWT claim) scan helpers for the live panel and CLI."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json, atomic_write_text, ensure_private_dir
from sso_to_auth_json import (
    inspect_jwt_bfs,
    inspect_token_bundle_bfs,
    scan_cpa_auth_dir_bfs,
)

ACCOUNTS_DIR = ROOT / "accounts"
CPA_DIR = Path(os.environ.get("CPA_AUTH_DIR", str(ROOT / "cpa_auth")))
G2A_DIR = Path(os.environ.get("GROK2API_AUTH_DIR", str(ROOT / "grok2api_auth")))
LOG_DIR = ROOT / "log"
BFS_REPORT = LOG_DIR / "bfs_scan_report.json"
BFS_EXPORT = LOG_DIR / "bfs_flagged.jsonl"
BFS_FLAGGED_FILE = ACCOUNTS_DIR / "sso_bfs_flagged.txt"
CONFIG_FILE = ROOT / "config.json"


def _resolve_auth_dirs() -> list[Path]:
    dirs: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path) -> None:
        try:
            key = str(path.resolve())
        except Exception:
            key = str(path)
        if key in seen:
            return
        seen.add(key)
        dirs.append(path)

    _add(CPA_DIR)
    _add(G2A_DIR)
    if CONFIG_FILE.is_file():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8") or "{}")
        except Exception:
            cfg = {}
        base = CONFIG_FILE.parent
        for key in ("cpa_auth_dir", "grok2api_auth_dir"):
            raw = str(cfg.get(key) or "").strip()
            if not raw:
                continue
            p = Path(raw)
            if not p.is_absolute():
                p = base / p
            _add(p)
    return dirs


def _flagged_line_count() -> int:
    try:
        if not BFS_FLAGGED_FILE.is_file():
            return 0
        n = 0
        for line in BFS_FLAGGED_FILE.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.strip().startswith("#"):
                n += 1
        return n
    except OSError:
        return 0


def _jsonl_bfs_from_results() -> dict:
    """Summarize bfs fields already written to register_results.jsonl."""
    path = LOG_DIR / "register_results.jsonl"
    out = {"ok": 0, "bfs": 0, "clean": 0, "unknown": 0, "total": 0}
    if not path.is_file():
        return out
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines[-5000:]:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        out["total"] += 1
        st = str(rec.get("status") or "")
        if st == "ok":
            out["ok"] += 1
        bfs = rec.get("bfs")
        if bfs is True:
            out["bfs"] += 1
        elif bfs is False:
            out["clean"] += 1
        else:
            out["unknown"] += 1
    return out


def bfs_status() -> dict:
    """Lightweight status for the panel (no full rescan)."""
    last: dict = {}
    if BFS_REPORT.is_file():
        try:
            last = json.loads(BFS_REPORT.read_text(encoding="utf-8") or "{}")
        except Exception:
            last = {}
    auth_dirs = [str(p) for p in _resolve_auth_dirs() if p.is_dir()]
    return {
        "ok": True,
        "flagged_file_count": _flagged_line_count(),
        "flagged_file": str(BFS_FLAGGED_FILE) if BFS_FLAGGED_FILE.exists() else "",
        "auth_dirs": auth_dirs,
        "last_report": {
            "scanned_at": last.get("scanned_at"),
            "total": last.get("total"),
            "bfs_count": last.get("bfs_count"),
            "clean_count": last.get("clean_count"),
            "error_count": last.get("error_count"),
            "bfs_rate": last.get("bfs_rate"),
            "bfs_value_dist": last.get("bfs_value_dist") or {},
            "export_path": last.get("export_path") or "",
            "export_count": last.get("export_count"),
        },
        "results_jsonl": _jsonl_bfs_from_results(),
    }


def run_bfs_scan(*, limit: int = 0, include_clean: bool = False) -> dict:
    """Scan all known auth dirs, write report + flagged export (no tokens)."""
    ensure_private_dir(LOG_DIR)
    dirs = [p for p in _resolve_auth_dirs() if p.is_dir()]
    merged: dict = {
        "ok": True,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "auth_dirs": [str(p) for p in dirs],
        "total": 0,
        "bfs_count": 0,
        "clean_count": 0,
        "error_count": 0,
        "bfs_rate": 0.0,
        "bfs_value_dist": {},
        "items": [],
        "export_path": str(BFS_EXPORT),
        "export_count": 0,
    }
    value_dist: dict[str, int] = {}
    seen_files: set[str] = set()

    for auth_dir in dirs:
        part = scan_cpa_auth_dir_bfs(auth_dir, limit=limit, include_clean=True)
        for item in part.get("items") or []:
            fkey = f"{auth_dir}/{item.get('file')}"
            if fkey in seen_files:
                continue
            seen_files.add(fkey)
            row = dict(item)
            row["auth_dir"] = str(auth_dir)
            merged["total"] += 1
            if row.get("error"):
                merged["error_count"] += 1
                if include_clean:
                    merged["items"].append(row)
                continue
            if row.get("has_bfs"):
                merged["bfs_count"] += 1
                key = str(row.get("bfs"))
                value_dist[key] = value_dist.get(key, 0) + 1
                merged["items"].append(row)
            else:
                merged["clean_count"] += 1
                if include_clean:
                    merged["items"].append(row)

    decoded = merged["bfs_count"] + merged["clean_count"]
    merged["bfs_rate"] = (
        round(100.0 * merged["bfs_count"] / decoded, 2) if decoded else 0.0
    )
    merged["bfs_value_dist"] = value_dist

    lines = [
        json.dumps(it, ensure_ascii=False)
        for it in merged["items"]
        if it.get("has_bfs")
    ]
    atomic_write_text(BFS_EXPORT, ("\n".join(lines) + ("\n" if lines else "")))
    merged["export_count"] = len(lines)

    report = dict(merged)
    if not include_clean:
        report["items"] = [
            it for it in merged["items"] if it.get("has_bfs") or it.get("error")
        ]
    atomic_write_json(BFS_REPORT, report)
    return report


def check_token_text(token: str) -> dict:
    """One-shot check for a pasted JWT / SSO (panel diagnostic)."""
    info = inspect_jwt_bfs(token)
    if not info.get("ok"):
        info = inspect_token_bundle_bfs(access_token=token, sso=token)
    return {
        "ok": bool(info.get("ok")),
        "has_bfs": bool(info.get("has_bfs")),
        "bfs": info.get("bfs"),
        "source": info.get("source") or ("jwt" if info.get("ok") else ""),
        "tier": info.get("tier"),
        "sub": info.get("sub") or "",
        "exp": info.get("exp"),
        "referrer": info.get("referrer"),
        "claim_keys": list(info.get("claim_keys") or [])[:40],
    }
