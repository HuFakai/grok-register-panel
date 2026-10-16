"""账号管理面板的后端逻辑：列表 / 复制导出 / 状态标记 / 删除。

数据源与注册进程共用 accounts 目录（见 account_exports.py）：
- accounts/tasks/<任务ID>/<email>.txt  每任务一个子目录，逐账号文件；
- accounts/<email>.txt                 遗留的根目录账号文件；
- accounts/account_status.json         面板维护的使用状态（不在 *.txt 扫描范围）。

状态不写入账号文件本身，避免与注册进程的聚合刷新互相覆盖；删除账号时
同时清理状态记录并重建受影响目录的聚合导出。
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from account_exports import (
    IGNORED_ACCOUNT_FILENAMES,
    AccountCredential,
    delete_account_records,
    parse_account_line,
)
from secure_files import atomic_write_json, exclusive_file_lock

try:
    from webui.security_utils import redact_log_line
except ImportError:  # pragma: no cover
    from security_utils import redact_log_line  # type: ignore

ACCOUNTS_DIR = ROOT / "accounts"
TASKS_SUBDIR = "tasks"
STATUS_FILE = ACCOUNTS_DIR / "account_status.json"
STATUS_LOCK_FILE = ACCOUNTS_DIR / ".account_status.lock"

VALID_STATUSES = ("unused", "used", "disabled")
STATUS_LABELS = {"unused": "未使用", "used": "已使用", "disabled": "已禁用"}
VALID_FORMATS = ("full", "sso", "emails", "jsonl")
ROOT_TASK_KEY = "__root__"
MAX_EMAILS_PER_REQUEST = 5000
MAX_PAGE_SIZE = 200
CACHE_TTL_SECONDS = 8.0

_lock = threading.Lock()
_cache: dict = {
    "records": {},       # email -> AccountCredential
    "tasks": {},         # email -> task id（"" 表示根目录遗留）
    "mtime": {},         # email -> 最新 mtime epoch
    "sources": {},       # email -> 出现过的目录数（含根目录）
    "signature": None,
    "built_at": 0.0,
}


# ---------------------------------------------------------------- helpers

def _dir_signature() -> tuple:
    """廉价嗅探账号目录变化：根目录 entries + 各任务目录的 mtime。

    任务目录内原子写（rename）会更新目录 mtime，因此注册进程新增账号、
    面板删除账号都会反映在这里；否则命中缓存不做全量扫描。
    """
    try:
        entries = list(ACCOUNTS_DIR.iterdir())
    except OSError:
        return ("missing",)
    root_txt_names = []
    task_mtimes = 0
    task_count = 0
    tasks_root = ACCOUNTS_DIR / TASKS_SUBDIR
    for entry in entries:
        name = entry.name
        try:
            if entry.is_file():
                if name.endswith(".txt") and name not in IGNORED_ACCOUNT_FILENAMES:
                    root_txt_names.append(name)
            elif entry.is_dir() and name == TASKS_SUBDIR:
                for sub in tasks_root.iterdir():
                    if not sub.is_dir():
                        continue
                    task_count += 1
                    try:
                        task_mtimes += int(sub.stat().st_mtime_ns)
                    except OSError:
                        pass
        except OSError:
            continue
    return (len(root_txt_names), hash(tuple(sorted(root_txt_names))), task_count, task_mtimes)


def _scan_account_dirs() -> dict:
    """全量扫描根目录与任务目录，按邮箱去重（新文件覆盖旧记录）。"""
    records: dict[str, AccountCredential] = {}
    tasks: dict[str, str] = {}
    mtimes: dict[str, float] = {}
    sources: dict[str, int] = {}

    roots: list[tuple[str, Path]] = [("", ACCOUNTS_DIR)]
    tasks_root = ACCOUNTS_DIR / TASKS_SUBDIR
    if tasks_root.is_dir():
        for task_dir in sorted((p for p in tasks_root.iterdir() if p.is_dir()), key=lambda p: p.name):
            roots.append((task_dir.name, task_dir))

    for task_id, root in roots:
        try:
            paths = [p for p in root.glob("*.txt") if p.name not in IGNORED_ACCOUNT_FILENAMES]
        except OSError:
            continue
        for path in paths:
            try:
                stat = path.stat()
                mtime = stat.st_mtime
                if not stat.st_size:
                    continue
                line = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()[0]
            except (OSError, IndexError):
                continue
            record = parse_account_line(line)
            if record is None:
                continue
            email = record.email
            sources[email] = sources.get(email, 0) + 1
            if email in records and mtimes.get(email, 0) >= mtime:
                continue
            records[email] = record
            tasks[email] = task_id
            mtimes[email] = mtime
    return {"records": records, "tasks": tasks, "mtime": mtimes, "sources": sources}


def _fresh_scan(force: bool = False) -> None:
    signature = _dir_signature()
    now = time.time()
    with _lock:
        # 目录签名一致即命中缓存（账号文件的增删都会体现在目录 mtime 上），
        # TTL 只是内容被原地改写等签名盲区的兜底，避免常规轮询反复全量扫描。
        safety_expired = now - float(_cache.get("built_at") or 0) > CACHE_TTL_SECONDS * 8
        if (
            not force
            and not safety_expired
            and _cache.get("signature") == signature
            and _cache.get("records")
        ):
            return
        data = _scan_account_dirs()
        _cache.update(data)
        _cache["signature"] = signature
        _cache["built_at"] = now


def invalidate_cache() -> None:
    with _lock:
        _cache["built_at"] = 0.0
        _cache["signature"] = None


# ---------------------------------------------------------------- status store

def _load_status_store() -> dict:
    try:
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8") or "{}")
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    accounts = data.get("accounts")
    return accounts if isinstance(accounts, dict) else {}


def _save_status_store(accounts: dict) -> None:
    payload = {
        "accounts": accounts,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    atomic_write_json(STATUS_FILE, payload)


def set_account_status(emails: list[str], status: str) -> dict:
    normalized = str(status or "").strip().lower()
    clear = normalized in ("", "clear", "none")
    if not clear and normalized not in VALID_STATUSES:
        return {"ok": False, "error": f"status 必须是 {'/'.join(VALID_STATUSES)} 或 clear"}

    wanted: set[str] = set()
    for item in emails or []:
        email = str(item or "").strip().lower()
        if email:
            wanted.add(email)
    if not wanted:
        return {"ok": False, "error": "没有选中的账号"}
    if len(wanted) > MAX_EMAILS_PER_REQUEST:
        return {"ok": False, "error": f"一次最多操作 {MAX_EMAILS_PER_REQUEST} 个账号"}

    with exclusive_file_lock(STATUS_LOCK_FILE):
        accounts = dict(_load_status_store())
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        changed = 0
        for email in sorted(wanted):
            if clear:
                if email in accounts:
                    accounts.pop(email, None)
                    changed += 1
                continue
            entry = accounts.get(email) if isinstance(accounts.get(email), dict) else {}
            if entry.get("status") != normalized:
                changed += 1
            accounts[email] = {
                "status": normalized,
                "updated_at": stamp,
            }
        _save_status_store(accounts)
    invalidate_cache()
    return {
        "ok": True,
        "changed": changed,
        "status": "unused" if clear else normalized,
        "label": "未使用" if clear else STATUS_LABELS[normalized],
    }


# ---------------------------------------------------------------- listing

def _status_of(store: dict, email: str) -> str:
    entry = store.get(email)
    if isinstance(entry, dict):
        status = str(entry.get("status") or "").strip().lower()
        if status in VALID_STATUSES:
            return status
    return "unused"


def _fmt_time(epoch: float) -> str:
    if not epoch:
        return "--"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))


def _mask_secret(value: str, keep: int) -> str:
    if not value:
        return ""
    return value[:keep] + "••••"


def list_accounts(
    *,
    page: int = 1,
    page_size: int = 50,
    search: str = "",
    task: str = "",
    status: str = "",
    sort: str = "newest",
    reveal: bool = False,
    force: bool = False,
) -> dict:
    _fresh_scan(force=force)
    with _lock:
        records = dict(_cache["records"])
        task_map = dict(_cache["tasks"])
        mtime_map = dict(_cache["mtime"])
        source_map = dict(_cache["sources"])
    store = _load_status_store()

    stats = {"total": len(records), "unused": 0, "used": 0, "disabled": 0}
    for email in records:
        stats[_status_of(store, email)] += 1

    search_key = str(search or "").strip().lower()
    task_key = str(task or "").strip()
    status_key = str(status or "").strip().lower()

    task_counts: dict[str, int] = {}
    rows = []
    for email, record in records.items():
        task_id = task_map.get(email, "")
        row_status = _status_of(store, email)
        task_counts[task_id or ROOT_TASK_KEY] = task_counts.get(task_id or ROOT_TASK_KEY, 0) + 1
        if search_key and search_key not in email:
            continue
        if task_key and task_key != (task_id or ROOT_TASK_KEY):
            continue
        if status_key and status_key != row_status:
            continue
        rows.append(
            {
                "email": email,
                "task": task_id,
                "task_key": task_id or ROOT_TASK_KEY,
                "copies": max(1, int(source_map.get(email, 1))),
                "registered_ts": round(mtime_map.get(email, 0), 3),
                "registered_at": _fmt_time(mtime_map.get(email, 0)),
                "status": row_status,
                "status_label": STATUS_LABELS[row_status],
                "status_updated_at": str((store.get(email) or {}).get("updated_at") or ""),
                "password": record.password if reveal else _mask_secret(record.password, 2),
                "sso": record.sso if reveal else _mask_secret(record.sso, 12),
                "sso_len": len(record.sso),
            }
        )

    if sort == "oldest":
        rows.sort(key=lambda r: (r["registered_ts"], r["email"]))
    elif sort == "email":
        rows.sort(key=lambda r: r["email"])
    elif sort == "email_desc":
        rows.sort(key=lambda r: r["email"], reverse=True)
    else:
        rows.sort(key=lambda r: (-r["registered_ts"], r["email"]))

    try:
        size = max(1, min(MAX_PAGE_SIZE, int(page_size)))
    except (TypeError, ValueError):
        size = 50
    total_filtered = len(rows)
    try:
        current = max(1, int(page))
    except (TypeError, ValueError):
        current = 1
    pages = max(1, (total_filtered + size - 1) // size)
    current = min(current, pages)
    page_rows = rows[(current - 1) * size : current * size]

    task_list = [
        {"key": key, "id": "" if key == ROOT_TASK_KEY else key, "count": count}
        for key, count in task_counts.items()
    ]
    task_list.sort(key=lambda t: (0 if t["key"] == ROOT_TASK_KEY else 1, t["key"]))

    return {
        "ok": True,
        "page": current,
        "pages": pages,
        "page_size": size,
        "filtered": total_filtered,
        "stats": stats,
        "tasks": task_list,
        "items": page_rows,
        "accounts_dir": str(ACCOUNTS_DIR),
        "status_file": str(STATUS_FILE),
        "reveal": bool(reveal),
    }


def resolve_filtered_emails(*, search: str = "", task: str = "", status: str = "") -> list[str]:
    """按筛选条件解析全部命中邮箱（供“全选筛选结果”复制/导出）。"""
    _fresh_scan()
    with _lock:
        emails = sorted(_cache["records"].keys())
        task_map = dict(_cache["tasks"])
    store = _load_status_store()
    search_key = str(search or "").strip().lower()
    task_key = str(task or "").strip()
    status_key = str(status or "").strip().lower()

    out = []
    for email in emails:
        if search_key and search_key not in email:
            continue
        task_id = task_map.get(email, "") or ROOT_TASK_KEY
        if task_key and task_key != task_id:
            continue
        if status_key and status_key != _status_of(store, email):
            continue
        out.append(email)
    return out


# ---------------------------------------------------------------- copy / export

def build_payload(emails: list[str], fmt: str) -> dict:
    normalized_fmt = str(fmt or "full").strip().lower()
    if normalized_fmt not in VALID_FORMATS:
        return {"ok": False, "error": f"fmt 必须是 {'/'.join(VALID_FORMATS)}"}
    wanted = []
    seen = set()
    for item in emails or []:
        email = str(item or "").strip().lower()
        if email and email not in seen:
            seen.add(email)
            wanted.append(email)
    if not wanted:
        return {"ok": False, "error": "没有选中的账号"}
    if len(wanted) > MAX_EMAILS_PER_REQUEST:
        return {"ok": False, "error": f"一次最多导出 {MAX_EMAILS_PER_REQUEST} 个账号"}

    _fresh_scan()
    with _lock:
        records = dict(_cache["records"])
    missing = [email for email in wanted if email not in records]
    found = [records[email] for email in wanted if email in records]
    if normalized_fmt == "sso":
        lines = [record.sso for record in found]
    elif normalized_fmt == "emails":
        lines = [record.email for record in found]
    elif normalized_fmt == "jsonl":
        lines = [record.grok2api_json() for record in found]
    else:
        lines = [record.master_line() for record in found]
    content = "".join(line + "\n" for line in lines)
    return {
        "ok": True,
        "fmt": normalized_fmt,
        "count": len(found),
        "missing": missing[:20],
        "missing_count": len(missing),
        "content": content,
    }


# ---------------------------------------------------------------- delete

def delete_accounts(emails: list[str]) -> dict:
    wanted = []
    seen = set()
    for item in emails or []:
        email = str(item or "").strip().lower()
        if email and email not in seen:
            seen.add(email)
            wanted.append(email)
    if not wanted:
        return {"ok": False, "error": "没有选中的账号"}
    if len(wanted) > MAX_EMAILS_PER_REQUEST:
        return {"ok": False, "error": f"一次最多删除 {MAX_EMAILS_PER_REQUEST} 个账号"}
    try:
        result = delete_account_records(ACCOUNTS_DIR, wanted)
    except Exception as exc:
        return {"ok": False, "error": redact_log_line(str(exc))}
    if result.get("ok"):
        # 同步清理状态记录，避免残留孤儿状态
        with exclusive_file_lock(STATUS_LOCK_FILE):
            accounts = dict(_load_status_store())
            removed = 0
            for email in wanted:
                if email in accounts:
                    accounts.pop(email, None)
                    removed += 1
            if removed:
                _save_status_store(accounts)
        result["status_removed"] = removed
        invalidate_cache()
    return result
