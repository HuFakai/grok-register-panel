"""Private account storage and grok2api-compatible export generation."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from secure_files import atomic_write_text, ensure_private_dir, exclusive_file_lock


MASTER_FILENAME = "accounts_all.txt"
GROK2API_SSO_FILENAME = "grok2api_web_sso.txt"
GROK2API_JSONL_FILENAME = "grok2api_web_accounts.jsonl"
GENERATED_EXPORT_FILENAMES = {
    MASTER_FILENAME,
    GROK2API_SSO_FILENAME,
    GROK2API_JSONL_FILENAME,
}
IGNORED_ACCOUNT_FILENAMES = GENERATED_EXPORT_FILENAMES | {
    "mail_credentials.txt",
    "sso_pending.txt",
    "sso_risk_rejected.txt",
}
# 每个注册任务一个子目录（accounts/tasks/<任务ID>/），避免账号过多时
# accounts 根目录堆满 <email>.txt 文件；根目录仍保留全量聚合文件。
TASKS_SUBDIR = "tasks"


@dataclass(frozen=True)
class AccountCredential:
    email: str
    password: str
    sso: str

    def master_line(self) -> str:
        return f"{self.email}----{self.password}----{self.sso}"

    def grok2api_json(self) -> str:
        return json.dumps(
            {
                "provider": "grok_web",
                "name": self.email,
                "email": self.email,
                "sso_token": self.sso,
                "tier": "auto",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )


def _clean_field(value: object, label: str, *, allow_empty: bool = False) -> str:
    text = str(value or "").strip()
    if not allow_empty and not text:
        raise ValueError(f"{label}为空")
    if "\n" in text or "\r" in text or "\x00" in text:
        raise ValueError(f"{label}包含非法换行或控制字符")
    return text


def normalize_account_record(email: object, password: object, sso: object) -> AccountCredential:
    normalized_email = _clean_field(email, "邮箱").lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+", normalized_email):
        raise ValueError("邮箱格式无效")
    normalized_password = _clean_field(password, "密码", allow_empty=True)
    normalized_sso = _clean_field(sso, "SSO")
    if normalized_sso.lower().startswith("sso="):
        normalized_sso = normalized_sso[4:].strip()
    if len(normalized_sso) < 24 or any(char.isspace() for char in normalized_sso):
        raise ValueError("SSO 格式无效")
    return AccountCredential(normalized_email, normalized_password, normalized_sso)


def parse_account_line(line: object) -> AccountCredential | None:
    raw = str(line or "").strip()
    if not raw or raw.startswith("#") or "----" not in raw:
        return None
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) < 3:
        return None
    try:
        return normalize_account_record(parts[0], "----".join(parts[1:-1]), parts[-1])
    except ValueError:
        return None


def _source_files(root: Path) -> list[Path]:
    """账号源文件：仅扫描 root 目录内（任务目录或根目录）的账号 txt。"""
    candidates = []
    for path in root.glob("*.txt"):
        if path.name in IGNORED_ACCOUNT_FILENAMES:
            continue
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            continue
        candidates.append((mtime, path.name, path))
    return [path for _mtime, _name, path in sorted(candidates)]


def _load_records(root: Path) -> dict[str, AccountCredential]:
    records: dict[str, AccountCredential] = {}
    master = root / MASTER_FILENAME
    sources = _source_files(root)
    if master.is_file():
        sources.append(master)
    sources.sort(
        key=lambda path: (
            path.stat().st_mtime_ns if path.exists() else 0,
            path.name,
        )
    )
    for path in sources:
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            continue
        for line in lines:
            record = parse_account_line(line)
            if record is not None:
                records[record.email] = record
    return records


def _write_exports(root: Path, records: dict[str, AccountCredential]) -> dict:
    ordered = [records[email] for email in sorted(records)]
    master_text = "".join(f"{record.master_line()}\n" for record in ordered)
    sso_text = "".join(f"{record.sso}\n" for record in ordered)
    jsonl_text = "".join(f"{record.grok2api_json()}\n" for record in ordered)
    master_path = atomic_write_text(root / MASTER_FILENAME, master_text)
    sso_path = atomic_write_text(root / GROK2API_SSO_FILENAME, sso_text)
    jsonl_path = atomic_write_text(root / GROK2API_JSONL_FILENAME, jsonl_text)
    return {
        "count": len(ordered),
        "master": str(master_path),
        "grok2api_sso": str(sso_path),
        "grok2api_jsonl": str(jsonl_path),
    }


def save_account_record(
    accounts_dir: str | os.PathLike[str],
    email: object,
    password: object,
    sso: object,
    *,
    task_subdir: str | None = None,
) -> dict:
    """Save one account and atomically refresh the task-level aggregate exports.

    task_subdir 非空时写入 accounts_dir/tasks/<task_subdir>/ 下，聚合文件
    （accounts_all.txt 等）也生成在该任务目录内（任务自包含）；None 时保持
    写入根目录并刷新根目录聚合（兼容旧调用/遗留数据）。
    """
    base = ensure_private_dir(accounts_dir)
    root = base
    if task_subdir:
        safe_subdir = str(task_subdir).strip().strip("/\\")
        if not safe_subdir or safe_subdir in (".", ".."):
            raise ValueError(f"任务目录名非法: {task_subdir!r}")
        root = ensure_private_dir(base / TASKS_SUBDIR / safe_subdir)
    record = normalize_account_record(email, password, sso)
    lock_path = root / ".account_exports.lock"
    with exclusive_file_lock(lock_path):
        records = _load_records(root)
        records[record.email] = record
        atomic_write_text(root / f"{record.email}.txt", f"{record.master_line()}\n")
        return _write_exports(root, records)


def consolidate_account_exports(accounts_dir: str | os.PathLike[str]) -> dict:
    """Rebuild per-task aggregate files after a GUI/CLI registration round.

    对 accounts/tasks/*/ 下每个任务目录刷新其任务级聚合（accounts_all.txt /
    grok2api 导入文件）；根目录遗留的历史账号文件仍兼容刷新根目录聚合。
    """
    base = ensure_private_dir(accounts_dir)
    tasks_root = base / TASKS_SUBDIR
    task_count = 0
    task_accounts = 0
    if tasks_root.is_dir():
        for task_dir in sorted(
            (p for p in tasks_root.iterdir() if p.is_dir()),
            key=lambda p: p.name,
        ):
            lock_path = task_dir / ".account_exports.lock"
            with exclusive_file_lock(lock_path):
                records = _load_records(task_dir)
                if not records:
                    continue
                _write_exports(task_dir, records)
                task_count += 1
                task_accounts += len(records)
    legacy_accounts = 0
    legacy = [
        p
        for p in base.glob("*.txt")
        if p.name not in IGNORED_ACCOUNT_FILENAMES
    ]
    if legacy:
        lock_path = base / ".account_exports.lock"
        with exclusive_file_lock(lock_path):
            records = _load_records(base)
            if records:
                _write_exports(base, records)
                legacy_accounts = len(records)
    return {
        "count": task_accounts + legacy_accounts,
        "tasks": task_count,
        "legacy_count": legacy_accounts,
    }
