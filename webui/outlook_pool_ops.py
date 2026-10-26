"""Outlook 卡池（待用/已用卡密文件）的面板管理操作。

行格式与 email_providers/outlook.py 保持一致：
email----password----client_id----refresh_token
写文件复用取号/回收同一把文件锁，避免与注册 worker 并发写互相覆盖。
"""

from __future__ import annotations

from email_providers.outlook import (
    DEFAULT_ACCOUNTS_FILE,
    DEFAULT_USED_FILE,
    _lines_text,
    _parse_line,
    _pool_lock,
    _pool_paths,
    _read_lines,
)
from secure_files import atomic_write_text


class OutlookPoolError(ValueError):
    pass


def _clean_refresh_tail(token: str) -> str:
    # 批发卡密常见污染：refresh_token 尾部被脚本重复拼接 "$$"。
    return token.rstrip("$")


def _normalize_line(line: str) -> str:
    text = line.strip()
    if not text or text.startswith("#"):
        raise OutlookPoolError("空行或注释行")
    parts = text.split("----")
    if len(parts) < 4:
        raise OutlookPoolError(f"行格式无效（需要 email----password----client_id----refresh_token）: {text[:12]}…")
    email = parts[0].strip().lower()
    if "@" not in email:
        raise OutlookPoolError(f"邮箱格式无效: {email[:12]}…")
    return "----".join([email, parts[1].strip(), parts[2].strip(), _clean_refresh_tail(parts[3])])


def _row_email(line: str) -> str:
    return line.split("----", 1)[0].strip().lower()


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = local[:1] + "*"
    else:
        masked = local[:2] + "***" + local[-1:]
    return f"{masked}@{domain}"


def outlook_pool_paths(accounts_file: str | None = None, used_file: str | None = None):
    try:
        return _pool_paths(
            accounts_file or DEFAULT_ACCOUNTS_FILE,
            used_file or DEFAULT_USED_FILE,
        )
    except ValueError as exc:
        raise OutlookPoolError(str(exc)) from exc


def outlook_pool_stats(accounts_file: str | None = None, used_file: str | None = None) -> dict:
    pending, used = outlook_pool_paths(accounts_file, used_file)
    with _pool_lock(pending, used):
        pending_lines = _read_lines(pending)
        used_lines = _read_lines(used)
    pending_emails = {_row_email(line) for line in pending_lines}
    used_emails = {_row_email(line) for line in used_lines}
    return {
        "pending": len(pending_lines),
        "used": len(used_lines),
        "total": len(pending_emails | used_emails),
        "available": len(pending_emails - used_emails),
        "duplicate_pending": len(pending_lines) - len(pending_emails),
        "duplicate_used": len(used_lines) - len(used_emails),
        "overlap": len(pending_emails & used_emails),
        "missing_file": {"pending": not pending.is_file(), "used": not used.is_file()},
        "pending_path": str(pending),
        "used_path": str(used),
    }


def outlook_pool_rows(accounts_file: str | None = None, used_file: str | None = None) -> dict:
    """返回脱敏明细：pending 行在前，used 追加在后，重叠邮箱以 used 状态显示。"""
    pending, used = outlook_pool_paths(accounts_file, used_file)
    with _pool_lock(pending, used):
        pending_lines = _read_lines(pending)
        used_lines = _read_lines(used)
    seen: dict[str, dict] = {}
    order: list[str] = []
    for state, lines in (("pending", pending_lines), ("used", used_lines)):
        for line in lines:
            email = _row_email(line)
            parsed = _parse_line(line)
            if email not in seen:
                seen[email] = {
                    "email": email,
                    "email_masked": _mask_email(email),
                    "state": state,
                    "client_id": (parsed[2] if parsed else ""),
                    "has_refresh": bool(parsed and parsed[3]),
                }
                order.append(email)
            elif state == "used":
                seen[email]["state"] = "used"
    rows = [seen[email] for email in order]
    return {"stats": outlook_pool_stats(accounts_file, used_file), "rows": rows}


def outlook_pool_import(text: str, accounts_file: str | None = None,
                        used_file: str | None = None) -> dict:
    """解析多行卡密文本并入池：去重、剥 refresh_token 尾部 '$$'，已存在行跳过。"""
    pending, used = outlook_pool_paths(accounts_file, used_file)
    normalized: list[str] = []
    for raw in str(text or "").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        normalized.append(_normalize_line(raw))
    if not normalized:
        raise OutlookPoolError("没有可导入的卡密行")
    with _pool_lock(pending, used):
        pending_lines = _read_lines(pending)
        used_lines = _read_lines(used)
        known = {_row_email(line) for line in pending_lines} | {_row_email(line) for line in used_lines}
        fresh: list[str] = []
        seen_batch: set[str] = set()
        for line in normalized:
            email = _row_email(line)
            if email in known or email in seen_batch:
                continue
            seen_batch.add(email)
            fresh.append(line)
        if fresh:
            atomic_write_text(pending, _lines_text(pending_lines + fresh))
    return {
        "ok": True,
        "added": len(fresh),
        "skipped_duplicate": len(normalized) - len(fresh),
        "stats": outlook_pool_stats(accounts_file, used_file),
    }


def outlook_pool_export(accounts_file: str | None = None,
                        used_file: str | None = None) -> dict:
    """导出待用池全文（原始行，不脱敏）——仅面板管理员令牌接口返回。"""
    pending, used = outlook_pool_paths(accounts_file, used_file)
    with _pool_lock(pending, used):
        pending_lines = _read_lines(pending)
    return {"ok": True, "text": _lines_text(pending_lines)}


def outlook_pool_delete(emails: list, accounts_file: str | None = None,
                        used_file: str | None = None) -> dict:
    """按邮箱删除记录：待用行直接移除，已用行默认保留（防复用），除非 force。"""
    targets = {str(item).strip().lower() for item in emails if str(item).strip()}
    if not targets:
        raise OutlookPoolError("未指定要删除的邮箱")
    pending, used = outlook_pool_paths(accounts_file, used_file)
    with _pool_lock(pending, used):
        pending_lines = _read_lines(pending)
        used_lines = _read_lines(used)
        kept_pending = [line for line in pending_lines if _row_email(line) not in targets]
        deleted_pending = len(pending_lines) - len(kept_pending)
        if deleted_pending:
            atomic_write_text(pending, _lines_text(kept_pending))
    return {
        "ok": True,
        "deleted_pending": deleted_pending,
        "skipped_used": len(targets & {_row_email(line) for line in used_lines}),
        "stats": outlook_pool_stats(accounts_file, used_file),
    }
