"""Conservative retention cleanup for generated runtime log files."""

from __future__ import annotations

import time
from pathlib import Path


MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 365


def cleanup_expired_logs(
    log_dir: Path,
    retention_days: object = 7,
    *,
    now: float | None = None,
    protected: tuple[Path, ...] | list[Path] = (),
) -> dict:
    """Delete direct-child ``*.log`` files older than the retention cutoff.

    State JSON, lock files, PID files, account result journals and symlinks are
    intentionally out of scope. The caller can protect current/latest log paths.
    """
    try:
        days = int(retention_days)
    except (TypeError, ValueError) as exc:
        raise ValueError("日志保留天数必须是整数") from exc
    if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
        raise ValueError(
            f"日志保留天数必须在 {MIN_RETENTION_DAYS}-{MAX_RETENTION_DAYS} 天之间"
        )

    root = Path(log_dir).resolve()
    cutoff = float(time.time() if now is None else now) - days * 86400
    protected_paths = {Path(path).resolve() for path in protected if path}
    deleted: list[str] = []
    errors: list[dict[str, str]] = []
    freed_bytes = 0

    if not root.is_dir():
        return {
            "ok": True,
            "retention_days": days,
            "deleted_count": 0,
            "freed_bytes": 0,
            "deleted": [],
            "errors": [],
        }

    for path in sorted(root.glob("*.log"), key=lambda value: value.name):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            resolved = path.resolve()
            if resolved.parent != root or resolved in protected_paths:
                continue
            stat = path.stat()
            if stat.st_mtime >= cutoff:
                continue
            size = stat.st_size
            path.unlink()
            deleted.append(path.name)
            freed_bytes += size
        except OSError as exc:
            errors.append({"file": path.name, "error": str(exc)[:160]})

    return {
        "ok": not errors,
        "retention_days": days,
        "deleted_count": len(deleted),
        "freed_bytes": freed_bytes,
        "deleted": deleted,
        "errors": errors,
    }
