# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui.log_cleanup import cleanup_expired_logs


def test_cleanup_only_removes_expired_unprotected_log_files():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        old_log = root / "old.log"
        current_log = root / "current.log"
        fresh_log = root / "fresh.log"
        state_file = root / "proxy_pool.json"
        for path in (old_log, current_log, fresh_log, state_file):
            path.write_text(path.name, encoding="utf-8")
        now = 2_000_000_000.0
        old_time = now - 10 * 86400
        fresh_time = now - 3600
        os.utime(old_log, (old_time, old_time))
        os.utime(current_log, (old_time, old_time))
        os.utime(fresh_log, (fresh_time, fresh_time))
        os.utime(state_file, (old_time, old_time))

        result = cleanup_expired_logs(
            root,
            7,
            now=now,
            protected=[current_log],
        )

        assert result["ok"] is True
        assert result["deleted"] == ["old.log"]
        assert result["deleted_count"] == 1
        assert result["freed_bytes"] == len("old.log")
        assert not old_log.exists()
        assert current_log.exists()
        assert fresh_log.exists()
        assert state_file.exists()


def test_cleanup_rejects_unsafe_retention_ranges():
    with tempfile.TemporaryDirectory() as tmp:
        for value in (0, 366, "not-a-number"):
            try:
                cleanup_expired_logs(Path(tmp), value)
            except ValueError:
                pass
            else:
                raise AssertionError(f"retention value should fail: {value!r}")


if __name__ == "__main__":
    test_cleanup_only_removes_expired_unprotected_log_files()
    test_cleanup_rejects_unsafe_retention_ranges()
    print("OK log_cleanup")
