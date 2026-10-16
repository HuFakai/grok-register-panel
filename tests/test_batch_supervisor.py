# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from batch_supervisor import (
    DEFAULT_MAX_RESTARTS,
    PROGRESS_ENV,
    initialize_progress,
    is_driver_crash_line,
    mark_slot_completed,
    read_completed,
    run_supervisor,
)
from retry_policy import PRECHECK_EXIT_CODE


def test_driver_crash_detection_is_specific():
    assert is_driver_crash_line(
        "TypeError: Cannot read properties of undefined (reading '_getChildFrames')"
    )
    assert is_driver_crash_line("Connection closed while reading from the driver")
    assert not is_driver_crash_line("[W1] 注册风控拒绝")


def test_progress_updates_are_thread_safe_and_private():
    with tempfile.TemporaryDirectory() as temp:
        progress = initialize_progress(Path(temp) / "progress.json", 200)
        previous = os.environ.get(PROGRESS_ENV)
        os.environ[PROGRESS_ENV] = str(progress)
        try:
            threads = [
                threading.Thread(
                    target=lambda: [mark_slot_completed() for _ in range(25)]
                )
                for _ in range(8)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            if previous is None:
                os.environ.pop(PROGRESS_ENV, None)
            else:
                os.environ[PROGRESS_ENV] = previous
        assert read_completed(progress) == 200
        if os.name == "posix":
            assert stat.S_IMODE(progress.stat().st_mode) == 0o600


def test_supervisor_restarts_after_driver_crash():
    with tempfile.TemporaryDirectory() as temp:
        temp_root = Path(temp)
        progress = temp_root / "progress.json"
        launches = temp_root / "launches.json"
        fake_child = temp_root / "fake_child.py"
        fake_child.write_text(
            """
import json
import sys
import time
from pathlib import Path

from batch_supervisor import mark_slot_completed

state = Path(sys.argv[1])
remaining = int(sys.argv[2])
try:
    launches = int(json.loads(state.read_text()).get("launches", 0))
except Exception:
    launches = 0
launches += 1
state.write_text(json.dumps({"launches": launches}))
if launches == 1:
    print("progress line before crash marker", flush=True)
    print("TypeError: Cannot read properties of undefined (reading '_getChildFrames')", flush=True)
    time.sleep(30)
else:
    mark_slot_completed(remaining)
    print("fake child complete", flush=True)
""".lstrip(),
            encoding="utf-8",
        )

        def command(remaining: int, _workers: int) -> list[str]:
            return [sys.executable, str(fake_child), str(launches), str(remaining)]

        started = time.monotonic()
        result = run_supervisor(
            5,
            3,
            command,
            progress_file=progress,
            idle_timeout=30,
            max_restarts=2,
            child_env={"PYTHONPATH": str(ROOT)},
        )
        elapsed = time.monotonic() - started
        assert result == 0
        assert json.loads(launches.read_text())["launches"] == 2
        assert elapsed < 10
        assert not progress.exists()



def test_supervisor_does_not_restart_precheck_failure():
    assert DEFAULT_MAX_RESTARTS == 2
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        progress = root / "progress.json"
        launches = root / "launches.txt"
        child = root / "precheck_fail.py"
        child.write_text(
            """
import sys
from pathlib import Path
path = Path(sys.argv[1])
count = int(path.read_text()) if path.exists() else 0
path.write_text(str(count + 1))
raise SystemExit(78)
""".lstrip(),
            encoding="utf-8",
        )

        result = run_supervisor(
            4,
            2,
            lambda _remaining, _workers: [sys.executable, str(child), str(launches)],
            progress_file=progress,
            max_restarts=2,
        )
        assert result == PRECHECK_EXIT_CODE
        assert launches.read_text() == "1"


def test_clean_exit_drains_pipe_before_restart_decision():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        progress = root / "progress.json"
        child = root / "clean_child.py"
        child.write_text(
            """
import sys
from batch_supervisor import mark_slot_completed
mark_slot_completed(int(sys.argv[1]))
sys.stdout.write("final line without newline")
raise SystemExit(0)
""".lstrip(),
            encoding="utf-8",
        )
        result = run_supervisor(
            3,
            1,
            lambda remaining, _workers: [sys.executable, str(child), str(remaining)],
            progress_file=progress,
            idle_timeout=1,
            max_restarts=0,
            child_env={"PYTHONPATH": str(ROOT)},
        )
        assert result == 0


if __name__ == "__main__":

    test_driver_crash_detection_is_specific()
    test_progress_updates_are_thread_safe_and_private()
    test_supervisor_restarts_after_driver_crash()
    test_supervisor_does_not_restart_precheck_failure()
    test_clean_exit_drains_pipe_before_restart_decision()
    print("OK batch supervisor")
