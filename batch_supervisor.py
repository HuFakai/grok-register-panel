"""Supervise headless registration batches and recover crashed browser drivers."""

from __future__ import annotations

import codecs
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Mapping, Sequence

import psutil

from runtime_platform import popen_group_kwargs
from retry_policy import BATCH_MAX_RESTARTS_DEFAULT, PRECHECK_EXIT_CODE
from secure_files import atomic_write_json, exclusive_file_lock


PROGRESS_ENV = "GROK_BATCH_PROGRESS_FILE"
DEFAULT_IDLE_TIMEOUT = 360
DEFAULT_MAX_RESTARTS = BATCH_MAX_RESTARTS_DEFAULT
NON_RETRYABLE_EXIT_CODES = frozenset({PRECHECK_EXIT_CODE})

_PROGRESS_LOCK = threading.Lock()
_DRIVER_CRASH_MARKERS = (
    "Cannot read properties of undefined (reading '_getChildFrames')",
    "Cannot read properties of undefined (reading 'childFrames')",
    "Connection closed while reading from the driver",
    "Playwright driver unexpectedly exited",
)


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


def _write_output(text: str) -> None:
    try:
        print(text, end="", flush=True)
    except UnicodeEncodeError:  # pragma: no cover - legacy Windows consoles
        buffer = getattr(sys.stdout, "buffer", None)
        if buffer is not None:
            buffer.write(text.encode("utf-8", errors="replace"))
            buffer.flush()


def _read_pipe(pipe, output: queue.Queue) -> None:
    try:
        while True:
            try:
                chunk = os.read(pipe.fileno(), 65536)
            except OSError:
                break
            if not chunk:
                break
            output.put(chunk)
    finally:
        output.put(None)


_configure_utf8_stdio()


def is_driver_crash_line(line: str) -> bool:
    text = str(line or "")
    return any(marker in text for marker in _DRIVER_CRASH_MARKERS)


def read_completed(path: str | os.PathLike[str]) -> int:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return max(0, int(data.get("completed", 0) or 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0


def initialize_progress(path: str | os.PathLike[str], target: int) -> Path:
    progress_path = Path(path)
    atomic_write_json(
        progress_path,
        {
            "completed": 0,
            "target": max(0, int(target)),
            "updated_at": time.time(),
        },
    )
    return progress_path


def mark_slot_completed(slots: int = 1) -> None:
    """Persist completed task slots for the supervising parent process."""
    raw_path = str(os.environ.get(PROGRESS_ENV, "") or "").strip()
    if not raw_path:
        return
    increment = max(0, int(slots or 0))
    if increment <= 0:
        return

    path = Path(raw_path)
    lock_path = path.with_name(f"{path.name}.lock")
    with _PROGRESS_LOCK:
        with exclusive_file_lock(lock_path):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                data = {}
            completed = max(0, int(data.get("completed", 0) or 0)) + increment
            target = max(0, int(data.get("target", 0) or 0))
            if target:
                completed = min(completed, target)
            atomic_write_json(
                path,
                {
                    "completed": completed,
                    "target": target,
                    "updated_at": time.time(),
                },
            )


def _terminate_windows_process_tree(
    process: subprocess.Popen,
    grace_seconds: float = 5.0,
    *,
    psutil_module=psutil,
) -> None:
    tracked = []
    try:
        root = psutil_module.Process(process.pid)
        tracked = root.children(recursive=True) + [root]
    except (psutil_module.Error, OSError):
        tracked = []

    ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
    if ctrl_break is not None:
        try:
            process.send_signal(ctrl_break)
        except (OSError, ValueError):
            pass
    if tracked:
        _gone, alive = psutil_module.wait_procs(
            tracked,
            timeout=min(max(0.1, grace_seconds), 2.0),
        )
        for item in alive:
            try:
                item.terminate()
            except (psutil_module.Error, OSError):
                pass
        _gone, alive = psutil_module.wait_procs(
            alive,
            timeout=max(0.1, grace_seconds - 2.0),
        )
        for item in alive:
            try:
                item.kill()
            except (psutil_module.Error, OSError):
                pass
    else:
        try:
            process.terminate()
        except (OSError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=max(0.1, grace_seconds))
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass


def _terminate_process_group(process: subprocess.Popen, grace_seconds: float = 5.0) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - exercised through the injected unit test
            _terminate_windows_process_tree(process, grace_seconds)
            return
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=max(0.1, grace_seconds))
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - handled above
            _terminate_windows_process_tree(process, 0.5)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def run_supervisor(
    count: int,
    workers: int,
    child_command_builder: Callable[[int, int], Sequence[str]],
    *,
    progress_file: str | os.PathLike[str],
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    max_restarts: int = DEFAULT_MAX_RESTARTS,
    child_env: Mapping[str, str] | None = None,
    non_retryable_exit_codes: Sequence[int] = tuple(NON_RETRYABLE_EXIT_CODES),
) -> int:
    """Run a batch child and restart the remaining work after a driver crash."""
    target = max(1, int(count))
    worker_count = max(1, min(24, int(workers), target))
    progress_path = initialize_progress(progress_file, target)
    stop_requested = False
    active_process: subprocess.Popen | None = None
    restarts = 0

    def request_stop(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    can_install_signals = threading.current_thread() is threading.main_thread()
    previous_handlers: dict[int, object] = {}
    if can_install_signals:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)

    try:
        while not stop_requested:
            completed = read_completed(progress_path)
            remaining = max(0, target - completed)
            if remaining <= 0:
                print(
                    f"[supervisor] batch complete completed={completed}/{target} restarts={restarts}",
                    flush=True,
                )
                return 0
            if restarts > max(0, int(max_restarts)):
                print(
                    f"[supervisor] restart limit reached remaining={remaining} restarts={restarts}",
                    flush=True,
                )
                return 1

            command = [str(part) for part in child_command_builder(remaining, worker_count)]
            env = {**os.environ, **dict(child_env or {})}
            env[PROGRESS_ENV] = str(progress_path)
            print(
                f"[supervisor] starting child remaining={remaining} workers={worker_count} restart={restarts}",
                flush=True,
            )
            active_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0,
                env=env,
                **popen_group_kwargs(),
            )
            assert active_process.stdout is not None
            output_queue: queue.Queue[bytes | None] = queue.Queue()
            reader = threading.Thread(
                target=_read_pipe,
                args=(active_process.stdout, output_queue),
                daemon=True,
            )
            reader.start()
            last_output = time.monotonic()
            restart_reason = ""
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            pending_output = ""
            pipe_closed = False
            exit_seen_at = None

            while not stop_requested:
                try:
                    chunk = output_queue.get(timeout=1.0)
                except queue.Empty:
                    chunk = b""
                if chunk is None:
                    pipe_closed = True
                elif chunk:
                    last_output = time.monotonic()
                    pending_output += decoder.decode(chunk)
                    lines = pending_output.splitlines(keepends=True)
                    pending_output = ""
                    if lines and not lines[-1].endswith(("\n", "\r")):
                        pending_output = lines.pop()
                    for line in lines:
                        _write_output(line)
                        if is_driver_crash_line(line):
                            restart_reason = "playwright driver crashed"
                            break
                if restart_reason:
                    break
                return_code = active_process.poll()
                if return_code is not None and pipe_closed:
                    pending_output += decoder.decode(b"", final=True)
                    if pending_output:
                        _write_output(pending_output)
                        if is_driver_crash_line(pending_output):
                            restart_reason = "playwright driver crashed"
                    break
                if return_code is not None:
                    # The reader may still be draining bytes written immediately
                    # before process exit. EOF wins over idle detection.
                    exit_seen_at = exit_seen_at or time.monotonic()
                    if time.monotonic() - exit_seen_at > 2.0:
                        pending_output += decoder.decode(b"", final=True)
                        if pending_output:
                            _write_output(pending_output)
                        break
                    continue
                if time.monotonic() - last_output > max(1.0, float(idle_timeout)):
                    restart_reason = f"no child output for {int(idle_timeout)}s"
                    break

            if stop_requested:
                _terminate_process_group(active_process)
                try:
                    active_process.stdout.close()
                except OSError:
                    pass
                reader.join(timeout=2)
                return 130

            return_code = active_process.poll()
            if restart_reason:
                _terminate_process_group(active_process)
                try:
                    active_process.stdout.close()
                except OSError:
                    pass
                reader.join(timeout=2)
                restarts += 1
                remaining = max(0, target - read_completed(progress_path))
                print(
                    f"[supervisor] {restart_reason}; restarting remaining={remaining} attempt={restarts}/{max_restarts}",
                    flush=True,
                )
                time.sleep(min(1.0 * restarts, 5.0))
                continue

            try:
                active_process.stdout.close()
            except OSError:
                pass
            reader.join(timeout=2)

            completed = read_completed(progress_path)
            if return_code in {int(code) for code in non_retryable_exit_codes}:
                print(
                    f"[supervisor] child exited with non-retryable rc={return_code} "
                    f"completed={completed}/{target}",
                    flush=True,
                )
                return int(return_code)
            if return_code == 0 and completed >= target:
                print(
                    f"[supervisor] child exited cleanly completed={completed}/{target}",
                    flush=True,
                )
                return 0

            restarts += 1
            remaining = max(0, target - completed)
            print(
                f"[supervisor] child exited rc={return_code} completed={completed}/{target}; "
                f"restarting remaining={remaining} attempt={restarts}/{max_restarts}",
                flush=True,
            )
            time.sleep(min(1.0 * restarts, 5.0))
    finally:
        if active_process is not None and active_process.poll() is None:
            _terminate_process_group(active_process)
        if can_install_signals:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        for path in (progress_path, progress_path.with_name(f"{progress_path.name}.lock")):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    return 130
