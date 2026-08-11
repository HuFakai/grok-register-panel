#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import run_until_100 as orch
from retry_policy import PRECHECK_EXIT_CODE


class FakeProcess:
    def __init__(self, pid: int, return_code: int):
        self.pid = pid
        self.return_code = return_code

    def poll(self):
        return self.return_code


def _run_with_exit_codes(exit_codes):
    names = (
        "apply_control",
        "kill_batch",
        "cpa_count",
        "ok_count",
        "read_blocklist_asns",
        "start_batch",
        "batch_alive",
        "count_risk",
        "count_ok",
        "analyze_risks_and_expand",
        "orchestrator_failure_limit",
        "log",
    )
    previous = {name: getattr(orch, name) for name in names}
    previous_base = orch.BASE0
    previous_target = orch.TARGET_CPA
    previous_rounds = orch.MAX_ROUNDS
    launches = []
    messages = []
    codes = iter(exit_codes)
    try:
        with tempfile.TemporaryDirectory() as temp:
            log_path = Path(temp) / "batch.log"
            log_path.write_text("", encoding="utf-8")
            orch.BASE0 = 0
            orch.TARGET_CPA = 1
            orch.MAX_ROUNDS = 10
            orch.apply_control = lambda: None
            orch.kill_batch = lambda: None
            orch.cpa_count = lambda: 0
            orch.ok_count = lambda: 0
            orch.read_blocklist_asns = lambda: set()
            orch.batch_alive = lambda _pid: False
            orch.count_risk = lambda _path: 0
            orch.count_ok = lambda _path: 0
            orch.analyze_risks_and_expand = lambda _path: []
            orch.orchestrator_failure_limit = lambda: 2
            orch.log = messages.append

            def start_batch(_count):
                code = next(codes)
                launches.append(code)
                return FakeProcess(100 + len(launches), code), log_path

            orch.start_batch = start_batch
            original_sleep = orch.time.sleep
            orch.time.sleep = lambda _seconds: None
            try:
                orch.main()
            finally:
                orch.time.sleep = original_sleep
    finally:
        for name, value in previous.items():
            setattr(orch, name, value)
        orch.BASE0 = previous_base
        orch.TARGET_CPA = previous_target
        orch.MAX_ROUNDS = previous_rounds
    return launches, messages


def test_precheck_failure_stops_orchestrator_immediately():
    launches, messages = _run_with_exit_codes([PRECHECK_EXIT_CODE])
    assert launches == [PRECHECK_EXIT_CODE]
    assert any("precheck failed" in message for message in messages)


def test_consecutive_abnormal_batches_are_bounded():
    launches, messages = _run_with_exit_codes([1, 1, 1])
    assert launches == [1, 1]
    assert any("consecutive batch failures=2/2" in message for message in messages)


if __name__ == "__main__":
    test_precheck_failure_stops_orchestrator_immediately()
    test_consecutive_abnormal_batches_are_bounded()
    print("OK orchestrator policy")
