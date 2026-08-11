"""Bounded retry policy shared by browser, batch, and orchestrator layers."""

from __future__ import annotations

import os
from typing import Mapping


BROWSER_START_ATTEMPTS_DEFAULT = 2
PROXY_BOOT_ROTATIONS_DEFAULT = 3
SLOT_RETRIES_DEFAULT = 1
BATCH_MAX_RESTARTS_DEFAULT = 2
ORCH_MAX_CONSECUTIVE_FAILURES_DEFAULT = 2
PRECHECK_EXIT_CODE = 78


def bounded_env_int(
    name: str,
    default: int,
    *,
    minimum: int = 0,
    maximum: int,
    environ: Mapping[str, str] | None = None,
) -> int:
    source = os.environ if environ is None else environ
    try:
        value = int(str(source.get(name, default)).strip())
    except (TypeError, ValueError):
        value = int(default)
    return max(int(minimum), min(int(maximum), value))


def browser_start_attempts(environ: Mapping[str, str] | None = None) -> int:
    return bounded_env_int(
        "GROK_BROWSER_START_ATTEMPTS",
        BROWSER_START_ATTEMPTS_DEFAULT,
        minimum=1,
        maximum=4,
        environ=environ,
    )


def proxy_boot_rotations(environ: Mapping[str, str] | None = None) -> int:
    return bounded_env_int(
        "GROK_PROXY_BOOT_ROTATIONS",
        PROXY_BOOT_ROTATIONS_DEFAULT,
        minimum=0,
        maximum=10,
        environ=environ,
    )


def slot_retries(environ: Mapping[str, str] | None = None) -> int:
    return bounded_env_int(
        "GROK_SLOT_RETRIES",
        SLOT_RETRIES_DEFAULT,
        minimum=0,
        maximum=3,
        environ=environ,
    )


def orchestrator_failure_limit(environ: Mapping[str, str] | None = None) -> int:
    return bounded_env_int(
        "GROK_ORCH_MAX_CONSECUTIVE_FAILURES",
        ORCH_MAX_CONSECUTIVE_FAILURES_DEFAULT,
        minimum=1,
        maximum=10,
        environ=environ,
    )
