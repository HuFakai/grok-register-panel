#!/usr/bin/env python3
"""Grok register batch live monitor — bind Tailscale, control + blacklist panel."""
from __future__ import annotations

import json
import ipaddress
import os
import re
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json, best_effort_fchmod, ensure_private_dir
from batch_traffic import (
    read_metrics as read_batch_traffic,
    read_summary as read_batch_traffic_summary,
)
from runtime_platform import (
    batch_launch_command,
    batch_runtime_error,
    beijing_strftime,
    now_beijing,
    popen_group_kwargs,
    runtime_python,
)

try:
    from webui.blacklist_store import read_blacklist as read_blacklist_state
    from results_store import count_results, ok_count
    from webui.proxy_store import (
        delete_proxy,
        delete_proxies,
        import_legacy_proxies,
        import_proxies,
        read_proxy_pool,
        start_proxy_tests,
        update_proxy,
    )
    from webui.email_domain_store import (
        delete_domain,
        import_domains,
        read_email_domain_pool,
        reset_domain,
        update_domain,
        update_settings as update_email_domain_settings,
    )
    from webui.email_provider_store import (
        read_email_provider_config,
        save_email_provider_config,
        test_email_provider_config,
    )
    from webui.process_utils import (
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from webui.log_cleanup import cleanup_expired_logs
    from webui.recovery_ops import recovery_status, start_recovery, stop_recovery
    from webui.bfs_ops import bfs_status, check_token_text, run_bfs_scan
    from webui.sso_state_ops import (
        read_sso_state_export,
        sso_state_status,
        start_sso_state_scan,
        stop_sso_state_scan,
    )
    from webui.security_utils import (
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_log_line,
        redact_proxy,
    )
except ImportError:  # running as script from webui/
    from blacklist_store import read_blacklist as read_blacklist_state  # type: ignore
    from proxy_store import (  # type: ignore
        delete_proxy,
        delete_proxies,
        import_legacy_proxies,
        import_proxies,
        read_proxy_pool,
        start_proxy_tests,
        update_proxy,
    )
    from email_domain_store import (  # type: ignore
        delete_domain,
        import_domains,
        read_email_domain_pool,
        reset_domain,
        update_domain,
        update_settings as update_email_domain_settings,
    )
    from email_provider_store import (  # type: ignore
        read_email_provider_config,
        save_email_provider_config,
        test_email_provider_config,
    )
    from process_utils import (  # type: ignore
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from log_cleanup import cleanup_expired_logs  # type: ignore
    from recovery_ops import recovery_status, start_recovery, stop_recovery  # type: ignore
    from sso_state_ops import (  # type: ignore
        read_sso_state_export,
        sso_state_status,
        start_sso_state_scan,
        stop_sso_state_scan,
    )
    from security_utils import (  # type: ignore
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_log_line,
        redact_proxy,
    )
LOG_DIR = ROOT / "log"
BATCH_TRAFFIC = LOG_DIR / "batch_traffic.json"
BATCH_TRAFFIC_HISTORY = LOG_DIR / "batch_traffic_history.json"
CPA_DIR = Path(os.environ.get("CPA_AUTH_DIR", str(ROOT / "cpa_auth")))
ASSET_DIR = Path(__file__).resolve().parent / "assets"
FONT_ASSETS = {
    "/assets/geist.woff2": ASSET_DIR / "geist-latin-wght-normal.woff2",
    "/assets/geist-mono.woff2": ASSET_DIR / "geist-mono-latin-wght-normal.woff2",
}
MONITOR_TOKEN_ENV = "MONITOR_TOKEN"
_panel_tail_setting = os.environ.get("PANEL_INCLUDE_TAIL")
if _panel_tail_setting is None:
    PANEL_INCLUDE_TAIL = os.environ.get("MONITOR_HOST", "127.0.0.1").strip().lower() in {
        "127.0.0.1",
        "::1",
        "localhost",
    }
else:
    PANEL_INCLUDE_TAIL = _panel_tail_setting.strip().lower() in ("1", "true", "yes")


def _configured_process_roots(
    current_root: Path = ROOT,
    environ=None,
) -> tuple[Path, ...]:
    """Return exact project roots allowed for cross-release process discovery."""
    env = os.environ if environ is None else environ
    roots = [Path(current_root).resolve()]
    raw = str(env.get("GROK_COMPAT_PROCESS_ROOTS", "") or "").strip()
    for item in raw.split(os.pathsep):
        value = item.strip()
        if not value:
            continue
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_dir() and resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


MANAGED_PROCESS_ROOTS = _configured_process_roots()


def _find_managed_processes(script_names) -> list[dict]:
    found = {}
    for root in MANAGED_PROCESS_ROOTS:
        for item in find_managed_processes(root, script_names):
            found[int(item["pid"])] = item
    return sorted(found.values(), key=lambda item: int(item["pid"]))


def _terminate_managed_processes(
    script_names,
    *,
    grace_seconds: float = 2.0,
) -> list[int]:
    killed = set()
    for root in MANAGED_PROCESS_ROOTS:
        killed.update(
            terminate_managed_processes(root, script_names, grace_seconds=grace_seconds)
        )
    return sorted(killed)

BASE_FILE = LOG_DIR / "batch1000.base"
ORCH_PID = LOG_DIR / "orch100.pid"
BATCH_PID = LOG_DIR / "batch100.pid"
CONTROL_FILE = LOG_DIR / "monitor_control.json"
STATS_CACHE = LOG_DIR / "monitor_stats.json"
BIND_HOST = os.environ.get("MONITOR_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("MONITOR_PORT", "8787"))
VENV_PY = runtime_python(ROOT)
ORCH_SCRIPT = ROOT / "run_until_100.py"
CONTROL_LOCK = threading.RLock()
START_LOCK = threading.Lock()
MAX_REQUEST_BODY = 256 * 1024

RE_OK = re.compile(r"\[\+\] 注册成功")
RE_FAIL = re.compile(r"\[-\] 失败")
RE_DOMAIN = re.compile(r"\[-\] 域名拒绝")
RE_SKIP = re.compile(r"\[-\] 卡住跳过")
RE_BOT0 = re.compile(r"botFlagSource=0")
RE_BOT1 = re.compile(r"botFlagSource=1")
RE_EMAIL_OK = re.compile(r"\[\+\] 注册成功(?:（[^）]*）)?:\s*(\S+)")
RE_RESULT = re.compile(r"\[结果\] status=(\S+)\s+ip=(\S*)\s+port=(\S*)")
RE_FAIL_KIND = re.compile(r"\[-\] 失败 \[([^\]]+)\]:\s*(.*)")
RE_WORKER = re.compile(r"\[W(\d+)\]")
RE_BATCH = re.compile(r"\[batch\] count=(\d+) workers=(\d+)")
RE_START = re.compile(r"终端模式启动，目标数量:\s*(\d+)\s*\|\s*并发:\s*(\d+)")
RE_END = re.compile(r"任务结束。成功\s*(\d+)\s*\|\s*失败\s*(\d+)")
RE_ADDED_BL = re.compile(r"ADDED blacklist AS(\d+)")
RE_LOOKUP_FAIL = re.compile(r"lookup fail", re.I)
RE_ANALYZE_ERR = re.compile(r"analyze error", re.I)
RE_BFS = re.compile(r"JWT bfs 标记|bfs=yes|kind=bfs_flagged|has_bfs")


def _read_json(path: Path, default=None):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        pass
    return default if default is not None else {}


def _write_json(path: Path, data: dict):
    atomic_write_json(path, data)


def load_control() -> dict:
    with CONTROL_LOCK:
        c = _read_json(CONTROL_FILE, {})
        c.setdefault("workers", 3)
        c.setdefault("risk_pause", 10)
        c.setdefault("batch_count", 40)
        c.setdefault("add_count", 40)  # 再跑 N 个
        c.setdefault("accounts_per_ip", 2)  # 0=不限每 IP 账号数
        c.setdefault("ip_failure_rotate_threshold", 3)
        c.setdefault("ip_usage_limit", 0)  # 0=不限单 IP 累计使用次数
        c.setdefault("mode", "orch")  # orch | batch
        return c


def save_control(updates: dict) -> dict:
    allowed = {
        "workers",
        "risk_pause",
        "batch_count",
        "add_count",
        "accounts_per_ip",
        "ip_failure_rotate_threshold",
        "ip_usage_limit",
        "mode",
        "base_cpa",
        "target_cpa",
        # 任务启动时的累计成功数基线（本次任务增量 = ok_count - base_ok）
        "base_ok",
    }
    with CONTROL_LOCK:
        c = load_control()
        c.update({key: value for key, value in (updates or {}).items() if key in allowed})
        try:
            c["workers"] = max(1, min(24, int(c.get("workers", 3))))
        except Exception:
            c["workers"] = 3
        try:
            c["risk_pause"] = max(1, min(50, int(c.get("risk_pause", 10))))
        except Exception:
            c["risk_pause"] = 10
        try:
            c["batch_count"] = max(1, int(c.get("batch_count", 40)))
        except Exception:
            c["batch_count"] = 40
        try:
            c["add_count"] = max(1, int(c.get("add_count", 40)))
        except Exception:
            c["add_count"] = 40
        try:
            c["accounts_per_ip"] = max(
                0, min(20, int(c.get("accounts_per_ip", 2)))
            )
        except Exception:
            c["accounts_per_ip"] = 2
        try:
            c["ip_failure_rotate_threshold"] = max(
                1, min(20, int(c.get("ip_failure_rotate_threshold", 3)))
            )
        except Exception:
            c["ip_failure_rotate_threshold"] = 3
        try:
            c["ip_usage_limit"] = max(
                0, min(100000, int(c.get("ip_usage_limit", 0) or 0))
            )
        except Exception:
            c["ip_usage_limit"] = 0
        c["mode"] = c.get("mode") if c.get("mode") in ("orch", "batch") else "orch"
        for key in ("base_cpa", "target_cpa"):
            if c.get(key) is None or str(c.get(key)).strip() == "":
                c.pop(key, None)
                continue
            try:
                c[key] = max(0, int(c[key]))
            except Exception:
                c.pop(key, None)
        c["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _write_json(CONTROL_FILE, c)
        return c


def discover_log():
    env = os.environ.get("BATCH_LOG")
    if env and Path(env).is_file():
        return Path(env)
    cands = sorted(LOG_DIR.glob("batch*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    cands = [p for p in cands if "sticky" not in p.name and "rotate" not in p.name]
    return cands[0] if cands else None


def cleanup_old_logs(retention_days: object = 7) -> dict:
    """Clean generated log files while retaining the newest dashboard inputs."""
    protected = []
    current = discover_log()
    if current:
        protected.append(current)
    for pattern in ("orch*.log",):
        candidates = sorted(
            LOG_DIR.glob(pattern),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            protected.append(candidates[0])
    return cleanup_expired_logs(
        LOG_DIR,
        retention_days,
        protected=protected,
    )


def read_base():
    """Prefer control.base_cpa; fall back to batch1000.base file if present."""
    try:
        c = load_control()
        if c.get("base_cpa") is not None and str(c.get("base_cpa")).strip() != "":
            return int(c["base_cpa"])
    except Exception:
        pass
    try:
        return int(BASE_FILE.read_text().strip())
    except Exception:
        return 0


def process_running():
    """Detect orch and/or batch workers."""
    info = {
        "running": False,
        "pid": None,
        "etime": None,
        "cmd": None,
        "orch_running": False,
        "orch_pid": None,
        "orch_etime": None,
        "batch_running": False,
        "batch_pid": None,
        "batch_etime": None,
    }
    orch = _find_managed_processes(("run_until_100.py",))
    batch = _find_managed_processes(("run_batch_headless.py",))

    def primary(items):
        if not items:
            return None
        return next((item for item in items if item.get("pgid") == item.get("pid")), items[0])

    orch_item = primary(orch)
    batch_item = primary(batch)
    if orch_item:
        info["orch_running"] = True
        info["orch_pid"] = orch_item["pid"]
        info["orch_etime"] = orch_item.get("etime")
        info["running"] = True
        info["pid"] = orch_item["pid"]
        info["etime"] = orch_item.get("etime")
        info["cmd"] = orch_item.get("cmd")
    if batch_item:
        info["batch_running"] = True
        info["batch_pid"] = batch_item["pid"]
        info["batch_etime"] = batch_item.get("etime")
        if not info["running"]:
            info["running"] = True
            info["pid"] = batch_item["pid"]
            info["etime"] = batch_item.get("etime")
            info["cmd"] = batch_item.get("cmd")
    return info


def parse_log(path, max_tail=400_000):
    if not path or not path.is_file():
        return {"error": "no log"}
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_tail:
            f.seek(size - max_tail)
            f.readline()
        text = f.read().decode("utf-8", errors="replace")

    lines = text.splitlines()
    ok = fail = domain = skip = bot0 = bot1 = 0
    count = workers = None
    ended = None
    recent_ok = []
    recent_fail = []
    fail_kinds = {}
    worker_ok = {}
    worker_fail = {}
    pending_result = {}

    for line in lines:
        m = RE_BATCH.search(line) or RE_START.search(line)
        if m:
            count, workers = int(m.group(1)), int(m.group(2))
        m = RE_END.search(line)
        if m:
            ended = {"success": int(m.group(1)), "fail": int(m.group(2))}

        if RE_OK.search(line):
            ok += 1
            em = RE_EMAIL_OK.search(line)
            email = em.group(1) if em else ""
            wm = RE_WORKER.search(line)
            w = f"W{wm.group(1)}" if wm else "?"
            worker_ok[w] = worker_ok.get(w, 0) + 1
            ts = line[1:9] if line.startswith("[") else ""
            recent_ok.append({"t": ts, "w": w, "email": mask_email(email), "ip": "", "port": ""})
            # [结果] 行紧随其后，按 worker 挂靠 IP/端口
            pending_result[w] = len(recent_ok) - 1
        rm = RE_RESULT.search(line)
        if rm:
            wm = RE_WORKER.search(line)
            w = f"W{wm.group(1)}" if wm else "?"
            idx = pending_result.get(w)
            if idx is not None and rm.group(1) == "ok":
                recent_ok[idx]["ip"] = rm.group(2)
                recent_ok[idx]["port"] = rm.group(3)
                pending_result.pop(w, None)
        if RE_FAIL.search(line):
            fail += 1
            fm = RE_FAIL_KIND.search(line)
            kind = fm.group(1) if fm else "其它"
            msg = fm.group(2) if fm else line[-120:]
            if "inputs=none" in msg:
                kind = "空页UI"
            if "Turnstile" in msg or "Turnstile" in kind:
                kind = "资料页Turnstile" if "Turnstile" in msg else kind
            fail_kinds[kind] = fail_kinds.get(kind, 0) + 1
            wm = RE_WORKER.search(line)
            w = f"W{wm.group(1)}" if wm else "?"
            worker_fail[w] = worker_fail.get(w, 0) + 1
            ts = line[1:9] if line.startswith("[") else ""
            recent_fail.append({"t": ts, "w": w, "kind": kind, "msg": redact_log_line(msg[:160])})
        if RE_DOMAIN.search(line):
            domain += 1
        if RE_SKIP.search(line):
            skip += 1
        if RE_BOT0.search(line):
            bot0 += 1
        if RE_BOT1.search(line):
            bot1 += 1

    last_lines = lines[-40:]
    if size > max_tail:
        def gcount(pat):
            r = subprocess.run(["grep", "-c", pat, str(path)], capture_output=True, text=True)
            try:
                return int(r.stdout.strip() or 0)
            except Exception:
                return 0

        ok = gcount("注册成功")
        fail = gcount(r"\[-\] 失败")
        bot0 = gcount("botFlagSource=0")
        bot1 = gcount("botFlagSource=1")

    return {
        "log": path.name,
        "log_name": path.name,
        "log_size": size,
        "mtime": path.stat().st_mtime,
        "count_target": count,
        "workers": workers,
        "ok": ok,
        "fail": fail,
        "domain": domain,
        "skip": skip,
        "bot0": bot0,
        "bot1": bot1,
        "ended": ended,
        "fail_kinds": fail_kinds,
        "worker_ok": worker_ok,
        "worker_fail": worker_fail,
        "recent_ok": recent_ok[-500:][::-1],
        "recent_fail": recent_fail[-25:][::-1],
        "tail": [redact_log_line(line) for line in last_lines],
    }


def cpa_count():
    try:
        return sum(1 for p in CPA_DIR.iterdir() if p.is_file() and p.name.startswith("xai-"))
    except Exception:
        try:
            return sum(1 for _ in CPA_DIR.iterdir() if _.is_file())
        except Exception:
            return 0


def read_blacklist():
    return read_blacklist_state()


def blacklist_update_errors():
    """Count blacklist expansion / ASN lookup errors from orch logs."""
    added = []
    lookup_fails = 0
    analyze_errors = 0
    hit_pause = 0
    try:
        logs = sorted(LOG_DIR.glob("orch100*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:8]
        logs += sorted(LOG_DIR.glob("orch100-stdout.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:1]
        seen = set()
        for path in logs:
            if str(path) in seen or not path.is_file():
                continue
            seen.add(str(path))
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for line in text.splitlines():
                m = RE_ADDED_BL.search(line)
                if m:
                    added.append({"asn": int(m.group(1)), "line": line[-120:], "log": path.name})
                if RE_LOOKUP_FAIL.search(line):
                    lookup_fails += 1
                if RE_ANALYZE_ERR.search(line):
                    analyze_errors += 1
                if "pause+blacklist" in line or "HIT" in line and "注册风控" in line:
                    hit_pause += 1
    except Exception:
        pass
    # unique recent added (last 30)
    uniq = []
    seen_a = set()
    for a in reversed(added):
        if a["asn"] in seen_a:
            continue
        seen_a.add(a["asn"])
        uniq.append(a)
        if len(uniq) >= 30:
            break
    uniq.reverse()
    return {
        "lookup_fail_count": lookup_fails,
        "analyze_error_count": analyze_errors,
        "error_count": lookup_fails + analyze_errors,
        "hit_pause_count": hit_pause,
        "recent_added": uniq[-15:],
        "added_total": len(added),
    }


def success_stats():
    """Aggregate success stats: CPA + jsonl + time-window rates + latest batch."""
    from datetime import datetime, timezone, timedelta

    cpa = cpa_count()
    configured_base = read_base()
    base_stale = configured_base < 0 or configured_base > cpa
    base = cpa if base_stale else configured_base
    jsonl_ok = 0
    jsonl_risk = 0
    jsonl_fail = 0
    bfs_hits = 0
    by_day = {}
    results = LOG_DIR / "register_results.jsonl"

    # windows in hours -> counters
    windows_h = (1, 3, 12)
    now = datetime.now(timezone.utc)
    win = {
        h: {"ok": 0, "fail": 0, "risk": 0, "total": 0, "since": (now - timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        for h in windows_h
    }

    def _parse_ts(ts: str):
        if not ts:
            return None
        s = str(ts).strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    try:
        if results.exists():
            size = results.stat().st_size
            # last 8MB covers 12h under high volume
            with results.open("rb") as f:
                if size > 8_000_000:
                    f.seek(size - 8_000_000)
                    f.readline()
                for line in f:
                    try:
                        o = json.loads(line.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
                    st = o.get("status")
                    if o.get("bfs") is True:
                        bfs_hits += 1
                    day = (o.get("ts") or "")[:10]
                    if day:
                        by_day.setdefault(day, {"ok": 0, "risk": 0, "fail": 0})
                    if st == "ok":
                        if day:
                            by_day[day]["ok"] += 1
                    elif st == "risk":
                        if day:
                            by_day[day]["risk"] += 1
                    elif st:
                        if day:
                            by_day[day]["fail"] += 1

                    dt = _parse_ts(o.get("ts") or "")
                    if not dt:
                        continue
                    age = now - dt
                    for h in windows_h:
                        if age <= timedelta(hours=h):
                            bucket = win[h]
                            if st == "ok":
                                bucket["ok"] += 1
                            elif st == "risk":
                                bucket["risk"] += 1
                            elif st:
                                bucket["fail"] += 1
                            if st in ("ok", "risk", "fail", "sso_timeout", "browser", "other"):
                                bucket["total"] += 1
                            elif st:
                                bucket["total"] += 1
    except Exception:
        pass

    # 全量计数（含归档摘要，轮转不丢数）
    try:
        totals = count_results()
        jsonl_ok = totals.get("ok", 0)
        jsonl_risk = totals.get("risk", 0)
        jsonl_fail = totals.get("fail", 0)
    except Exception:
        jsonl_ok = jsonl_ok or 0
        jsonl_risk = jsonl_risk or 0
        jsonl_fail = jsonl_fail or 0

    # normalize window rates
    rates = {}
    for h, b in win.items():
        # total attempts that finished with a status
        total = int(b["ok"]) + int(b["fail"]) + int(b["risk"])
        ok = int(b["ok"])
        rate = round(100.0 * ok / total, 1) if total else None
        rates[f"{h}h"] = {
            "hours": h,
            "ok": ok,
            "fail": int(b["fail"]),
            "risk": int(b["risk"]),
            "total": total,
            "success_rate": rate,
            "since": b["since"],
        }

    log = discover_log()
    parsed = parse_log(log) if log else {}
    batch_ok = parsed.get("ok") or 0
    batch_fail = parsed.get("fail") or 0
    data = {
        "cpa": cpa,
        "base_cpa": base,
        "base_cpa_stale": base_stale,
        "cpa_delta": cpa - base,
        "jsonl_ok": jsonl_ok,
        "jsonl_risk": jsonl_risk,
        "jsonl_fail": jsonl_fail,
        "bfs": bfs_hits,
        "batch_ok": batch_ok,
        "batch_fail": batch_fail,
        "batch_log": parsed.get("log_name"),
        "by_day": by_day,
        "rates": rates,
        "refreshed_at": beijing_strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        _write_json(STATS_CACHE, data)
    except Exception:
        pass
    return data




def _parse_etime(s):
    if not s:
        return None
    s = s.strip()
    try:
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        parts = [int(x) for x in s.split(":")]
        if len(parts) == 3:
            h, m, sec = parts
        elif len(parts) == 2:
            h = 0
            m, sec = parts
        else:
            return None
        return days * 86400 + h * 3600 + m * 60 + sec
    except Exception:
        return None


def kill_all():
    """Stop orchestrator and batch process groups under this project root."""
    killed = _terminate_managed_processes(
        ("run_until_100.py", "run_batch_headless.py"),
        grace_seconds=8.0,
    )
    remaining = process_running()
    return {
        "ok": not remaining.get("running"),
        "killed": killed,
        "remaining": remaining,
        "error": (
            "任务进程仍未退出，请重试停止或检查进程权限"
            if remaining.get("running")
            else ""
        ),
    }


def _runtime_prerequisite_error() -> str | None:
    if not VENV_PY.is_file():
        return f"missing runtime python: {VENV_PY}"
    if not (ROOT / "config.json").is_file():
        return f"missing config: {ROOT / 'config.json'}"
    launch_error = batch_runtime_error()
    if launch_error:
        return launch_error
    return None


def _runtime_config() -> dict:
    try:
        return json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def _proxy_prerequisite_error(workers: int) -> str | None:
    if bool(_runtime_config().get("proxy_fallback_to_local", False)):
        # 面板池无健康代理时允许回退本地网络（config.proxy / 直连）
        return None
    try:
        pool = read_proxy_pool(page=1, page_size=10)
    except Exception as exc:
        return f"无法读取代理池: {redact_log_line(str(exc))}"
    summary = pool.get("summary") or {}
    total = int(summary.get("total") or 0)
    usable = int(summary.get("usable") or 0)
    usable_templates = int(summary.get("usable_templates") or 0)
    if total and usable <= 0:
        return "代理池已配置，但没有健康且启用的代理；请先完成代理检测"
    if total and usable < max(1, int(workers)) and usable_templates <= 0:
        return f"健康代理仅 {usable} 条，少于并发数 {workers}；请降低并发或继续检测"
    return None


def _email_domain_pool_view(result: dict | None = None) -> dict:
    data = result if isinstance(result, dict) else read_email_domain_pool()
    try:
        runtime_config = json.loads(
            (ROOT / "config.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        runtime_config = {}
    active_provider = str(
        runtime_config.get("email_provider") or "cloudflare"
    ).strip().lower()
    labels = data.get("provider_labels") or {}
    data["active_provider"] = active_provider
    data["active_provider_label"] = labels.get(active_provider, active_provider)
    return data


def _registration_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("GROK_STATIC_ASSET_CACHE", "1")
    env.setdefault(
        "GROK_STATIC_CACHE_DIR",
        str(LOG_DIR / "static-asset-cache"),
    )
    return env


def _start_orch_unlocked():
    proc = process_running()
    if proc.get("orch_running") or proc.get("batch_running"):
        return {"ok": False, "error": "already running", "process": proc}
    if _find_managed_processes(("sso_to_auth_json.py",)):
        return {"ok": False, "error": "account recovery is running"}
    prerequisite_error = _runtime_prerequisite_error()
    if prerequisite_error:
        return {"ok": False, "error": prerequisite_error}
    c = load_control()
    proxy_error = _proxy_prerequisite_error(int(c.get("workers") or 3))
    if proxy_error:
        return {"ok": False, "error": proxy_error}
    now = cpa_count()
    add_count = c.get("add_count")
    try:
        add_count = int(add_count) if add_count is not None else 0
    except Exception:
        add_count = 0
    target = c.get("target_cpa")
    try:
        target = int(target) if target is not None else None
    except Exception:
        target = None
    if add_count > 0:
        c["base_cpa"] = now
        c["target_cpa"] = now + add_count
        c["base_ok"] = ok_count()
    elif target is None or target <= now:
        n = int(c.get("batch_count") or 40)
        c["add_count"] = n
        c["base_cpa"] = now
        c["target_cpa"] = now + n
        c["base_ok"] = ok_count()
        add_count = n
    c = save_control(c)
    need = int(c.get("target_cpa") or 0) - now
    ensure_private_dir(LOG_DIR)
    stdout_path = LOG_DIR / "orch100-stdout.log"
    fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        best_effort_fchmod(fd, 0o600)
    except OSError:
        pass
    stdout = os.fdopen(fd, "a", encoding="utf-8")
    stdout.write(
        f"\n--- monitor start {time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
        f"workers={c.get('workers')} cpa={now} target={c.get('target_cpa')} need={need} ---\n"
    )
    stdout.flush()
    try:
        p = subprocess.Popen(
            [str(VENV_PY), "-u", str(ORCH_SCRIPT)],
            cwd=str(ROOT),
            stdout=stdout,
            stderr=subprocess.STDOUT,
            env=_registration_env(),
            **popen_group_kwargs(),
        )
    finally:
        stdout.close()
    write_pid_file(ORCH_PID, p.pid)
    return {
        "ok": True,
        "pid": p.pid,
        "mode": "orch",
        "workers": c.get("workers"),
        "cpa_now": now,
        "target_cpa": c.get("target_cpa"),
        "need": need,
        "add_count": add_count or c.get("add_count"),
        "control": c,
        "message": f"已启动 orch pid={p.pid} 目标 CPA {c.get('target_cpa')} (再跑 {need})",
    }


def start_orch():
    with START_LOCK:
        return _start_orch_unlocked()


def _start_batch_only_unlocked():
    proc = process_running()
    if proc.get("batch_running") or proc.get("orch_running"):
        return {"ok": False, "error": "already running", "process": proc}
    if _find_managed_processes(("sso_to_auth_json.py",)):
        return {"ok": False, "error": "account recovery is running"}
    prerequisite_error = _runtime_prerequisite_error()
    if prerequisite_error:
        return {"ok": False, "error": prerequisite_error}
    c = load_control()
    workers = int(c.get("workers") or 3)
    count = int(c.get("batch_count") or 40)
    proxy_error = _proxy_prerequisite_error(workers)
    if proxy_error:
        return {"ok": False, "error": proxy_error}
    now = cpa_count()
    c["base_cpa"] = now
    c["target_cpa"] = now + count
    c["base_ok"] = ok_count()
    c = save_control(c)
    logname = LOG_DIR / f"batch-orch-{time.strftime('%Y%m%d-%H%M%S')}-n{count}.log"
    ensure_private_dir(LOG_DIR)
    fd = os.open(logname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        best_effort_fchmod(fd, 0o600)
    except OSError:
        pass
    fout = os.fdopen(fd, "w", encoding="utf-8")
    try:
        p = subprocess.Popen(
            batch_launch_command(
                ROOT,
                count,
                workers,
                python_path=VENV_PY,
            ),
            cwd=str(ROOT),
            stdout=fout,
            stderr=subprocess.STDOUT,
            env=_registration_env(),
            **popen_group_kwargs(),
        )
    finally:
        fout.close()
    write_pid_file(BATCH_PID, p.pid)
    return {
        "ok": True,
        "pid": p.pid,
        "mode": "batch",
        "workers": workers,
        "count": count,
        "log": logname.name,
    }


def start_batch_only():
    with START_LOCK:
        return _start_batch_only_unlocked()


def snapshot():
    log = discover_log()
    parsed = parse_log(log) if log else {"error": "no log"}
    cpa = cpa_count()
    configured_base = read_base()
    base_stale = configured_base < 0 or configured_base > cpa
    base = cpa if base_stale else configured_base
    proc = process_running()
    control = load_control()
    bl = read_blacklist()
    bl_err = blacklist_update_errors()
    try:
        rates = success_stats().get("rates") or {}
    except Exception:
        rates = {}
    target = parsed.get("count_target") or control.get("batch_count") or 40
    ok = parsed.get("ok") or 0
    fail = parsed.get("fail") or 0
    done = ok + fail
    pct = round(100.0 * ok / target, 2) if target else 0
    # 任务级进度（单次任务）：每次点击启动 = 一次任务。
    # 总数 = 本次任务目标数（target_cpa - base_cpa，即本次 add_count）；
    # 已完成 = 本次任务新增成功数（ok_count - base_ok，base_ok 为启动时基线）。
    task_total = 0
    task_done = 0
    try:
        base_c = int(control.get("base_cpa") or 0)
        target_c = int(control.get("target_cpa") or 0)
        if target_c > base_c:
            task_total = target_c - base_c
            if control.get("base_ok") is not None:
                base_ok = int(control.get("base_ok") or 0)
                task_done = max(0, min(task_total, ok_count() - base_ok))
            else:
                # 旧任务无 base_ok 时回退 CPA 口径（本次 CPA 增量）
                task_done = max(0, min(task_total, cpa - base_c))
    except (TypeError, ValueError):
        pass
    eta = None
    rate_per_min = None
    etime = proc.get("etime") or proc.get("batch_etime") or ""
    secs = _parse_etime(etime)
    if secs and ok > 0:
        rate_per_min = round(ok / (secs / 60.0), 2)
        remain = max(target - ok, 0)
        if rate_per_min > 0:
            eta_min = remain / rate_per_min
            eta = f"{int(eta_min)}m" if eta_min < 120 else f"{eta_min/60:.1f}h"
    workers_show = parsed.get("workers") or control.get("workers")
    traffic = read_batch_traffic(BATCH_TRAFFIC)
    if traffic.get("running") and not proc.get("running"):
        traffic["running"] = False
    if int(traffic.get("version") or 0) < 2:
        traffic["successful_accounts"] = max(
            int(traffic.get("successful_accounts") or 0),
            int(parsed.get("ok") or 0),
        )
    traffic_summary = read_batch_traffic_summary(BATCH_TRAFFIC_HISTORY, traffic)
    return {
        "ts": time.time(),
        "ts_human": beijing_strftime("%Y-%m-%d %H:%M:%S"),
        "base_cpa": base,
        "base_cpa_stale": base_stale,
        "cpa": cpa,
        "cpa_delta": cpa - base,
        "process": proc,
        "control": control,
        "target": target,
        "done_attempts": done,
        "progress_pct": pct,
        "task_total": task_total,
        "task_done": task_done,
        "success_rate": round(100.0 * ok / done, 1) if done else None,
        "rate_per_min": rate_per_min,
        "eta": eta,
        "traffic": traffic,
        "traffic_summary": traffic_summary,
        "blacklist": {
            "count": bl.get("count"),
            "asns": bl.get("asns"),
            "items": bl.get("items"),
            "isp_keywords": bl.get("isp_keywords"),
            "mtime_human": bl.get("mtime_human"),
            "ok": bl.get("ok"),
            "error": bl.get("error"),
            "errors": bl.get("errors"),
        },
        "blacklist_update": bl_err,
        "rates": rates,
        **{k: v for k, v in parsed.items() if k != "tail"},
        "workers": workers_show,
        "tail": (parsed.get("tail") or []) if PANEL_INCLUDE_TAIL else ["(raw log tail disabled; set PANEL_INCLUDE_TAIL=1)"],
    }


HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="theme-color" content="#f3f4f1" id="theme-color"/>
<title>GrokRegister</title>
<script>
  (function () {
    const key = "GROK_REGISTER_THEME";
    let theme = "";
    try { theme = localStorage.getItem(key) || ""; } catch (e) {}
    if (theme !== "light" && theme !== "dark") {
      theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.dataset.theme = theme;
    document.getElementById("theme-color").content = theme === "dark" ? "#171815" : "#f3f4f1";
  })();
</script>
<style>
  @font-face {
    font-family: "Geist";
    src: url("/assets/geist.woff2") format("woff2");
    font-style: normal;
    font-weight: 100 900;
    font-display: swap;
  }
  @font-face {
    font-family: "Geist Mono";
    src: url("/assets/geist-mono.woff2") format("woff2");
    font-style: normal;
    font-weight: 100 900;
    font-display: swap;
  }
  :root {
    color-scheme: light;
    --bg: #f3f4f1;
    --surface: #e9eae6;
    --surface-raised: #f8f9f6;
    --surface-soft: #eff0ec;
    --surface-deep: #d9dad5;
    --border: rgba(21, 22, 19, .16);
    --border-strong: rgba(21, 22, 19, .46);
    --text: #151613;
    --text-secondary: #383a35;
    --muted: #696b64;
    --placeholder: #85877f;
    --ok: #237a57;
    --fail: #b83f3f;
    --warn: #8a6400;
    --accent: #b93b28;
    --accent-hover: #9f2f1f;
    --accent-ink: #f8f9f6;
    --focus: #b93b28;
    --button: #f8f9f6;
    --button-hover: #e1e2dd;
    --hover-border: rgba(21, 22, 19, .46);
    --focus-shadow: rgba(185, 59, 40, .16);
    --primary-bg: #151613;
    --primary-text: #f8f9f6;
    --primary-hover: #2e302b;
    --danger-border: rgba(184, 63, 63, .45);
    --danger-hover-bg: rgba(184, 63, 63, .08);
    --danger-hover-border: rgba(184, 63, 63, .72);
    --header: rgba(243, 244, 241, .88);
    --progress-track: #d9dad5;
    --row-hover: rgba(21, 22, 19, .035);
    --tail-bg: #151613;
    --tail-text: #d3d5ce;
    --grid-line: rgba(21, 22, 19, .055);
  }
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
  html {
    background: var(--bg);
    transition: background-color 180ms ease, color 180ms ease;
  }
  body {
    margin: 0;
    min-height: 100dvh;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
    background-attachment: fixed;
    color: var(--text);
    font-family: "Geist", "Noto Sans CJK SC", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.45;
    letter-spacing: 0;
    transition: background-color 180ms ease, color 180ms ease;
  }
  ::selection { background: var(--accent); color: var(--accent-ink); }
  header {
    position: sticky;
    top: 0;
    z-index: 10;
    border-bottom: 1px solid var(--border);
    background: var(--header);
    backdrop-filter: blur(18px) saturate(118%);
    -webkit-backdrop-filter: blur(18px) saturate(118%);
    transition: background-color 180ms ease, border-color 180ms ease;
  }
  .topbar {
    width: min(calc(100% - 64px), 1480px);
    height: 68px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
  }
  .brand { min-width: 0; }
  h1 {
    margin: 0;
    color: var(--text);
    font-size: 17px;
    line-height: 1.2;
    font-weight: 800;
  }
  h1::after {
    content: "";
    width: 5px;
    height: 5px;
    display: inline-block;
    margin-left: 5px;
    background: var(--accent);
    transition: background-color 180ms ease;
  }
  .page-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 20px;
    margin: 2px 0 14px;
  }
  .page-heading > div { min-width: 0; }
  .page-title { margin: 0; color: var(--text); font-size: 28px; line-height: 1.18; font-weight: 680; }
  .brand-subtitle {
    margin-top: 7px;
    color: var(--muted);
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .status-cluster {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    flex-wrap: nowrap;
  }
  .badge {
    min-height: 28px;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: transparent;
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 560;
    white-space: nowrap;
  }
  .dot { width: 7px; height: 7px; flex: 0 0 auto; border-radius: 50%; background: var(--muted); }
  .dot.on { background: var(--ok); }
  .dot.done { background: var(--ok); }
  .dot.off { background: var(--muted); }
  main { width: min(calc(100% - 64px), 1280px); margin: 0 auto; padding: 28px 0 48px; }
  .panel-gap { margin-top: 14px; }
  .card {
    min-width: 0;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    border-radius: 0;
    padding: 14px;
    transition: background-color 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms cubic-bezier(.16, 1, .3, 1);
  }
  @media (hover: hover) {
    .card:hover { border-color: var(--border-strong); transform: translateY(-2px); }
    .chip:hover { border-color: var(--border-strong); background: var(--surface-raised); }
    .rate-item:hover,
    .proxy-summary-item:hover,
    .domain-summary-item:hover { background: var(--surface-raised); }
    .proxy-state:hover,
    .domain-state:hover { background: var(--surface-soft); }
    .domain-advanced > summary:hover .domain-advanced-title,
    .faq-item summary:hover { color: var(--text-secondary); }
    .card > summary.panel-summary:hover { background: var(--surface-soft); }
    .faq-item[open] summary:hover { color: var(--accent); }
  }
  .proxy-select:focus-visible,
  .proxy-toggle:focus-visible,
  .domain-toggle:focus-visible,
  .domain-advanced > summary:focus-visible,
  .card > summary.panel-summary:focus-visible,
  .faq-item summary:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: 2px;
  }
  .panel { margin-top: 14px; }
  .panel.no-margin { margin-top: 0; }
  .panel h2, .card h2 {
    margin: 0;
    color: var(--text);
    font-size: 13px;
    font-weight: 620;
  }
  .ok { color: var(--ok); } .fail { color: var(--fail); } .warn { color: var(--warn); } .accent { color: var(--accent); }
  .section-head {
    min-height: 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 14px;
  }
  .section-meta { color: var(--muted); font-size: 12px; text-align: right; }
  .card > summary.panel-summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    min-height: 24px;
    cursor: pointer;
    list-style: none;
  }
  .card > summary.panel-summary::-webkit-details-marker { display: none; }
  .card > summary.panel-summary::after {
    content: "+";
    flex: 0 0 auto;
    color: var(--accent);
    font-family: "Geist Mono", monospace;
    font-size: 18px;
    line-height: 1;
  }
  .card[open] > summary.panel-summary::after { content: "-"; }
  .card[open] > summary.panel-summary { margin-bottom: 12px; }
  .control-grid {
    display: grid;
    grid-template-columns: minmax(220px, 1.6fr) minmax(150px, .9fr) repeat(4, minmax(100px, .55fr)) minmax(258px, auto);
    gap: 12px;
    align-items: end;
  }
  .control-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .control-panel { padding: 12px 16px; }
  .control-panel .section-head { min-height: 24px; margin-bottom: 8px; }
  .control-panel .msg:empty { display: none; }
  .ip-policy {
    grid-column: 1 / -1;
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
    align-items: end;
    padding: 12px;
    border: 1px solid var(--border);
    background: color-mix(in srgb, var(--surface) 92%, var(--accent) 8%);
  }
  .policy-switch {
    min-height: 38px;
    display: flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
  }
  .policy-switch input { position: absolute; opacity: 0; pointer-events: none; }
  .policy-track {
    width: 38px;
    height: 20px;
    flex: 0 0 auto;
    border: 1px solid var(--border-strong);
    background: var(--surface-deep);
    position: relative;
    transition: background .16s ease, border-color .16s ease;
  }
  .policy-track::after {
    content: "";
    width: 12px;
    height: 12px;
    position: absolute;
    top: 3px;
    left: 3px;
    background: var(--muted);
    transition: transform .16s ease, background .16s ease;
  }
  .policy-switch input:checked + .policy-track { background: var(--accent); border-color: var(--accent); }
  .policy-switch input:checked + .policy-track::after { transform: translateX(18px); background: var(--accent-ink); }
  .policy-switch input:focus-visible + .policy-track { outline: 2px solid var(--accent); outline-offset: 2px; }
  .policy-copy { display: flex; flex-direction: column; gap: 2px; }
  .policy-title { color: var(--text); font-size: 12px; font-weight: 720; }
  .policy-note { color: var(--muted); font-size: 10.5px; line-height: 1.45; }
  .ip-policy .field[data-inactive="true"] { opacity: .42; }
  .field { min-width: 0; display: flex; flex-direction: column; gap: 6px; }
  .field label { color: var(--muted); font-size: 12px; font-weight: 560; }
  input, select, textarea, button { font: inherit; letter-spacing: 0; }
  input, select, textarea {
    width: 100%;
    min-height: 38px;
    border: 1px solid var(--border-strong);
    border-radius: 2px;
    background: var(--surface-soft);
    color: var(--text);
    padding: 8px 10px;
    outline: none;
  }
  textarea { resize: vertical; }
  input::placeholder, textarea::placeholder { color: var(--placeholder); opacity: 1; }
  input:hover, select:hover, textarea:hover { border-color: var(--hover-border); }
  input:focus, select:focus, textarea:focus { border-color: var(--focus); box-shadow: 0 0 0 3px var(--focus-shadow); }
  button {
    min-height: 38px;
    border: 1px solid var(--border-strong);
    border-radius: 2px;
    background: var(--button);
    color: var(--text);
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms cubic-bezier(.16, 1, .3, 1);
    white-space: nowrap;
  }
  button:hover { background: var(--button-hover); border-color: var(--hover-border); }
  button:active { transform: translateY(2px); }
  button:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  button.primary { background: var(--primary-bg); border-color: var(--primary-bg); color: var(--primary-text); }
  button.primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
  button.danger { background: transparent; border-color: var(--danger-border); color: var(--fail); }
  button.danger:hover { background: var(--danger-hover-bg); border-color: var(--danger-hover-border); }
  button:disabled { opacity: .42; cursor: not-allowed; transform: none; }
  button.view-switch {
    min-width: 68px;
    min-height: 30px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 9px;
    border-color: var(--border);
    background: var(--surface-soft);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 620;
    line-height: 1;
  }
  button.view-switch:hover { border-color: var(--hover-border); color: var(--text); }
  button.view-switch[data-active="true"] {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--accent-ink);
  }
  .header-btn {
    min-width: 0;
    min-height: 30px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 0 10px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 620;
    line-height: 1;
    cursor: pointer;
    white-space: nowrap;
    transition: background-color 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms cubic-bezier(.16, 1, .3, 1);
  }
  .header-btn:hover { border-color: var(--hover-border); color: var(--text); }
  .header-btn:active { transform: translateY(1px); }
  .header-btn.primary { background: var(--primary-bg); border-color: var(--primary-bg); color: var(--primary-text); }
  .header-btn.primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
  .status-cluster .msg { margin: 0; min-height: 0; font-size: 11px; white-space: nowrap; }
  .theme-switch {
    flex: 0 0 auto;
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  button.theme-option {
    min-height: 24px;
    padding: 3px 8px;
    border: 0;
    border-radius: 1px;
    background: transparent;
    color: var(--muted);
    font-size: 11px;
    font-weight: 560;
    line-height: 1;
  }
  button.theme-option:hover { border: 0; background: var(--button-hover); color: var(--text); }
  button.theme-option[aria-pressed="true"] { background: var(--accent); color: var(--accent-ink); }
  .metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1px;
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: 0;
    background: var(--border);
  }
  #kpis { margin-top: 10px; }
  .metric {
    min-width: 0;
    padding: 10px 14px;
    background: var(--surface);
    transition: background-color 180ms ease, color 180ms ease;
  }
  .metric:hover { background: var(--surface-raised); }
  .metric .label { color: var(--muted); font-size: 11px; }
  .metric .value {
    margin-top: 4px;
    font-size: 23px;
    line-height: 1.05;
    font-weight: 730;
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  }
  .metric .sub { min-height: 16px; margin-top: 4px; color: var(--muted); font-size: 11px; }
  .rate-panel { padding: 12px 14px 14px; }
  .rate-panel .section-head { min-height: 24px; margin-bottom: 8px; }
  .rate-panel .section-meta { font-size: 11px; }
  .rate-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    border: 1px solid var(--border);
    border-radius: 0;
    overflow: hidden;
  }
  .rate-item { min-width: 0; padding: 10px 12px; background: var(--surface-soft); transition: background-color 180ms ease; }
  .rate-item + .rate-item { border-left: 1px solid var(--border); }
  .rate-top { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
  .rate-label { color: var(--text-secondary); font-size: 12px; }
  .rate-total { color: var(--muted); font-size: 11px; white-space: nowrap; }
  .rate-value { margin-top: 4px; font-size: 23px; line-height: 1; font-weight: 730; font-variant-numeric: tabular-nums; }
  .rate-breakdown { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 6px; color: var(--muted); font-size: 11px; }
  .progress-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 10px; }
  .bar-wrap { height: 8px; overflow: hidden; border-radius: 1px; background: var(--progress-track); }
  .bar { height: 100%; width: 0%; background: var(--accent); transition: width 420ms cubic-bezier(.16, 1, .3, 1), background-color 180ms ease; }
  .progress-sub { margin-top: 9px; color: var(--muted); font-size: 12px; }
  .two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
  .three { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr) minmax(0, .95fr); gap: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 620; font-size: 11px; }
  td { color: var(--text-secondary); }
  tbody tr:last-child td { border-bottom: 0; }
  tr:hover td { background: var(--row-hover); }
  .table-scroll { width: 100%; overflow: auto; }
  .mono { font-family: "Geist Mono", "SFMono-Regular", Consolas, monospace; font-size: 12px; }
  .tail {
    max-height: 360px;
    overflow: auto;
    overscroll-behavior: contain;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--tail-bg);
    padding: 12px;
    color: var(--tail-text);
    font-size: 11.5px;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .log-tools {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    margin: 0 0 10px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .log-retention { width: 132px; }
  .log-retention input { min-height: 32px; }
  .log-tools button { min-height: 32px; padding: 5px 10px; }
  .log-tools button[aria-pressed="true"] { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
  .log-cleanup-msg { min-width: 180px; color: var(--muted); font-size: 11px; text-align: right; }
  .chips { display: flex; flex-wrap: wrap; gap: 7px; }
  .card > h2 + .chips { margin-top: 14px; }
  .chip {
    min-width: 84px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
    padding: 8px 9px;
  }
  .chip b { display: block; margin-top: 2px; font-size: 17px; font-variant-numeric: tabular-nums; }
  .chip span { color: var(--muted); font-size: 11px; }
  .bl-list {
    max-height: 260px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  .bl-list table { font-size: 12px; }
  .msg { font-size: 12px; color: var(--muted); min-height: 18px; margin-top: 8px; }
  .msg.err { color: var(--fail); } .msg.ok { color: var(--ok); }
  .button-group { display: flex; align-items: center; justify-content: flex-end; gap: 7px; flex-wrap: wrap; }
  .recovery-layout { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .recovery-layout .chips { flex: 1 1 auto; }
  .recovery-actions { flex: 0 0 auto; }
  body.proxy-view-open { overflow: hidden; }
  body.proxy-view-open #dashboard-view > :not(#proxy-view) { display: none; }
  body.ip-usage-view-open { overflow: hidden; }
  body.ip-usage-view-open #dashboard-view > :not(#ip-usage-view) { display: none; }
  .proxy-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .proxy-view[hidden] { display: none; }
  .proxy-view-inner {
    width: min(calc(100% - 64px), 1280px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .proxy-view-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .proxy-view-subtitle { margin: 7px 0 0; color: var(--muted); font-size: 12px; }
  .proxy-summary {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--border);
    gap: 1px;
  }
  .proxy-summary-item { min-width: 0; padding: 12px 14px; background: var(--surface); }
  .proxy-summary-label { color: var(--muted); font-size: 11px; }
  .proxy-summary-value { margin-top: 4px; font-family: "Geist Mono", monospace; font-size: 22px; line-height: 1; font-weight: 720; }
  .proxy-import {
    display: grid;
    grid-template-columns: minmax(0, 1.5fr) minmax(260px, .5fr);
    gap: 16px;
    align-items: stretch;
    margin-top: 14px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  #proxy-input {
    min-height: 126px;
    font-family: "Geist Mono", monospace;
    font-size: 12px;
    line-height: 1.55;
  }
  .proxy-import-actions { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
  .proxy-import-actions .button-group { justify-content: flex-start; }
  .proxy-format { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
  .proxy-list-section { margin-top: 18px; }
  .proxy-list-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
  .proxy-list-head h2 { margin: 0; font-size: 13px; }
  .proxy-list-tools { display: flex; align-items: center; justify-content: flex-end; gap: 7px; flex-wrap: wrap; }
  .proxy-list-tools button { min-height: 34px; }
  .proxy-selection-count { color: var(--text-secondary); font-size: 11px; white-space: nowrap; }
  .proxy-table-wrap { overflow: auto; border: 1px solid var(--border); background: var(--surface-raised); }
  .proxy-table { min-width: 1040px; table-layout: fixed; }
  .proxy-table th:nth-child(1) { width: 44px; text-align: center; }
  .proxy-table th:nth-child(2) { width: 82px; }
  .proxy-table th:nth-child(3) { width: 250px; }
  .proxy-table th:nth-child(4) { width: 145px; }
  .proxy-table th:nth-child(5) { width: 82px; }
  .proxy-table th:nth-child(6) { width: 180px; }
  .proxy-table th:nth-child(7) { width: 74px; }
  .proxy-table th:nth-child(8) { width: 160px; }
  /* IP 使用统计表：7 列独立列宽（复用 proxy-table 的 fixed 布局，
     但代理池的 nth-child 宽度不适用，需单独定义避免 IP/国家列重叠） */
  .ip-usage-table { min-width: 720px; }
  .ip-usage-table th:nth-child(1) { width: 220px; text-align: left; }
  .ip-usage-table th:nth-child(2) { width: 86px; }
  .ip-usage-table th:nth-child(3) { width: 170px; }
  .ip-usage-table th:nth-child(4) { width: 150px; }
  .ip-usage-table th:nth-child(5) { width: 76px; }
  .ip-pool-table { min-width: 700px; }
  .ip-pool-table th:nth-child(1) { width: 220px; text-align: left; }
  .ip-pool-table th:nth-child(2) { width: 86px; }
  .ip-pool-table th:nth-child(3) { width: 76px; }
  .ip-pool-table th:nth-child(4) { width: 110px; }
  .ip-pool-table th:nth-child(5) { width: 110px; }
  .ip-pool-table th:nth-child(6) { width: 90px; }
  /* BFS 检测表：4 列自适应（proxy-table 的 min-width:1040px 会撑出横向滚动，这里不适用） */
  .bfs-table { min-width: 0; }
  .bfs-table td { overflow-wrap: anywhere; }
  .proxy-select { width: 16px; height: 16px; min-height: 0; accent-color: var(--accent); }
  .proxy-endpoint { overflow-wrap: anywhere; }
  .proxy-meta { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .proxy-state {
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 2px;
    color: var(--text-secondary);
    font-size: 11px;
    white-space: nowrap;
  }
  .proxy-state.healthy { border-color: color-mix(in srgb, var(--ok) 55%, var(--border)); color: var(--ok); }
  .proxy-state.unhealthy { border-color: color-mix(in srgb, var(--fail) 55%, var(--border)); color: var(--fail); }
  .proxy-state.cooldown { border-color: color-mix(in srgb, var(--warn) 55%, var(--border)); color: var(--warn); }
  .proxy-state.testing { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); color: var(--accent); }
  .proxy-actions { display: flex; align-items: center; gap: 6px; }
  .proxy-actions button { min-height: 30px; padding: 5px 9px; font-size: 11px; }
  .proxy-toggle { width: 16px; height: 16px; min-height: 0; accent-color: var(--accent); }
  .proxy-empty { padding: 38px 18px !important; color: var(--muted); text-align: center; }
  .proxy-job { color: var(--muted); font-size: 11px; }
  body.sso-view-open { overflow: hidden; }
  body.sso-view-open #dashboard-view > :not(#sso-view) { display: none; }
  .sso-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .sso-view[hidden] { display: none; }
  .sso-view-inner {
    width: min(calc(100% - 64px), 1280px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .sso-view-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .sso-view-subtitle { margin: 7px 0 0; color: var(--muted); font-size: 12px; }
  .sso-summary {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--border);
    gap: 1px;
  }
  .sso-summary-item { min-width: 0; padding: 12px 14px; background: var(--surface); }
  .sso-summary-label { color: var(--muted); font-size: 11px; }
  .sso-summary-value { margin-top: 4px; font-family: "Geist Mono", monospace; font-size: 22px; line-height: 1; font-weight: 720; }
  .sso-summary-value.warn { color: var(--warn); }
  .sso-summary-value.ok { color: var(--ok); }
  .sso-summary-value.fail { color: var(--fail); }
  .sso-import {
    display: grid;
    grid-template-columns: minmax(0, 1.5fr) minmax(280px, .55fr);
    gap: 16px;
    align-items: stretch;
    margin-top: 14px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  #sso-input {
    min-height: 148px;
    font-family: "Geist Mono", monospace;
    font-size: 12px;
    line-height: 1.55;
  }
  .sso-import-actions { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
  .sso-source-row { display: flex; flex-wrap: wrap; gap: 6px; }
  .sso-source-row button[aria-pressed="true"] {
    border-color: var(--accent);
    color: var(--accent);
  }
  .sso-settings { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
  .sso-format { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
  .sso-list-section { margin-top: 18px; }
  .sso-list-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
  .sso-list-head h2 { margin: 0; font-size: 13px; }
  .sso-filter { display: flex; gap: 6px; flex-wrap: wrap; }
  .sso-filter button[aria-pressed="true"] { border-color: var(--accent); color: var(--accent); }
  .sso-table-wrap { overflow: auto; border: 1px solid var(--border); background: var(--surface-raised); max-height: 460px; }
  .sso-table { min-width: 920px; table-layout: fixed; }
  .sso-table th:nth-child(1) { width: 180px; }
  .sso-table th:nth-child(2) { width: 72px; }
  .sso-table th:nth-child(3) { width: 88px; }
  .sso-table th:nth-child(4) { width: 72px; }
  .sso-table th:nth-child(5) { width: 110px; }
  .sso-table th:nth-child(6) { width: 90px; }
  .sso-empty { padding: 38px 18px !important; color: var(--muted); text-align: center; }
  .sso-job { color: var(--muted); font-size: 11px; }
  .sso-verdict {
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 2px;
    font-size: 11px;
    white-space: nowrap;
  }
  .sso-verdict.clean { border-color: color-mix(in srgb, var(--ok) 55%, var(--border)); color: var(--ok); }
  .sso-verdict.flagged { border-color: color-mix(in srgb, var(--fail) 55%, var(--border)); color: var(--fail); }
  .sso-verdict.error, .sso-verdict.unknown { border-color: color-mix(in srgb, var(--warn) 55%, var(--border)); color: var(--warn); }
  .proxy-pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 0 0;
  }
  .proxy-page-controls { display: flex; align-items: center; gap: 7px; }
  .proxy-page-controls select { min-height: 32px; width: auto; padding: 5px 28px 5px 9px; }
  .proxy-page-controls button { min-height: 32px; padding: 5px 10px; }
  body.domain-view-open { overflow: hidden; }
  body.domain-view-open #dashboard-view > :not(#domain-view) { display: none; }
  .domain-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .domain-view[hidden] { display: none; }
  .domain-view-inner {
    width: min(calc(100% - 64px), 1280px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .domain-view-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .domain-view-subtitle { margin: 7px 0 0; color: var(--muted); font-size: 12px; }
  .mail-source-kicker {
    margin-bottom: 5px;
    color: var(--accent);
    font-size: 10px;
    font-weight: 760;
    text-transform: uppercase;
  }
  .mail-provider-panel {
    padding: 18px;
    border: 1px solid var(--border-strong);
    background: var(--surface-raised);
  }
  .mail-provider-toolbar {
    display: grid;
    grid-template-columns: minmax(280px, 1fr) auto;
    align-items: end;
    gap: 18px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .mail-provider-toolbar .field { max-width: 520px; }
  .mail-provider-toolbar h2 { margin: 0; color: var(--text); font-size: 15px; font-weight: 620; }
  .mail-provider-status { display: flex; align-items: center; gap: 8px; min-height: 38px; }
  .mail-provider-status-label { color: var(--muted); font-size: 11px; }
  .mail-provider-fields {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px 16px;
    padding: 18px 0;
  }
  .mail-provider-fields .field { min-width: 0; gap: 5px; }
  .mail-provider-fields input,
  .mail-provider-fields select { width: 100%; min-height: 40px; }
  .mail-secret-wrap { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 6px; }
  .mail-secret-wrap button { min-width: 54px; min-height: 40px; padding-inline: 10px; font-size: 11px; }
  .mail-secret-wrap.pending-clear input { border-color: var(--warn); }
  .mail-secret-note { min-height: 14px; color: var(--muted); font-size: 10px; }
  .mail-secret-note.warn { color: var(--warn); }
  .mail-provider-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
  }
  .mail-provider-actions .mail-provider-meta { margin-left: auto; color: var(--muted); font-size: 11px; }
  .mail-provider-result { min-height: 18px; margin-top: 10px; }
  .domain-advanced { margin-top: 20px; border-top: 1px solid var(--border-strong); border-bottom: 1px solid var(--border-strong); }
  .domain-advanced > summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    min-height: 52px;
    padding: 10px 2px;
    color: var(--text);
    cursor: pointer;
    list-style: none;
  }
  .domain-advanced > summary::-webkit-details-marker { display: none; }
  .domain-advanced > summary::after { content: "+"; color: var(--accent); font-family: "Geist Mono", monospace; font-size: 18px; }
  .domain-advanced[open] > summary::after { content: "-"; }
  .domain-advanced-title { font-size: 13px; font-weight: 680; }
  .domain-advanced-meta { color: var(--muted); font-size: 11px; font-weight: 450; }
  .domain-advanced-body { padding: 4px 0 24px; }
  .domain-advanced-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
  .domain-summary {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--border);
    gap: 1px;
  }
  .domain-summary-item { min-width: 0; padding: 12px 14px; background: var(--surface); }
  .domain-summary-label { color: var(--muted); font-size: 11px; }
  .domain-summary-value { margin-top: 4px; font-family: "Geist Mono", monospace; font-size: 22px; line-height: 1; font-weight: 720; }
  .domain-import {
    display: grid;
    grid-template-columns: minmax(0, 1.25fr) minmax(300px, .75fr);
    gap: 16px;
    align-items: stretch;
    margin-top: 14px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  #domain-input {
    min-height: 126px;
    font-family: "Geist Mono", monospace;
    font-size: 12px;
    line-height: 1.55;
  }
  .domain-import-actions { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
  .domain-import-actions .button-group { justify-content: flex-start; }
  .domain-format { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
  .domain-settings { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
  .domain-settings .field { gap: 4px; }
  .domain-settings input, .domain-settings select { min-height: 34px; }
  .domain-list-section { margin-top: 18px; }
  .domain-list-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
  .domain-list-head h2 { margin: 0; font-size: 13px; }
  .domain-table-wrap { overflow: auto; border: 1px solid var(--border); background: var(--surface-raised); }
  .domain-table { min-width: 960px; table-layout: fixed; }
  .domain-table th:nth-child(1) { width: 92px; }
  .domain-table th:nth-child(2) { width: 230px; }
  .domain-table th:nth-child(3) { width: 130px; }
  .domain-table th:nth-child(4) { width: 150px; }
  .domain-table th:nth-child(5) { width: 220px; }
  .domain-table th:nth-child(6) { width: 72px; }
  .domain-table th:nth-child(7) { width: 170px; }
  .domain-name { overflow-wrap: anywhere; }
  .domain-meta { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .domain-state {
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 2px;
    color: var(--text-secondary);
    font-size: 11px;
    white-space: nowrap;
  }
  .domain-state.active { border-color: color-mix(in srgb, var(--ok) 55%, var(--border)); color: var(--ok); }
  .domain-state.standby { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); color: var(--accent); }
  .domain-state.blocked { border-color: color-mix(in srgb, var(--fail) 55%, var(--border)); color: var(--fail); }
  .domain-state.disabled { border-color: var(--border); color: var(--muted); }
  .domain-actions { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .domain-actions button { min-height: 30px; padding: 5px 9px; font-size: 11px; }
  .domain-toggle { width: 16px; height: 16px; min-height: 0; accent-color: var(--accent); }
  .domain-empty { padding: 38px 18px !important; color: var(--muted); text-align: center; }
  .domain-job { color: var(--muted); font-size: 11px; }
  body.help-view-open { overflow: hidden; }
  body.help-view-open #dashboard-view > :not(#help-view) { display: none; }
  .help-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .help-view[hidden] { display: none; }
  .help-view-inner {
    width: min(calc(100% - 64px), 1120px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .help-view-heading {
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .help-view-subtitle {
    margin: 7px 0 0;
    color: var(--muted);
    font-size: 12px;
  }
  .help-body { min-width: 0; }
  .help-toolbar {
    min-height: 42px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;
  }
  .help-tabs {
    display: inline-flex;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  button.help-tab {
    min-height: 28px;
    padding: 5px 10px;
    border: 0;
    border-radius: 1px;
    background: transparent;
    color: var(--muted);
    font-size: 12px;
  }
  button.help-tab:hover { border: 0; color: var(--text); }
  button.help-tab[aria-selected="true"] { background: var(--accent); color: var(--accent-ink); }
  .help-guide-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1px;
    border: 1px solid var(--border);
    background: var(--border);
  }
  .help-guide-item { min-width: 0; min-height: 132px; padding: 14px; background: var(--surface-soft); }
  .help-guide-item h3 { margin: 0; color: var(--text); font-size: 13px; font-weight: 650; }
  .help-guide-item p { margin: 9px 0 0; color: var(--text-secondary); font-size: 12px; line-height: 1.65; }
  .help-guide-item code, .faq-answer code {
    color: var(--accent);
    font-family: "Geist Mono", monospace;
    font-size: .94em;
    overflow-wrap: anywhere;
  }
  .help-note {
    margin: 14px 0 0;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
    line-height: 1.6;
  }
  .faq-tools {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 4px;
  }
  #faq-search { min-height: 36px; max-width: 360px; }
  .faq-count { flex: 0 0 auto; color: var(--muted); font-size: 11px; }
  .faq-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); column-gap: 24px; }
  .faq-item { min-width: 0; border-top: 1px solid var(--border); }
  .faq-item summary {
    padding: 13px 2px;
    color: var(--text);
    font-size: 12px;
    font-weight: 620;
    line-height: 1.45;
    cursor: pointer;
  }
  .faq-item summary::marker { color: var(--accent); }
  .faq-item[open] summary { color: var(--accent); }
  .faq-answer { padding: 0 18px 14px; color: var(--text-secondary); font-size: 12px; line-height: 1.65; }
  .faq-empty { margin: 16px 0 2px; color: var(--muted); font-size: 12px; }
  footer { margin-top: 16px; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
  main > :not(.help-view) {
    animation: panel-enter 400ms cubic-bezier(.16, 1, .3, 1) both;
  }
  main > :nth-child(2) { animation-delay: 15ms; }
  main > :nth-child(3) { animation-delay: 30ms; }
  main > :nth-child(4) { animation-delay: 45ms; }
  main > :nth-child(5) { animation-delay: 60ms; }
  main > :nth-child(6) { animation-delay: 75ms; }
  main > :nth-child(n + 7) { animation-delay: 90ms; }
  @keyframes panel-enter {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @media (min-width: 1121px) {
    .control-panel .control-grid { gap: 10px; }
    .control-panel .field { gap: 4px; }
    .control-panel .field label { font-size: 11px; }
    .control-panel .control-actions { gap: 6px; }
    .control-panel input,
    .control-panel select,
    .control-panel .control-actions button {
      min-height: 34px;
      padding-block: 6px;
    }
  }
  @media (max-width: 1120px) {
    .control-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .field-token { grid-column: span 2; }
    .control-actions { grid-column: 1 / -1; padding-top: 14px; border-top: 1px solid var(--border); }
    .ip-policy { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .policy-switch { grid-column: 1 / -1; }
    .metric-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .three { grid-template-columns: minmax(0, 1fr); }
    .help-guide-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .mail-provider-fields { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 760px) {
    .topbar { width: calc(100% - 32px); height: 60px; align-items: center; flex-direction: row; gap: 10px; }
    .brand { width: auto; }
    .status-cluster { width: auto; justify-content: flex-end; margin-left: auto; }
    #clock, #sync-label { display: none; }
    .header-btn { min-height: 28px; padding: 0 8px; font-size: 10px; }
    #config-backup-msg { display: none; }
    main { width: calc(100% - 24px); padding: 20px 0 34px; }
    .page-heading { margin-bottom: 16px; }
    .page-title { font-size: 22px; }
    .card { padding: 14px; }
    .control-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .field-token, .field-mode { grid-column: 1 / -1; }
    .control-actions { justify-content: stretch; }
    .control-actions button { flex: 1 1 0; padding-inline: 8px; }
    .ip-policy { grid-template-columns: minmax(0, 1fr); }
    .policy-switch { grid-column: auto; }
    .log-tools { align-items: stretch; flex-wrap: wrap; justify-content: flex-start; }
    .log-cleanup-msg { width: 100%; min-width: 0; text-align: left; }
    .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .metric { padding: 14px; }
    .metric .value { font-size: 23px; }
    .rate-grid, .two { grid-template-columns: minmax(0, 1fr); }
    .rate-item + .rate-item { border-left: 0; border-top: 1px solid var(--border); }
    .section-head { align-items: flex-start; }
    .section-meta { max-width: 48%; }
    .help-view { inset-block-start: 60px; }
    .help-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .help-view-heading { margin-bottom: 16px; padding-bottom: 16px; }
    .help-toolbar, .faq-tools { align-items: stretch; flex-direction: column; }
    .help-toolbar { min-height: 0; }
    .help-tabs { width: 100%; }
    button.help-tab { flex: 1 1 0; }
    .help-guide-grid, .faq-grid { grid-template-columns: 1fr; }
    #faq-search { max-width: none; }
    .recovery-layout { align-items: stretch; flex-direction: column; }
    .recovery-actions { justify-content: stretch; }
    .recovery-actions button { flex: 1 1 0; }
    .proxy-view { inset-block-start: 60px; }
    .proxy-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .proxy-view-heading { align-items: flex-start; flex-direction: column; margin-bottom: 16px; padding-bottom: 16px; }
    .sso-view { inset-block-start: 60px; }
    .sso-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .sso-view-heading { align-items: flex-start; flex-direction: column; margin-bottom: 16px; padding-bottom: 16px; }
    .sso-summary { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .sso-import { grid-template-columns: minmax(0, 1fr); }
    .proxy-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .proxy-summary-item:last-child { grid-column: 1 / -1; }
    .proxy-import { grid-template-columns: minmax(0, 1fr); }
    .proxy-import-actions .button-group { justify-content: stretch; }
    .proxy-import-actions button { flex: 1 1 auto; }
    .proxy-list-head { align-items: flex-start; flex-direction: column; }
    .domain-view { inset-block-start: 60px; }
    .domain-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .domain-view-heading { align-items: flex-start; flex-direction: column; margin-bottom: 16px; padding-bottom: 16px; }
    .mail-provider-panel { padding: 14px; }
    .mail-provider-toolbar { grid-template-columns: minmax(0, 1fr); gap: 10px; }
    .mail-provider-toolbar .field { max-width: none; }
    .mail-provider-fields { grid-template-columns: minmax(0, 1fr); }
    .mail-provider-actions { align-items: stretch; flex-wrap: wrap; }
    .mail-provider-actions button { flex: 1 1 0; }
    .mail-provider-actions .mail-provider-meta { width: 100%; margin-left: 0; }
    .domain-advanced-head { align-items: flex-start; flex-direction: column; }
    .domain-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .domain-summary-item:last-child { grid-column: 1 / -1; }
    .domain-import { grid-template-columns: minmax(0, 1fr); }
    .domain-settings { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .domain-import-actions .button-group { justify-content: stretch; }
    .domain-import-actions button { flex: 1 1 auto; }
    .domain-list-head { align-items: flex-start; flex-direction: column; }
  }
  @media (max-width: 420px) {
    .topbar { gap: 6px; }
    .brand { flex: 0 0 auto; }
    h1 { font-size: 0; }
    h1::before { content: "GR"; font-size: 15px; }
    .status-cluster { min-width: 0; gap: 4px; }
    .badge { font-size: 11px; }
    .run-status { width: 30px; min-width: 30px; justify-content: center; padding-inline: 0; }
    #run-label { display: none; }
    .card { padding: 13px; }
    .control-actions { flex-wrap: wrap; }
    .control-actions button { flex-basis: calc(50% - 4px); }
    .control-actions button:last-child { flex-basis: 100%; }
    .metric .sub { font-size: 11px; }
    .button-group { justify-content: flex-start; }
    #run-status { display: none; }
    button.view-switch { min-width: 0; padding-inline: 6px; }
    #domain-view-label, #proxy-view-label, #sso-view-label, #help-view-label { font-size: 0; }
    #domain-view-label::after { content: "邮箱"; font-size: 11px; }
    #proxy-view-label::after { content: "代理"; font-size: 11px; }
    #sso-view-label::after { content: "风控"; font-size: 11px; }
    #help-view-label::after { content: "问题"; font-size: 11px; }
    #domain-view-toggle[data-active="true"] #domain-view-label::after,
    #proxy-view-toggle[data-active="true"] #proxy-view-label::after,
    #sso-view-toggle[data-active="true"] #sso-view-label::after,
    #help-view-toggle[data-active="true"] #help-view-label::after { content: "返回"; }
    button.theme-option { padding-inline: 6px; }
    .domain-settings { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .domain-settings .field:first-child { grid-column: 1 / -1; }
  }
  @media (max-width: 340px) {
    .run-status { display: none; }
  }
  html[data-theme="dark"] {
      color-scheme: dark;
      --bg: #171815;
      --surface: #20211e;
      --surface-raised: #242622;
      --surface-soft: #1d1e1b;
      --surface-deep: #30322d;
      --border: rgba(240, 241, 237, .16);
      --border-strong: rgba(240, 241, 237, .42);
      --text: #f0f1ed;
      --text-secondary: #d3d5ce;
      --muted: #a5a79f;
      --placeholder: #777971;
      --ok: #69c493;
      --fail: #f27c71;
      --warn: #d7ae58;
      --accent: #f06449;
      --accent-hover: #ff7a60;
      --accent-ink: #171815;
      --focus: #f06449;
      --button: #242622;
      --button-hover: #30322d;
      --hover-border: rgba(240, 241, 237, .42);
      --focus-shadow: rgba(240, 100, 73, .18);
      --primary-bg: #f0f1ed;
      --primary-text: #171815;
      --primary-hover: #d3d5ce;
      --danger-border: rgba(242, 124, 113, .48);
      --danger-hover-bg: rgba(242, 124, 113, .09);
      --danger-hover-border: rgba(242, 124, 113, .75);
      --header: rgba(23, 24, 21, .88);
      --progress-track: #30322d;
      --row-hover: rgba(240, 241, 237, .035);
      --tail-bg: #11120f;
      --tail-text: #d3d5ce;
      --grid-line: rgba(240, 241, 237, .045);
  }
  @media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    *, *::before, *::after {
      animation-duration: .01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: .01ms !important;
    }
    .card:hover { transform: none; }
  }
</style>
</head>
<body>
<header>
  <div class="topbar">
    <div class="brand">
      <h1>GrokRegister</h1>
    </div>
    <div class="status-cluster">
      <button type="button" class="view-switch" id="domain-view-toggle" aria-label="打开邮箱服务" title="邮箱服务" aria-controls="domain-view" aria-expanded="false" data-active="false" onclick="toggleDomainView()">
        <span id="domain-view-label" aria-hidden="true">邮箱服务</span>
      </button>
      <button type="button" class="view-switch" id="proxy-view-toggle" aria-label="打开代理池" title="代理池" aria-controls="proxy-view" aria-expanded="false" data-active="false" onclick="toggleProxyView()">
        <span id="proxy-view-label" aria-hidden="true">代理池</span>
      </button>
      <button type="button" class="view-switch" id="sso-view-toggle" aria-label="打开 SSO 风控" title="SSO 风控" aria-controls="sso-view" aria-expanded="false" data-active="false" onclick="toggleSsoView()">
        <span id="sso-view-label" aria-hidden="true">SSO 风控</span>
      </button>
      <button type="button" class="view-switch" id="ip-usage-view-toggle" aria-label="打开IP使用统计" title="IP使用统计" aria-controls="ip-usage-view" aria-expanded="false" data-active="false" onclick="toggleIpUsageView()">
        <span id="ip-usage-view-label" aria-hidden="true">IP使用</span>
      </button>
      <button type="button" class="view-switch" id="help-view-toggle" aria-label="打开问题和使用" title="问题和使用" aria-controls="help-view" aria-expanded="false" data-active="false" onclick="toggleAppView()">
        <span id="help-view-label" aria-hidden="true">问题和使用</span>
      </button>
      <button type="button" class="header-btn primary" id="topbar-export" onclick="exportConfig()"
              title="导出全部配置（config / 代理池 / 邮箱域名 / 多配置档 / IP 限制，含敏感凭据，请妥善保管）">导出配置</button>
      <label class="header-btn" id="topbar-import"
             title="导入配置文件恢复环境（将覆盖上述配置，导入后需重启面板生效）">
        <span>导入</span>
        <input type="file" id="config-import-file" accept=".json,application/json" class="sr-only"
               onchange="importConfigFile(this.files[0])"/>
      </label>
      <span class="badge" id="config-backup-msg" role="status" aria-live="polite" hidden></span>
      <div class="theme-switch" role="group" aria-label="界面主题">
        <button type="button" class="theme-option" data-theme-choice="light" aria-pressed="false" onclick="setTheme('light')">浅色</button>
        <button type="button" class="theme-option" data-theme-choice="dark" aria-pressed="false" onclick="setTheme('dark')">深色</button>
      </div>
      <span class="badge run-status" id="run-status" aria-label="任务状态：加载中" aria-live="polite" aria-atomic="true"><span class="dot" id="run-dot"></span><span id="run-label">加载中</span></span>
      <span class="badge mono" id="clock">--</span>
      <span class="badge" id="sync-label">实时更新</span>
    </div>
  </div>
</header>
<main id="dashboard-view" aria-label="注册控制台">
  <div class="page-heading">
    <div>
      <div class="page-title">注册控制台</div>
      <div class="brand-subtitle mono" id="logname">--</div>
    </div>
  </div>
  <section class="card control-panel">
    <div class="section-head">
      <h2>任务控制</h2>
      <span class="section-meta mono" id="ctrl-status"></span>
    </div>
    <div class="control-grid">
      <div class="field field-token">
        <label for="monitor-token">访问令牌</label>
        <input id="monitor-token" type="password" autocomplete="off" placeholder="MONITOR_TOKEN" onchange="getToken(); refresh(); refreshRecovery(); refreshProxies(); refreshEmailProvider(); refreshEmailDomains(); refreshSsoState(); refreshBfs()" onblur="getToken()"/>
      </div>
      <div class="field field-mode">
        <label for="mode">运行模式</label>
        <select id="mode">
          <option value="orch">持续编排</option>
          <option value="batch">单批运行</option>
        </select>
      </div>
      <div class="field"><label for="workers-input">并发数</label>
        <input type="number" id="workers-input" min="1" max="24" value="3"/>
      </div>
      <div class="field"><label for="batch_count">单批数量</label>
        <input type="number" id="batch_count" min="1" value="40"/>
      </div>
      <div class="field"><label for="add_count">追加目标</label>
        <input type="number" id="add_count" min="1" value="40" title="每次启动从当前 CPA 再注册 N 个"/>
      </div>
      <div class="field"><label for="risk_pause">风控阈值</label>
        <input type="number" id="risk_pause" min="1" max="50" value="10"/>
      </div>
      <div class="ip-policy" aria-label="出口 IP 轮换策略">
        <div class="field" id="accounts-per-ip-field"><label for="accounts_per_ip">每 IP 账号数（0=不限）</label>
          <input type="number" id="accounts_per_ip" min="0" max="20" value="2" title="0=不限制每 IP 账号数（只按连续失败换 IP）；大于 0 时满额换 IP。成功和最终失败都计入；内部重试不计入"/>
        </div>
        <div class="field" id="ip-failure-threshold-field"><label for="ip_failure_rotate_threshold">连续失败换 IP</label>
          <input type="number" id="ip_failure_rotate_threshold" min="1" max="20" value="3" title="同一出口连续最终失败达到此值即更换 IP（始终生效）"/>
        </div>
        <div class="field" id="ip-usage-limit-field"><label for="ip_usage_limit">单IP累计使用上限（0=不限）</label>
          <input type="number" id="ip_usage_limit" min="0" max="100000" value="0" title="该出口 IP 在所有任务中的累计账号槽位数（成功/最终失败都计）达到此值后必须换 IP"/>
        </div>
      </div>
      <div class="control-actions">
        <button class="primary" id="btn-start" onclick="doStart()">启动任务</button>
        <button class="danger" id="btn-stop" onclick="doStop()">停止任务</button>
        <button onclick="saveCtrl()">保存设置</button>
      </div>
    </div>
    <div class="msg" id="ctrl-msg" role="status" aria-live="polite"></div>
  </section>

  <section class="help-view" id="help-view" aria-labelledby="help-view-title" hidden>
    <div class="help-view-inner">
      <div class="help-view-heading">
        <div class="page-title" id="help-view-title">使用帮助</div>
        <p class="help-view-subtitle">运行方法与故障排查</p>
      </div>
      <div class="help-body" id="help-body">
      <div class="help-toolbar">
        <div class="help-tabs" role="tablist" aria-label="帮助内容" onkeydown="handleHelpTabKey(event)">
          <button type="button" class="help-tab" id="help-tab-guide" role="tab" aria-selected="true" aria-controls="help-guide" data-help-tab="guide" onclick="setHelpTab('guide')">快速使用</button>
          <button type="button" class="help-tab" id="help-tab-faq" role="tab" aria-selected="false" aria-controls="help-faq" data-help-tab="faq" tabindex="-1" onclick="setHelpTab('faq')">常见问题</button>
        </div>
      </div>

      <div id="help-guide" role="tabpanel" aria-labelledby="help-tab-guide">
        <div class="help-guide-grid">
          <div class="help-guide-item">
            <h3>准备环境</h3>
            <p>确认 Camoufox 引擎已安装、邮箱服务可用、CPA auth 目录可写。直连可用时不必额外配置代理。</p>
          </div>
          <div class="help-guide-item">
            <h3>选择模式</h3>
            <p><code>持续编排</code>按追加目标多轮运行；<code>单批运行</code>只执行单批数量。首次建议并发 2-3。</p>
          </div>
          <div class="help-guide-item">
            <h3>保存并启动</h3>
            <p>输入当前面板令牌，先保存设置再启动。追加目标表示从现有 CPA 数量继续增加多少。</p>
          </div>
          <div class="help-guide-item">
            <h3>观察结果</h3>
            <p>优先看注册风控、时段成功率和日志尾部。连续风控时先换出口或邮箱域名，不要继续提高并发。</p>
          </div>
        </div>
        <p class="help-note">停止任务会结束当前编排和批处理进程。重置黑名单会恢复基线规则，不等于清空所有风控判断。</p>
      </div>

      <div id="help-faq" role="tabpanel" aria-labelledby="help-tab-faq" hidden>
        <div class="faq-tools">
          <label class="sr-only" for="faq-search">搜索常见问题</label>
          <input id="faq-search" type="search" placeholder="搜索错误码或现象" autocomplete="off" oninput="filterFaq(this.value)"/>
          <span class="faq-count mono" id="faq-count">12 项</span>
        </div>
        <div class="faq-grid" id="faq-grid">
          <details class="faq-item" data-faq-item data-search="令牌 token unauthorized 401 保存设置 启动">
            <summary>提示访问令牌不匹配或 401</summary>
            <div class="faq-answer">重新输入当前面板令牌并保存。令牌只保存在当前浏览器的 localStorage 中，换端口、设备或浏览器后需要重新输入。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="启动 立即结束 目标 cpa add_count 追加目标">
            <summary>点击启动后立即结束</summary>
            <div class="faq-answer">通常是 CPA 已达到旧目标。提高“追加目标”后再启动；持续编排会以当前 CPA 为基线增加 N，单批运行只执行“单批数量”。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="风控 policy deny registration risk botFlagSource ip 邮箱 域名">
            <summary>出现 policy=deny 或注册风控</summary>
            <div class="faq-answer">该账号已被注册风控拒绝，不要反复重转同一 SSO。先更换质量更好的出口并给 IP 冷却时间，邮箱优先使用稳定的子域名，并发先保持 2-3。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="卡住 浏览器 启动失败 turnstile 资料页 空页 并发 camoufox">
            <summary>注册卡在验证码、资料页或浏览器启动</summary>
            <div class="faq-answer">先从失败分类和日志尾部确认具体阶段。连续浏览器启动失败时降低并发，并检查是否执行过 <code>camoufox fetch</code>；资料页失败也可能是 Turnstile 未通过。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="cpa 没新增 invalid_grant access denied 503 auth unavailable oauth 入库 目录 管理密钥">
            <summary>CPA 没新增，或出现 invalid_grant / 503</summary>
            <div class="faq-answer">先检查 <code>cpa_auto_add</code>、auth 目录、远程 CPA 地址和管理密钥。<code>invalid_grant Access denied</code> 表示 OAuth 交换被拒；503 表示 CPA 当前没有可用 xAI auth。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="permission denied access chat endpoint referrer grok build base_url oauth">
            <summary>调用模型提示 permission-denied</summary>
            <div class="faq-answer">常见原因是 token 缺少 <code>referrer=grok-build</code>，或 <code>base_url</code> 指向了 <code>api.x.ai</code>。使用项目的 Authorization Code + PKCE 流程重新生成，并指向 Build 通道。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="出口 ip 代理 无法解析 流量 住宅 链式 dialer">
            <summary>无法解析出口 IP，或代理流量消耗很高</summary>
            <div class="faq-answer">先单独测试代理端口是否可用。住宅代理可能同时计算上下行流量，实际每 GB 产出没有固定值；降低并发并避免重复失败重试。链式代理应在代理客户端配置。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="邮箱 api 401 超时 cloudflare workers key auth_mode proxy">
            <summary>邮箱 API 返回 401 或请求超时</summary>
            <div class="faq-answer">401 先检查对应邮箱服务的 key 和 <code>auth_mode</code>。访问 workers.dev 超时时，在配置中显式填写代理，不要只依赖桌面进程可能无法继承的 HTTP_PROXY 环境变量。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="邮箱服务 provider cloudflare duckmail yyds mailnest cloudmail moemail outlook_rt jsonl refresh_token api 测试 域名轮换">
            <summary>如何配置邮箱服务</summary>
            <div class="faq-answer">打开顶部“邮箱服务”，选择当前使用的服务商后填写对应 API 配置，保存并测试连通性。Outlook RT 库存模式填写 jsonl（email + refresh_token）路径即可，无需 client_id。自有域名轮换位于同页高级设置；只有 xAI 明确拒绝域名才累计，邮箱 API 和验证码异常不会处罚域名。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="bfs jwt claim access_token 标记 flagged 风控 检测 scan">
            <summary>什么是 bfs，和 botFlagSource 有何不同</summary>
            <div class="faq-answer"><code>bfs</code> 是 xAI access_token / SSO JWT 里的风险 claim：payload 里<strong>出现该字段</strong>即视为标记（常见值 2）。它与 grok.com 页面的 <code>botFlagSource</code> / <code>policy=deny</code> 独立。注册换 token 后会自动检测；也可在控制台“BFS 检测”扫描 CPA 目录，导出 <code>log/bfs_flagged.jsonl</code>。配置 <code>bfs_skip_cpa</code> 可跳过入库，<code>bfs_disable_cpa</code> 可写 disabled。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="sso 风控 botFlagSource policy deny check-sso-state 检测 面板 粘贴">
            <summary>如何用 SSO 批量检测账号是否被风控</summary>
            <div class="faq-answer">打开顶部“SSO 风控”，粘贴 <code>email----sso</code> 或纯 cookie，也可扫描待处理 / 全部账号 / 已隔离名单。面板用 SSO 访问 grok.com 读取 <code>botFlagSource</code> 和 <code>policy=deny</code>，不换 token、不入库。标记规则与注册门禁一致：<code>botFlagSource</code> 为 1/2，或任意 <code>policy=deny</code>。干净名单写到 <code>log/sso_clean.txt</code>，标记名单写到 <code>log/sso_flagged.jsonl</code>（不含 token）。命令行：<code>python scripts/check_sso_state.py --sso list.txt --from-config config.json</code>。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="黑名单 asn 清除 重置 baseline 风控 出口">
            <summary>黑名单有什么作用，可以清除吗</summary>
            <div class="faq-answer">黑名单用于避开持续触发风控的出口 ASN。面板“重置”会恢复基线熔断规则；不清楚影响时不要清空全部规则，重复命中通常说明出口质量需要调整。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="accounts txt sso 导入 cpa json sub2api 转换">
            <summary>已有 accounts 文本怎么导入 CPA 或 sub2api</summary>
            <div class="faq-answer">控制台的“账号补录”可处理待补录队列，也可扫描全部 accounts 文本；已存在 CPA 的账号会跳过，成功项会从待补录队列移除。面板不直接导入 sub2api，需要按目标系统的数据结构另行转换。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="搜索 模型 grok build 4.5 能力 api">
            <summary>注册成功但搜索或某个模型不可用</summary>
            <div class="faq-answer">注册成功不代表所有上游能力都会开放。确认请求走 Grok Build 通道；搜索和具体模型可用性仍可能随账号状态和上游策略变化。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="体验额度 429 quota rate limit 免费 余额">
            <summary>体验额度有多少，出现 429 怎么办</summary>
            <div class="faq-answer">体验额度由上游按账号分配，面板无法推算准确余额。429 通常表示额度耗尽或触发速率限制，需要等待恢复或更换仍有可用额度的 auth。</div>
          </details>
        </div>
        <p class="faq-empty" id="faq-empty" hidden>没有匹配的问题，请换一个错误码或现象关键词。</p>
      </div>
      </div>
    </div>
  </section>

  <section class="proxy-view" id="proxy-view" aria-labelledby="proxy-view-title" hidden>
    <div class="proxy-view-inner">
      <div class="proxy-view-heading">
        <div>
          <div class="page-title" id="proxy-view-title">外部代理池</div>
          <p class="proxy-view-subtitle">凭据仅保存在本机，注册中途不会切换出口</p>
        </div>
        <span class="proxy-job mono" id="proxy-updated">等待读取</span>
      </div>

      <div class="proxy-summary" id="proxy-summary" aria-label="代理池状态">
        <div class="proxy-summary-item"><div class="proxy-summary-label">总数</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">可用</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">异常</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">冷却</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">未检测</div><div class="proxy-summary-value">--</div></div>
      </div>

      <div class="proxy-import">
        <div class="field">
          <label for="proxy-input">代理地址（每行一条）</label>
          <textarea id="proxy-input" spellcheck="false" autocomplete="off" placeholder="http://user:password@host:port&#10;http://Default.{session}:token@127.0.0.1:2260"></textarea>
        </div>
        <div class="proxy-import-actions">
          <p class="proxy-format">支持 http、https、socks5、socks5h，以及 host:port:user:password。Resin 可在用户名中使用 <code>{session}</code> 或 <code>{account}</code>；每个 worker、每轮切换会生成独立粘性身份。一条健康模板可供多个 worker 使用。Camoufox 不支持带认证的 SOCKS5；Resin 开启强制认证时请使用 <code>http://</code>。</p>
          <div class="button-group">
            <button class="primary" id="proxy-import-button" onclick="importProxyInput()">导入代理</button>
            <button id="proxy-legacy-button" onclick="importLegacyProxies()">导入 proxies.txt</button>
          </div>
        </div>
      </div>
      <div class="msg" id="proxy-msg" role="status" aria-live="polite"></div>

      <div class="proxy-list-section">
        <div class="proxy-list-head">
          <div>
            <h2>代理明细</h2>
            <div class="proxy-job mono" id="proxy-test-status" role="status" aria-live="polite">未开始检测</div>
          </div>
          <div class="proxy-list-tools">
            <span class="proxy-selection-count mono" id="proxy-selection-count">已选 0</span>
            <button id="proxy-test-selected" onclick="testSelectedProxies()" disabled>检测所选</button>
            <button class="danger" id="proxy-delete-selected" onclick="deleteSelectedProxies()" disabled>删除所选</button>
            <button id="proxy-clear-selection" onclick="clearProxySelection()" disabled>清空选择</button>
            <button class="primary" id="proxy-test-all" onclick="testProxies()">检测全部（自动分批）</button>
          </div>
        </div>
        <div class="proxy-table-wrap">
          <table class="proxy-table">
            <thead><tr><th><input class="proxy-select" id="proxy-select-page" type="checkbox" aria-label="全选本页" onchange="toggleProxyPageSelection(this.checked)"/></th><th>状态</th><th>代理端点</th><th>出口 / ASN</th><th>使用次数</th><th>延迟</th><th>最近状态</th><th>启用</th><th>操作</th></tr></thead>
            <tbody id="proxy-body"><tr><td colspan="9" class="proxy-empty">正在读取代理池</td></tr></tbody>
          </table>
        </div>
        <div class="proxy-pagination">
          <span class="proxy-job mono" id="proxy-page-status">第 1 / 1 页</span>
          <div class="proxy-page-controls">
            <label for="proxy-page-size" class="proxy-job">每页</label>
            <select id="proxy-page-size" onchange="changeProxyPageSize(this.value)">
              <option value="25">25</option>
              <option value="50" selected>50</option>
              <option value="100">100</option>
              <option value="200">200</option>
            </select>
            <button id="proxy-page-prev" onclick="changeProxyPage(-1)">上一页</button>
            <button id="proxy-page-next" onclick="changeProxyPage(1)">下一页</button>
          </div>
        </div>
      </div>
    </div>
  </section>

  <section class="proxy-view" id="ip-usage-view" aria-labelledby="ip-usage-view-title" hidden>
    <div class="proxy-view-inner">
      <div class="domain-view-heading">
        <div>
          <div class="mail-source-kicker">IP usage</div>
          <div class="page-title" id="ip-usage-view-title">IP 使用统计</div>
          <p class="domain-view-subtitle">所有任务累计的出口 IP 使用次数（log/ip_usage.json）</p>
        </div>
        <span class="domain-job" id="ip-usage-heading-label">--</span>
        <div class="mail-provider-actions" style="display:inline-flex;gap:8px;align-items:center">
          <button class="danger" id="ip-usage-reset-btn" onclick="resetIpUsage()">清空全部统计</button>
        </div>
      </div>

      <div class="proxy-summary" id="ip-usage-summary"></div>

      <section class="mail-provider-panel" aria-labelledby="ip-pool-label">
        <div class="mail-provider-toolbar">
          <div>
            <div class="mail-source-kicker">Ready IP pool</div>
            <h2 id="ip-pool-label">可用 IP 池（预筛可用出口，worker 优先取用）</h2>
            <p class="mail-provider-meta" style="margin:4px 0 0;max-width:640px">
              面板后台批量探测 sticky 身份，筛出未超限出口写入池；注册 worker 换口时优先从这里取已确认可用的身份（不再随机碰运气）。身份在会话有效期（默认 10 分钟）内有效，过期自动清理并补充。
            </p>
          </div>
          <div class="mail-provider-actions" style="display:inline-flex;gap:8px;align-items:center">
            <button class="primary" id="ip-pool-probe-btn" onclick="probeIpPool()">立即探测</button>
            <span class="mail-provider-meta mono" id="ip-pool-status">--</span>
          </div>
        </div>
        <div class="msg" id="ip-pool-msg" role="status" aria-live="polite"></div>
        <details class="domain-advanced" id="ip-pool-details">
          <summary><span class="domain-advanced-title" id="ip-pool-summary-label">查看池详情</span></summary>
          <div class="table-scroll" style="margin-top:8px">
            <table class="proxy-table ip-pool-table">
              <thead><tr>
                <th>出口 IP</th><th>累计次数</th><th>上限</th><th>状态</th><th>剩余有效期</th><th>占用</th>
              </tr></thead>
              <tbody id="ip-pool-body"><tr><td colspan="6" class="proxy-empty">暂无数据</td></tr></tbody>
            </table>
          </div>
        </details>
      </section>

      <section class="mail-provider-panel" aria-labelledby="ip-usage-limit-label">
        <div class="mail-provider-toolbar">
          <div class="field">
            <label for="ip-usage-limit-page" id="ip-usage-limit-label">单 IP 累计使用上限（0=不限）</label>
            <input type="number" id="ip-usage-limit-page" min="0" max="100000" value="0"
                   title="该出口 IP 在所有任务中的累计账号槽位数（成功/最终失败都计）达到此值后必须换 IP"/>
          </div>
          <div class="mail-provider-actions" style="display:inline-flex;gap:8px;align-items:center">
            <button class="primary" id="ip-usage-limit-save" onclick="saveIpUsageLimit()">保存上限</button>
            <span class="mail-provider-meta mono" id="ip-usage-limit-saved">--</span>
          </div>
        </div>
        <div class="msg" id="ip-usage-limit-msg" role="status" aria-live="polite"></div>
      </section>

      <div class="table-scroll" style="margin-top:12px">
        <table class="proxy-table ip-usage-table">
          <thead><tr>
            <th>出口 IP</th>
            <th>累计次数</th><th>上限占比</th><th>每IP上限</th><th>操作</th>
          </tr></thead>
          <tbody id="ip-usage-body"><tr><td colspan="5" class="proxy-empty">正在读取</td></tr></tbody>
        </table>
      </div>
      <div class="proxy-pagination">
        <span class="proxy-job mono" id="ip-page-status">第 1 / 1 页</span>
        <div class="proxy-page-controls">
          <label for="ip-page-size" class="proxy-job">每页</label>
          <select id="ip-page-size" onchange="changeIpPageSize(this.value)">
            <option value="25">25</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
          <button id="ip-page-prev" onclick="changeIpPage(-1)">上一页</button>
          <button id="ip-page-next" onclick="changeIpPage(1)">下一页</button>
        </div>
      </div>
    </div>
  </section>

  <section class="domain-view" id="domain-view" aria-labelledby="domain-view-title" hidden>
    <div class="domain-view-inner">
      <div class="domain-view-heading">
        <div>
          <div class="mail-source-kicker">Mail source</div>
          <div class="page-title" id="domain-view-title">邮箱服务</div>
          <p class="domain-view-subtitle" id="mail-provider-subtitle">读取当前邮箱服务配置</p>
        </div>
        <span class="domain-job" id="mail-provider-heading-label">--</span>
      </div>

      <section class="mail-provider-panel" aria-labelledby="mail-provider-label">
        <div class="mail-provider-toolbar">
          <div class="field">
            <label for="mail-provider-select" id="mail-provider-label">邮箱提供商</label>
            <select id="mail-provider-select" onchange="selectEmailProvider(this.value)">
              <option value="">正在读取</option>
            </select>
          </div>
          <div class="mail-provider-status">
            <span class="mail-provider-status-label">当前状态</span>
            <span class="badge" id="mail-provider-status" role="status" aria-live="polite">读取中</span>
          </div>
        </div>
        <div class="mail-provider-fields" id="mail-provider-fields" aria-live="polite">
          <div class="field"><label>服务配置</label><input disabled value="正在读取"/></div>
        </div>
        <div class="mail-provider-actions">
          <button class="primary" id="mail-provider-save" onclick="saveEmailProviderConfig()">保存配置</button>
          <button id="mail-provider-test" onclick="testEmailProviderConnection()">测试当前提供商</button>
          <span class="mail-provider-meta mono" id="mail-provider-updated">尚未读取</span>
        </div>
        <div class="msg mail-provider-result" id="mail-provider-msg" role="status" aria-live="polite"></div>
      </section>

      <section class="mail-provider-panel" aria-labelledby="email-profiles-label" style="margin-top:12px">
        <div class="mail-provider-toolbar" style="align-items:flex-start;flex-wrap:wrap">
          <div>
            <div class="mail-source-kicker">Multiple configs</div>
            <h2 id="email-profiles-label">多配置档（自动轮流使用）</h2>
            <p class="mail-provider-meta" style="margin:4px 0 0;max-width:560px">启用多个配置档时，注册自动按顺序轮流使用；验证码取信始终用建号时的同一档。没有配置档时使用上方的单配置。</p>
          </div>
          <div class="mail-provider-actions" style="display:inline-flex;gap:8px;align-items:center">
            <span class="badge" id="email-profiles-summary">--</span>
            <button id="email-profiles-refresh" onclick="refreshEmailProfiles(false)">刷新</button>
            <button class="primary" onclick="openEmailProfileEditor(null)">新增配置档</button>
          </div>
        </div>
        <div class="msg" id="email-profiles-msg" role="status" aria-live="polite"></div>
        <div class="table-scroll" style="margin-top:8px">
          <table class="proxy-table">
            <thead><tr><th>启用</th><th>名称</th><th>提供商</th><th>状态</th><th>操作</th></tr></thead>
            <tbody id="email-profiles-body"><tr><td colspan="5" class="proxy-empty">正在读取</td></tr></tbody>
          </table>
        </div>
        <div class="mail-provider-fields" id="email-profile-editor" hidden
             style="margin-top:10px;border:1px solid var(--border);padding:12px;border-radius:2px">
          <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
            <div class="field" style="flex:1;min-width:180px">
              <label for="email-profile-name">配置名称</label>
              <input id="email-profile-name" placeholder="如：CloudMail 主号" autocomplete="off" spellcheck="false"/>
            </div>
            <div class="field" style="flex:1;min-width:180px">
              <label for="email-profile-provider">提供商</label>
              <select id="email-profile-provider" onchange="renderEmailProfileEditorFields(this.value)">
                <option value="">--</option>
              </select>
            </div>
            <div class="mail-provider-actions" style="display:inline-flex;gap:8px;align-items:center">
              <button class="primary" onclick="saveEmailProfile()">保存配置档</button>
              <button onclick="closeEmailProfileEditor()">取消</button>
            </div>
          </div>
          <div class="mail-provider-fields" id="email-profile-fields" style="margin-top:10px"></div>
        </div>
      </section>

      <details class="domain-advanced" id="domain-advanced">
        <summary>
          <span class="domain-advanced-title">域名轮换 <span class="domain-advanced-meta">高级设置</span></span>
          <span class="domain-advanced-meta mono" id="domain-advanced-count">0 个域名</span>
        </summary>
        <div class="domain-advanced-body">
          <div class="domain-advanced-head">
            <span class="domain-advanced-meta">仅 xAI 明确拒绝域名时累计失败</span>
            <span class="domain-job mono" id="domain-updated">等待读取</span>
          </div>
          <div class="domain-summary" id="domain-summary" aria-label="邮箱域名轮换状态">
            <div class="domain-summary-item"><div class="domain-summary-label">总数</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">轮换中</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">待命</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">已拉黑</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">已停用</div><div class="domain-summary-value">--</div></div>
          </div>

          <div class="domain-import">
            <div class="field">
              <label for="domain-input">域名或子域名（每行一条）</label>
              <textarea id="domain-input" spellcheck="false" autocomplete="off" placeholder="mail.example.com&#10;inbox.example.net"></textarea>
            </div>
            <div class="domain-import-actions">
              <div class="domain-settings">
                <div class="field">
                  <label for="domain-provider">邮箱服务商</label>
                  <select id="domain-provider" onchange="selectDomainProvider(this.value)">
                    <option value="cloudflare">Cloudflare</option>
                    <option value="cloudmail">CloudMail</option>
                    <option value="moemail">MoeMail</option>
                    <option value="yyds">YYDS</option>
                  </select>
                </div>
                <div class="field">
                  <label for="domain-threshold">拒绝阈值</label>
                  <input type="number" id="domain-threshold" min="1" max="20" value="3"/>
                </div>
                <div class="field">
                  <label for="domain-max-active">每个服务商活跃数</label>
                  <input type="number" id="domain-max-active" min="0" max="100" value="0" title="0 表示不限"/>
                </div>
              </div>
              <p class="domain-format" id="domain-active-provider">正在读取当前注册服务商…</p>
              <p class="domain-format">Cloudflare、CloudMail、MoeMail 与 YYDS 可绑定自有域名；0 表示不限制活跃数。</p>
              <div class="button-group">
                <button class="primary" id="domain-import-button" onclick="importDomainInput()">导入域名</button>
                <button id="domain-settings-button" onclick="saveDomainSettings()">保存规则</button>
              </div>
            </div>
          </div>
          <div class="msg" id="domain-msg" role="status" aria-live="polite"></div>

          <div class="domain-list-section">
            <div class="domain-list-head">
              <div>
                <h2>域名明细</h2>
                <div class="domain-job mono" id="domain-status" role="status" aria-live="polite">未导入域名</div>
              </div>
              <button id="domain-refresh-button" onclick="refreshEmailDomains(false)">刷新</button>
            </div>
            <div class="domain-table-wrap">
              <table class="domain-table">
                <thead><tr><th>状态</th><th>域名</th><th>服务商</th><th>拒绝次数</th><th>最近状态</th><th>启用</th><th>操作</th></tr></thead>
                <tbody id="domain-body"><tr><td colspan="7" class="domain-empty">正在读取邮箱域名轮换</td></tr></tbody>
              </table>
            </div>
          </div>
        </div>
      </details>
    </div>
  </section>

  <section class="sso-view" id="sso-view" aria-labelledby="sso-view-title" hidden>
    <div class="sso-view-inner">
      <div class="sso-view-heading">
        <div>
          <div class="mail-source-kicker">Account state</div>
          <div class="page-title" id="sso-view-title">SSO 风控</div>
          <p class="sso-view-subtitle">用 SSO 读取 grok.com 的 botFlagSource / policy，不换 token、不入库</p>
        </div>
        <span class="sso-job mono" id="sso-heading-status">尚未扫描</span>
      </div>

      <div class="sso-summary" id="sso-summary" aria-label="SSO 风控扫描结果">
        <div class="sso-summary-item"><div class="sso-summary-label">总数</div><div class="sso-summary-value" id="sso-kpi-total">--</div></div>
        <div class="sso-summary-item"><div class="sso-summary-label">干净</div><div class="sso-summary-value ok" id="sso-kpi-clean">--</div></div>
        <div class="sso-summary-item"><div class="sso-summary-label">标记</div><div class="sso-summary-value fail" id="sso-kpi-flagged">--</div></div>
        <div class="sso-summary-item"><div class="sso-summary-label">deny</div><div class="sso-summary-value warn" id="sso-kpi-denied">--</div></div>
        <div class="sso-summary-item"><div class="sso-summary-label">失败</div><div class="sso-summary-value" id="sso-kpi-error">--</div></div>
        <div class="sso-summary-item"><div class="sso-summary-label">进度</div><div class="sso-summary-value" id="sso-kpi-progress">--</div></div>
      </div>

      <div class="sso-import">
        <div class="field">
          <label for="sso-input">SSO 列表（每行一条）</label>
          <textarea id="sso-input" spellcheck="false" autocomplete="off" placeholder="email----sso&#10;email----password----sso&#10;eyJ..."></textarea>
        </div>
        <div class="sso-import-actions">
          <div>
            <div class="sso-source-row" role="group" aria-label="数据来源">
              <button type="button" id="sso-src-paste" aria-pressed="true" onclick="setSsoSource('paste')">粘贴</button>
              <button type="button" id="sso-src-pending" aria-pressed="false" onclick="setSsoSource('pending')">待处理</button>
              <button type="button" id="sso-src-accounts" aria-pressed="false" onclick="setSsoSource('accounts')">全部账号</button>
              <button type="button" id="sso-src-risk" aria-pressed="false" onclick="setSsoSource('risk')">已隔离</button>
            </div>
            <div class="sso-settings" style="margin-top:10px">
              <div class="field">
                <label for="sso-delay">间隔秒</label>
                <input type="number" id="sso-delay" min="0" max="10" step="0.1" value="0.4"/>
              </div>
              <div class="field">
                <label for="sso-proxy">代理（可空）</label>
                <input id="sso-proxy" type="text" autocomplete="off" placeholder="沿用 config.proxy"/>
              </div>
            </div>
            <p class="sso-format" id="sso-source-hint">粘贴 JWT 或 email----sso。判定规则与注册门禁一致：botFlag 1/2 或 policy=deny 记为标记。</p>
          </div>
          <div class="button-group">
            <button class="primary" id="sso-start" onclick="startSsoScan()">开始检测</button>
            <button class="danger" id="sso-stop" onclick="stopSsoScan()">停止</button>
            <button id="sso-export-flagged" onclick="exportSsoState('flagged')">导出标记</button>
            <button id="sso-export-clean" onclick="exportSsoState('clean')">导出干净</button>
          </div>
        </div>
      </div>
      <div class="msg" id="sso-msg" role="status" aria-live="polite"></div>

      <div class="sso-list-section">
        <div class="sso-list-head">
          <div>
            <h2>检测明细</h2>
            <div class="sso-job mono" id="sso-job-status" role="status" aria-live="polite">等待开始</div>
          </div>
          <div class="sso-filter" role="group" aria-label="结果筛选">
            <button type="button" id="sso-filter-all" aria-pressed="true" onclick="setSsoFilter('all')">全部</button>
            <button type="button" id="sso-filter-flagged" aria-pressed="false" onclick="setSsoFilter('flagged')">标记</button>
            <button type="button" id="sso-filter-clean" aria-pressed="false" onclick="setSsoFilter('clean')">干净</button>
            <button type="button" id="sso-filter-error" aria-pressed="false" onclick="setSsoFilter('error')">失败</button>
          </div>
        </div>
        <div class="sso-table-wrap">
          <table class="sso-table">
            <thead><tr><th>邮箱</th><th>bot</th><th>policy</th><th>risk</th><th>event</th><th>判定</th><th>说明</th></tr></thead>
            <tbody id="sso-body"><tr><td colspan="7" class="sso-empty">粘贴 SSO 或选择库存后开始检测</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
  </section>

  <section class="metric-grid panel-gap" id="kpis" aria-label="核心指标"></section>

  <div class="two panel-gap">
    <section class="card rate-panel">
      <div class="section-head">
        <h2>时段成功率</h2>
        <span class="section-meta mono" id="rates-updated">register_results.jsonl</span>
      </div>
      <div class="rate-grid" id="rate-kpis"></div>
    </section>
    <section class="card">
      <div class="progress-head">
        <h2>当前批次</h2>
        <div class="mono" id="prog-text">--</div>
      </div>
      <div class="bar-wrap"><div class="bar" id="bar"></div></div>
      <div class="progress-sub" id="prog-sub"></div>
    </section>
  </div>

  <div class="two panel-gap">
    <details class="card recovery-panel" aria-labelledby="recovery-title">
      <summary class="panel-summary">
        <h2 id="recovery-title">账号补录</h2>
        <span class="section-meta mono" id="recovery-status">等待检查</span>
      </summary>
      <div class="recovery-layout">
        <div class="chips" id="recovery-kpis"></div>
        <div class="button-group recovery-actions">
          <button id="recovery-pending" onclick="startRecovery('pending')">补录待处理</button>
          <button id="recovery-accounts" onclick="startRecovery('accounts')">扫描全部账号</button>
          <button class="danger" id="recovery-stop" onclick="stopRecovery()">停止补录</button>
        </div>
      </div>
      <div class="msg" id="recovery-msg" role="status" aria-live="polite"></div>
      <div style="margin-top:10px;border-top:1px solid var(--border);padding-top:10px">
        <div class="domain-view-heading" style="margin-bottom:6px">
          <div>
            <div class="mail-source-kicker">Grok2API upload</div>
            <div class="page-title" style="font-size:14px">上传到 grok2api（导入 + 转 Build + 转 Console）</div>
            <p class="mail-provider-meta" style="margin:4px 0 0;max-width:560px">
              把注册产生的 Web SSO 账号批量上传到 grok2api 管理 API，自动执行转 Build / 转 Console。
              后台执行不阻塞注册。需先在 config 配置 grok2api_admin_url / user / password。
            </p>
          </div>
          <span class="domain-job mono" id="grok2api-status">--</span>
        </div>
        <div class="chips" id="grok2api-kpis"></div>
        <div class="button-group recovery-actions">
          <button id="grok2api-upload" onclick="startGrok2apiUpload()">上传到 grok2api</button>
          <button class="danger" id="grok2api-stop" onclick="stopGrok2apiUpload()">停止上传</button>
        </div>
        <div class="msg" id="grok2api-msg" role="status" aria-live="polite"></div>
      </div>
    </details>

    <section class="card panel" aria-labelledby="sso-dash-title">
      <div class="section-head">
        <h2 id="sso-dash-title">SSO 风控</h2>
        <span class="section-meta mono" id="sso-dash-status">grok.com botFlag</span>
      </div>
      <p style="margin:0 0 10px;color:var(--muted);font-size:13px;line-height:1.5">
        用 SSO 访问 grok.com，检查 <code>botFlagSource</code> / <code>policy=deny</code>，不换 token。
      </p>
      <div class="chips" id="sso-dash-kpis"></div>
      <div class="button-group" style="margin-top:10px">
        <button class="primary" onclick="toggleSsoView()">打开检测面板</button>
        <button onclick="refreshSsoState()">刷新</button>
      </div>
    </section>

    <details class="card" aria-labelledby="bfs-title">
      <summary class="panel-summary">
        <h2 id="bfs-title">BFS 检测</h2>
        <span class="section-meta mono" id="bfs-status">JWT claim</span>
      </summary>
      <p style="margin:6px 0 10px;color:var(--muted);font-size:12px;line-height:1.5">
        解码 CPA / Grok2API auth 中的 access_token，检查是否含 <code>bfs</code> claim（与 botFlagSource 独立）。
        注册换 token 后会自动检测并写入 <code>accounts/sso_bfs_flagged.txt</code>。
      </p>
      <div class="chips" id="bfs-kpis"></div>
      <div class="button-group" style="margin:10px 0 8px">
        <button id="bfs-scan" onclick="runBfsScan()">扫描 auth 目录</button>
      </div>
      <div class="msg" id="bfs-msg" role="status" aria-live="polite"></div>
      <div class="table-scroll">
        <table class="bfs-table">
          <thead><tr><th>邮箱</th><th>bfs</th><th>来源</th><th>文件</th></tr></thead>
          <tbody id="bfs-body"><tr><td colspan="4" class="proxy-empty">尚未扫描（点「扫描 auth 目录」）</td></tr></tbody>
        </table>
      </div>
    </details>
  </div>

  <details class="card panel" aria-labelledby="stats-collapse-title">
    <summary class="panel-summary">
      <h2 id="stats-collapse-title">统计明细</h2>
      <span class="section-meta mono">成功统计 · 黑名单 · 黑名单更新记录</span>
    </summary>
    <div class="three">
    <div class="card">
      <div class="section-head">
        <h2>成功统计</h2>
        <button onclick="refreshStats()">刷新</button>
      </div>
      <div class="chips" id="stats-chips"></div>
      <div class="msg" id="stats-msg" role="status" aria-live="polite"></div>
      <div class="table-scroll">
        <table><thead><tr><th>日期</th><th>成功</th><th>风控</th><th>失败</th></tr></thead>
        <tbody id="stats-day"></tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="section-head">
        <h2>黑名单</h2>
        <div class="button-group">
          <button onclick="refreshBlacklist()">刷新</button>
          <button class="danger" onclick="resetBlacklist('baseline')">重置</button>
        </div>
      </div>
      <div class="chips" id="bl-kpis"></div>
      <div class="msg" id="bl-msg" role="status" aria-live="polite"></div>
      <div class="bl-list" style="margin-top:10px">
        <table><thead><tr><th>ASN</th><th>备注</th></tr></thead><tbody id="bl-body"></tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="section-head"><h2>黑名单更新记录</h2></div>
      <div class="chips" id="bl-err-chips"></div>
      <div class="table-scroll">
        <table><thead><tr><th>新增 ASN</th><th>来源</th></tr></thead>
        <tbody id="bl-added"></tbody></table>
      </div>
    </div>
    </div>
  </details>

  <div class="two panel-gap">
    <div class="card"><h2>Worker 成功 / 失败</h2><div class="chips" id="workers-stats"></div></div>
    <div class="card"><h2>失败分类</h2><div class="chips" id="fails"></div></div>
  </div>
  <div class="two panel-gap">
    <div class="card">
      <div class="section-head"><h2>最近成功</h2></div>
      <div class="table-scroll"><table><thead><tr><th>时间</th><th>W</th><th>邮箱</th><th>IP</th></tr></thead><tbody id="ok-body"></tbody></table></div>
      <div class="proxy-pagination">
        <span class="proxy-job mono" id="ok-page-status">第 1 / 1 页</span>
        <div class="proxy-page-controls">
          <label for="ok-page-size" class="proxy-job">每页</label>
          <select id="ok-page-size" onchange="changeOkPageSize(this.value)">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
          <button id="ok-page-prev" onclick="changeOkPage(-1)">上一页</button>
          <button id="ok-page-next" onclick="changeOkPage(1)">下一页</button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="section-head"><h2>最近失败</h2></div>
      <div class="table-scroll"><table><thead><tr><th>时间</th><th>W</th><th>类型</th><th>摘要</th></tr></thead><tbody id="fail-body"></tbody></table></div>
    </div>
  </div>
  <details class="card panel" open>
    <summary class="panel-summary">
      <h2>日志尾部</h2>
      <span class="section-meta mono" id="tail-meta">实时 · 每 2 秒刷新</span>
    </summary>
    <div class="log-tools">
      <div class="field log-retention">
        <label for="log-retention-days">保留最近天数</label>
        <input type="number" id="log-retention-days" min="1" max="365" value="7"/>
      </div>
      <button class="danger" id="btn-clean-logs" onclick="cleanupLogs()">清理过期日志</button>
      <button id="tail-follow" onclick="toggleTailFollow()" aria-pressed="true" title="新日志到达时自动滚动到底部">自动滚动</button>
      <span class="log-cleanup-msg" id="log-cleanup-msg" role="status" aria-live="polite"></span>
    </div>
    <div class="tail mono" id="tail"></div>
  </details>
  <footer id="footer"></footer>
</main>
<script>
let last = null;
let fullStats = null;
let proxyData = null;
let proxyPage = 1;
let proxyPageSize = 50;
let proxyRefreshPending = false;
let proxyRefreshQueued = false;
const proxySelected = new Set();
let okPage = 1;
let okPageSize = 10;
let okItems = [];
let domainData = null;
let emailProviderData = null;
let selectedEmailProvider = "";
const clearedEmailSecrets = new Set();
let domainProviderTouched = false;
const THEME_KEY = "GROK_REGISTER_THEME";
const APP_VIEW_KEY = "GROK_REGISTER_APP_VIEW";
const HELP_TAB_KEY = "GROK_REGISTER_HELP_TAB";
let ssoSource = "paste";
let ssoFilter = "all";
let lastSsoState = null;
function syncThemeButtons() {
  const theme = document.documentElement.dataset.theme || "light";
  document.querySelectorAll("[data-theme-choice]").forEach(button => {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === theme));
  });
  const color = document.getElementById("theme-color");
  if (color) color.content = theme === "dark" ? "#171815" : "#f3f4f1";
}
function setTheme(theme) {
  if (theme !== "light" && theme !== "dark") return;
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  syncThemeButtons();
}
function setAppView(view, options = {}) {
  if (view !== "dashboard" && view !== "help" && view !== "proxies" && view !== "domains" && view !== "ip-usage" && view !== "sso") return;
  const dashboard = document.getElementById("dashboard-view");
  const help = document.getElementById("help-view");
  const proxies = document.getElementById("proxy-view");
  const domains = document.getElementById("domain-view");
  const ipUsage = document.getElementById("ip-usage-view");
  const sso = document.getElementById("sso-view");
  const domainToggle = document.getElementById("domain-view-toggle");
  const domainLabel = document.getElementById("domain-view-label");
  const toggle = document.getElementById("help-view-toggle");
  const label = document.getElementById("help-view-label");
  const proxyToggle = document.getElementById("proxy-view-toggle");
  const proxyLabel = document.getElementById("proxy-view-label");
  const ipUsageToggle = document.getElementById("ip-usage-view-toggle");
  const ipUsageLabel = document.getElementById("ip-usage-view-label");
  const ssoToggle = document.getElementById("sso-view-toggle");
  const ssoLabel = document.getElementById("sso-view-label");
  if (!dashboard || !help || !proxies || !domains || !ipUsage || !sso || !domainToggle || !domainLabel || !toggle || !label || !proxyToggle || !proxyLabel || !ipUsageToggle || !ipUsageLabel || !ssoToggle || !ssoLabel) return;
  const isHelp = view === "help";
  const isProxies = view === "proxies";
  const isDomains = view === "domains";
  const isIpUsage = view === "ip-usage";
  const isSso = view === "sso";
  const isOverlay = isHelp || isProxies || isDomains || isIpUsage || isSso;
  const dashboardChildren = Array.from(dashboard.children).filter(element => element !== help && element !== proxies && element !== domains && element !== ipUsage && element !== sso);
  dashboardChildren.forEach(element => {
    element.inert = isOverlay;
    if (isOverlay) element.setAttribute("aria-hidden", "true");
    else element.removeAttribute("aria-hidden");
  });
  help.hidden = !isHelp;
  help.inert = !isHelp;
  proxies.hidden = !isProxies;
  proxies.inert = !isProxies;
  domains.hidden = !isDomains;
  domains.inert = !isDomains;
  ipUsage.hidden = !isIpUsage;
  ipUsage.inert = !isIpUsage;
  sso.hidden = !isSso;
  sso.inert = !isSso;
  document.body.classList.toggle("help-view-open", isHelp);
  document.body.classList.toggle("proxy-view-open", isProxies);
  document.body.classList.toggle("domain-view-open", isDomains);
  document.body.classList.toggle("ip-usage-view-open", isIpUsage);
  document.body.classList.toggle("sso-view-open", isSso);
  toggle.dataset.active = String(isHelp);
  toggle.setAttribute("aria-expanded", String(isHelp));
  toggle.setAttribute("aria-label", isHelp ? "返回控制台" : "打开问题和使用");
  toggle.title = isHelp ? "返回控制台" : "问题和使用";
  label.textContent = isHelp ? "返回控制台" : "问题和使用";
  proxyToggle.dataset.active = String(isProxies);
  proxyToggle.setAttribute("aria-expanded", String(isProxies));
  proxyToggle.setAttribute("aria-label", isProxies ? "返回控制台" : "打开代理池");
  proxyToggle.title = isProxies ? "返回控制台" : "代理池";
  proxyLabel.textContent = isProxies ? "返回控制台" : "代理池";
  domainToggle.dataset.active = String(isDomains);
  domainToggle.setAttribute("aria-expanded", String(isDomains));
  domainToggle.setAttribute("aria-label", isDomains ? "返回控制台" : "打开邮箱服务");
  domainToggle.title = isDomains ? "返回控制台" : "邮箱服务";
  domainLabel.textContent = isDomains ? "返回控制台" : "邮箱服务";
  ipUsageToggle.dataset.active = String(isIpUsage);
  ipUsageToggle.setAttribute("aria-expanded", String(isIpUsage));
  ipUsageToggle.setAttribute("aria-label", isIpUsage ? "返回控制台" : "打开IP使用统计");
  ipUsageToggle.title = isIpUsage ? "返回控制台" : "IP使用统计";
  ipUsageLabel.textContent = isIpUsage ? "返回控制台" : "IP使用";
  ssoToggle.dataset.active = String(isSso);
  ssoToggle.setAttribute("aria-expanded", String(isSso));
  ssoToggle.setAttribute("aria-label", isSso ? "返回控制台" : "打开 SSO 风控");
  ssoToggle.title = isSso ? "返回控制台" : "SSO 风控";
  ssoLabel.textContent = isSso ? "返回控制台" : "SSO 风控";
  if (options.persist !== false) {
    try { localStorage.setItem(APP_VIEW_KEY, view); } catch (e) {}
  }
  if (isProxies) refreshProxies();
  if (isDomains) {
    refreshEmailProvider();
    refreshEmailDomains();
    refreshEmailProfiles();
  }
  if (isIpUsage) refreshIpUsage();
  if (isSso) refreshSsoState();
  if (options.focus) {
    requestAnimationFrame(() => {
      const target = isHelp
        ? document.querySelector('[data-help-tab][aria-selected="true"]')
        : (isProxies ? document.getElementById("proxy-input") : (isDomains ? document.getElementById("mail-provider-select") : (isIpUsage ? document.getElementById("ip-usage-limit-page") : (isSso ? document.getElementById("sso-input") : (view === "dashboard" ? domainToggle : toggle)))));
      if (target) target.focus();
    });
  }
}
function toggleAppView() {
  const isHelp = document.body.classList.contains("help-view-open");
  setAppView(isHelp ? "dashboard" : "help", { focus: true });
}
function toggleProxyView() {
  const isProxies = document.body.classList.contains("proxy-view-open");
  setAppView(isProxies ? "dashboard" : "proxies", { focus: true });
}
function toggleDomainView() {
  const isDomains = document.body.classList.contains("domain-view-open");
  setAppView(isDomains ? "dashboard" : "domains", { focus: true });
}
function toggleIpUsageView() {
  const isIpUsage = document.body.classList.contains("ip-usage-view-open");
  setAppView(isIpUsage ? "dashboard" : "ip-usage", { focus: true });
}
function toggleSsoView() {
  const isSso = document.body.classList.contains("sso-view-open");
  setAppView(isSso ? "dashboard" : "sso", { focus: true });
}
function setHelpTab(name) {
  if (name !== "guide" && name !== "faq") return;
  document.querySelectorAll("[data-help-tab]").forEach(button => {
    const selected = button.dataset.helpTab === name;
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  const guide = document.getElementById("help-guide");
  const faq = document.getElementById("help-faq");
  if (guide) guide.hidden = name !== "guide";
  if (faq) faq.hidden = name !== "faq";
  try { localStorage.setItem(HELP_TAB_KEY, name); } catch (e) {}
}
function handleHelpTabKey(event) {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  const tabs = Array.from(document.querySelectorAll("[data-help-tab]"));
  const current = tabs.indexOf(document.activeElement);
  if (current < 0) return;
  event.preventDefault();
  const next = event.key === "ArrowRight" ? (current + 1) % tabs.length : (current - 1 + tabs.length) % tabs.length;
  tabs[next].focus();
  setHelpTab(tabs[next].dataset.helpTab);
}
function filterFaq(value) {
  const query = String(value || "").trim().toLocaleLowerCase();
  const items = Array.from(document.querySelectorAll("[data-faq-item]"));
  const matches = [];
  items.forEach(item => {
    const haystack = ((item.dataset.search || "") + " " + item.textContent).toLocaleLowerCase();
    const matched = !query || haystack.includes(query);
    item.hidden = !matched;
    if (matched) matches.push(item);
  });
  if (query && matches.length === 1) matches[0].open = true;
  const count = document.getElementById("faq-count");
  const empty = document.getElementById("faq-empty");
  if (count) count.textContent = matches.length + " 项";
  if (empty) empty.hidden = matches.length > 0;
}
function showHelpFor(query) {
  setAppView("help", { focus: false });
  setHelpTab("faq");
  const search = document.getElementById("faq-search");
  if (search) search.value = query || "";
  filterFaq(query || "");
  if (search) requestAnimationFrame(() => search.focus());
}
function initHelp() {
  let view = "dashboard";
  let tab = "guide";
  try {
    view = localStorage.getItem(APP_VIEW_KEY) || "dashboard";
    tab = localStorage.getItem(HELP_TAB_KEY) || "guide";
  } catch (e) {}
  if (!["dashboard", "help", "proxies", "domains", "ip-usage", "sso"].includes(view)) view = "dashboard";
  setHelpTab(tab);
  filterFaq("");
  setAppView(view, { persist: false, focus: false });
}
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && (document.body.classList.contains("help-view-open") || document.body.classList.contains("proxy-view-open") || document.body.classList.contains("domain-view-open") || document.body.classList.contains("ip-usage-view-open") || document.body.classList.contains("sso-view-open"))) {
    setAppView("dashboard", { focus: true });
  }
});
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return Math.round(bytes) + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = bytes / 1024;
  let unit = units[0];
  for (let i = 1; i < units.length && scaled >= 1024; i += 1) {
    scaled /= 1024;
    unit = units[i];
  }
  const digits = scaled >= 100 ? 0 : (scaled >= 10 ? 1 : 2);
  return scaled.toFixed(digits) + " " + unit;
}
function setMsg(id, text, cls) {
  const el = document.getElementById(id);
  el.textContent = text || "";
  el.className = "msg" + (cls ? " " + cls : "");
  el.hidden = false;
}
function flashMsg(id, text, cls, ms) {
  // 顶部导航栏等紧凑位置的瞬时反馈：显示后自动隐藏
  setMsg(id, text, cls);
  setTimeout(() => {
    const el = document.getElementById(id);
    if (el && el.textContent === text) {
      el.textContent = "";
      el.hidden = true;
    }
  }, ms || 6000);
}
function getToken() {
  const el = document.getElementById("monitor-token");
  const fromInput = el ? (el.value || "").trim() : "";
  const tok = (fromInput || window.MONITOR_TOKEN || localStorage.getItem("MONITOR_TOKEN") || "").trim();
  if (fromInput) try { localStorage.setItem("MONITOR_TOKEN", fromInput); } catch (e) {}
  return tok;
}
function loadTokenField() {
  const el = document.getElementById("monitor-token");
  if (!el) return;
  if (!el.value) {
    try { el.value = localStorage.getItem("MONITOR_TOKEN") || window.MONITOR_TOKEN || ""; } catch (e) {}
  }
}
async function api(path, opts) {
  opts = Object.assign({}, opts || {});
  const authHelp = opts.authHelp !== false;
  delete opts.authHelp;
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  const tok = getToken();
  if (tok) headers["Authorization"] = "Bearer " + tok;
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401) {
      if (authHelp) showHelpFor("令牌");
      throw new Error("访问令牌不匹配，请重新输入当前面板令牌");
    }
    throw new Error(j.error || j.detail || r.statusText || "request failed");
  }
  if (j && j.ok === false) throw new Error(j.error || j.message || "request failed");
  return j;
}
function proxyStatusLabel(status) {
  return ({ healthy: "健康", unhealthy: "异常", cooldown: "冷却", testing: "检测中", unknown: "未检测" })[status] || "未检测";
}
function proxyTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
}
function cooldownText(item) {
  const seconds = Number(item.cooldown_remaining_seconds || 0);
  if (seconds <= 0) return "";
  const value = seconds >= 3600 ? Math.ceil(seconds / 3600) + " 小时" : Math.ceil(seconds / 60) + " 分钟";
  return (item.cooldown_reason === "risk" ? "风控冷却 " : "网络冷却 ") + value;
}
function renderProxyPool(data) {
  proxyData = data || {};
  const summary = proxyData.summary || {};
  const pagination = proxyData.pagination || { page: 1, page_size: proxyPageSize, total: summary.total || 0, pages: 1 };
  proxyPage = Number(pagination.page || 1);
  proxyPageSize = Number(pagination.page_size || proxyPageSize || 50);
  const values = [
    ["总数", summary.total ?? 0, ""],
    ["可用", summary.usable ?? 0, "ok"],
    ["异常", summary.unhealthy ?? 0, (summary.unhealthy || 0) > 0 ? "fail" : ""],
    ["冷却", summary.cooldown ?? 0, (summary.cooldown || 0) > 0 ? "warn" : ""],
    ["未检测", summary.unknown ?? 0, (summary.unknown || 0) > 0 ? "accent" : ""],
  ];
  document.getElementById("proxy-summary").innerHTML = values.map(([label, value, cls]) =>
    `<div class="proxy-summary-item"><div class="proxy-summary-label">${esc(label)}</div><div class="proxy-summary-value ${cls}">${esc(value)}</div></div>`
  ).join("");
  document.getElementById("proxy-updated").textContent = proxyData.updated_at ? ("更新 " + proxyTime(proxyData.updated_at)) : "尚未写入";

  const legacy = proxyData.legacy || {};
  const legacyButton = document.getElementById("proxy-legacy-button");
  legacyButton.disabled = !legacy.available;
  legacyButton.textContent = legacy.available ? ("导入 proxies.txt (" + (legacy.count || 0) + ")") : "无 proxies.txt";

  const job = proxyData.test_job || {};
  const testButton = document.getElementById("proxy-test-all");
  testButton.disabled = !!job.running || !(summary.enabled > 0);
  document.getElementById("proxy-test-status").textContent = job.running
    ? ("检测中 " + (job.completed || 0) + "/" + (job.total || 0)
      + "，批次 " + (job.batch_index || 1) + "/" + (job.batch_total || 1)
      + "，健康 " + (job.healthy || 0) + "，失败 " + (job.failed || 0))
    : (job.finished_at ? ("上次检测：健康 " + (job.healthy || 0) + "，失败 " + (job.failed || 0)) : "未开始检测");

  const items = proxyData.items || [];
  document.getElementById("proxy-body").innerHTML = items.length ? items.map(item => {
    const status = item.status || "unknown";
    const stateClass = ["healthy", "unhealthy", "cooldown", "testing"].includes(status) ? status : "";
    const exit = item.exit_ip ? esc(item.exit_ip) : "--";
    const asn = item.asn ? ("AS" + esc(item.asn)) : "--";
    const org = item.asn_org ? `<div class="proxy-meta">${esc(item.asn_org)}</div>` : "";
    const latency = item.latency_ms == null ? "--" : (esc(item.latency_ms) + " ms");
    const cooldown = cooldownText(item);
    const detail = cooldown || item.last_error || (item.last_checked_at ? ("检测 " + proxyTime(item.last_checked_at)) : "尚未检测");
    const count = (item.failure_count || 0) > 0 ? `<div class="proxy-meta">失败 ${esc(item.failure_count)} / 风控 ${esc(item.risk_count || 0)}</div>` : "";
    const usage = item.ip_usage == null ? "--" : `<div class="mono">${esc(item.ip_usage)}</div>`;
    return `<tr>
      <td style="text-align:center"><input class="proxy-select proxy-row-select" type="checkbox" aria-label="选择 ${esc(item.display_url || "代理")}" data-proxy-id="${item.id}" ${proxySelected.has(item.id) ? "checked" : ""} onchange="toggleProxySelection('${item.id}', this.checked)"/></td>
      <td><span class="proxy-state ${stateClass}">${esc(proxyStatusLabel(status))}</span></td>
      <td><div class="mono proxy-endpoint">${esc(item.display_url || "")}</div><div class="proxy-meta">${item.is_template ? "Resin 会话模板" : (item.has_auth ? "凭据已隐藏" : "无鉴权")} / ${esc(item.source || "panel")}</div></td>
      <td><div class="mono">${exit}</div><div class="proxy-meta mono">${asn}</div>${org}</td>
      <td>${usage}</td>
      <td class="mono">${latency}</td>
      <td title="${esc(item.last_error || "")}">${esc(detail)}${count}</td>
      <td><input class="proxy-toggle" type="checkbox" aria-label="启用 ${esc(item.display_url || "代理")}" ${item.enabled ? "checked" : ""} onchange="setProxyEnabled('${item.id}', this.checked)"/></td>
      <td><div class="proxy-actions"><button ${status === "testing" ? "disabled" : ""} onclick="testProxies('${item.id}')">检测</button><button class="danger" onclick="deleteProxyItem('${item.id}')">删除</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="9" class="proxy-empty">代理池为空，可在上方导入单条或批量代理</td></tr>';

  const pageIds = items.map(item => item.id);
  const selectedOnPage = pageIds.filter(id => proxySelected.has(id)).length;
  const selectPage = document.getElementById("proxy-select-page");
  selectPage.checked = pageIds.length > 0 && selectedOnPage === pageIds.length;
  selectPage.indeterminate = selectedOnPage > 0 && selectedOnPage < pageIds.length;
  selectPage.disabled = !pageIds.length || !!job.running;
  document.getElementById("proxy-selection-count").textContent = "已选 " + proxySelected.size;
  document.getElementById("proxy-test-selected").disabled = !proxySelected.size || !!job.running;
  document.getElementById("proxy-delete-selected").disabled = !proxySelected.size || !!job.running;
  document.getElementById("proxy-clear-selection").disabled = !proxySelected.size;
  document.getElementById("proxy-page-status").textContent =
    "第 " + pagination.page + " / " + pagination.pages + " 页，共 " + pagination.total + " 条";
  document.getElementById("proxy-page-prev").disabled = !pagination.has_previous;
  document.getElementById("proxy-page-next").disabled = !pagination.has_next;
  document.getElementById("proxy-page-size").value = String(proxyPageSize);
}
async function refreshProxies(authHelp = false) {
  if (proxyRefreshPending) {
    proxyRefreshQueued = true;
    return;
  }
  proxyRefreshPending = true;
  try {
    const data = await api(
      "/api/proxies?page=" + encodeURIComponent(proxyPage)
      + "&page_size=" + encodeURIComponent(proxyPageSize)
      + "&_=" + Date.now(),
      { authHelp }
    );
    renderProxyPool(data);
    if (!data.ok && data.error) setMsg("proxy-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("proxy-updated").textContent = message.includes("令牌") ? "等待令牌" : "读取失败";
    setMsg("proxy-msg", message, "err");
  } finally {
    proxyRefreshPending = false;
    if (proxyRefreshQueued) {
      proxyRefreshQueued = false;
      setTimeout(() => refreshProxies(false), 0);
    }
  }
}
function proxyImportMessage(result, prefix) {
  const errors = result.errors || [];
  const errorText = errors.length ? ("，跳过 " + errors.length + " 条：" + errors.slice(0, 2).map(item => "第 " + item.line + " 行 " + item.error).join("；")) : "";
  return prefix + (result.imported_count || 0) + " 条，重复 " + (result.duplicate_count || 0) + " 条" + errorText;
}
async function startImportedProxyTests(result) {
  const ids = result.imported_ids || [];
  if (!ids.length) return false;
  await api("/api/proxies/test", { method: "POST", body: JSON.stringify({ ids }) });
  return true;
}
async function importProxyInput() {
  const input = document.getElementById("proxy-input");
  const button = document.getElementById("proxy-import-button");
  const value = (input.value || "").trim();
  if (!value) { setMsg("proxy-msg", "请输入至少一条代理", "err"); input.focus(); return; }
  button.disabled = true;
  setMsg("proxy-msg", "正在导入…", "");
  try {
    const result = await api("/api/proxies/import", { method: "POST", body: JSON.stringify({ proxies: value }) });
    input.value = "";
    const testing = await startImportedProxyTests(result);
    setMsg("proxy-msg", proxyImportMessage(result, "已导入 ") + (testing ? "，已开始检测" : ""), result.errors && result.errors.length ? "" : "ok");
    proxyPage = 1;
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function importLegacyProxies() {
  const button = document.getElementById("proxy-legacy-button");
  button.disabled = true;
  try {
    const result = await api("/api/proxies/import", { method: "POST", body: JSON.stringify({ legacy: true }) });
    const testing = await startImportedProxyTests(result);
    setMsg("proxy-msg", proxyImportMessage(result, "已从 proxies.txt 导入 ") + (testing ? "，已开始检测" : ""), "ok");
    proxyPage = 1;
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function testProxies(id) {
  const ids = id ? [id] : [];
  setMsg("proxy-msg", id ? "正在检测该代理…" : "正在启动全部代理分批检测…", "");
  try {
    const result = await api("/api/proxies/test", { method: "POST", body: JSON.stringify({ ids }) });
    setMsg(
      "proxy-msg",
      "检测任务已启动，共 " + (result.total || ids.length) + " 条，"
      + (result.batch_total || 1) + " 个批次",
      "ok"
    );
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
async function testSelectedProxies() {
  const ids = [...proxySelected];
  if (!ids.length) { setMsg("proxy-msg", "请先选择代理", "err"); return; }
  setMsg("proxy-msg", "正在启动所选 " + ids.length + " 条代理检测…", "");
  try {
    const result = await api("/api/proxies/test", { method: "POST", body: JSON.stringify({ ids }) });
    setMsg(
      "proxy-msg",
      "已开始检测 " + (result.total || ids.length) + " 条，"
      + (result.batch_total || 1) + " 个批次",
      "ok"
    );
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
function toggleProxySelection(id, checked) {
  if (checked) proxySelected.add(id); else proxySelected.delete(id);
  renderProxyPool(proxyData || {});
}
function toggleProxyPageSelection(checked) {
  const items = (proxyData && proxyData.items) || [];
  items.forEach(item => checked ? proxySelected.add(item.id) : proxySelected.delete(item.id));
  renderProxyPool(proxyData || {});
}
function clearProxySelection() {
  proxySelected.clear();
  renderProxyPool(proxyData || {});
}
function changeProxyPage(delta) {
  const pagination = (proxyData && proxyData.pagination) || {};
  const next = Math.max(1, Math.min(Number(pagination.pages || 1), proxyPage + Number(delta || 0)));
  if (next === proxyPage) return;
  proxyPage = next;
  refreshProxies(false);
}
function changeProxyPageSize(value) {
  proxyPageSize = Math.max(10, Math.min(200, Number(value || 50)));
  proxyPage = 1;
  refreshProxies(false);
}
let ipUsageData = null;
let ipPage = 1;
let ipPageSize = 50;
async function refreshIpUsage(silent = true) {
  try {
    const data = await api("/api/ip-usage" + (silent ? "" : "?_=" + Date.now()));
    ipUsageData = data;
    renderIpUsage(data);
  } catch (e) {
    if (!silent) setMsg("ip-usage-limit-msg", String(e.message || e), "err");
  }
}
function changeIpPage(delta) {
  const total = (ipUsageData && ipUsageData.items || []).length;
  const pages = Math.max(1, Math.ceil(total / ipPageSize));
  const next = Math.max(1, Math.min(pages, ipPage + Number(delta || 0)));
  if (next === ipPage) return;
  ipPage = next;
  renderIpUsage(ipUsageData || {});
}
function changeIpPageSize(value) {
  ipPageSize = Math.max(10, Math.min(200, Number(value || 50)));
  ipPage = 1;
  renderIpUsage(ipUsageData || {});
}
function renderIpUsage(data) {
  const items = (data.items || []).slice();
  const limit = Number(data.limit) || 0;
  document.getElementById("ip-usage-heading-label").textContent =
    "共 " + (data.ip_count ?? 0) + " 个 IP / 累计 " + (data.total_usage ?? 0) + " 次"
    + (data.updated_at ? " / 更新 " + esc(data.updated_at) : "");
  const overCount = items.filter(it => {
    const eff = Number(it.limit_effective) || 0;
    return eff > 0 && Number(it.count) >= eff;
  }).length;
  const summaryValues = [
    ["使用过 IP 数", data.ip_count ?? 0, ""],
    ["累计使用次数", data.total_usage ?? 0, "ok"],
    ["全局上限", limit > 0 ? limit : "不限", limit > 0 ? "accent" : ""],
    ["超限 IP 数", overCount, overCount > 0 ? "fail" : ""],
  ];
  document.getElementById("ip-usage-summary").innerHTML = summaryValues.map(([label, value, cls]) =>
    `<div class="proxy-summary-item"><div class="proxy-summary-label">${esc(label)}</div><div class="proxy-summary-value ${cls}">${esc(value)}</div></div>`
  ).join("");
  const limitInput = document.getElementById("ip-usage-limit-page");
  if (limitInput && document.activeElement !== limitInput) limitInput.value = limit;
  // 客户端分页：全量计算 summary，表格只渲染当前页
  const pages = Math.max(1, Math.ceil(items.length / ipPageSize));
  ipPage = Math.max(1, Math.min(pages, ipPage));
  const pageItems = items.slice((ipPage - 1) * ipPageSize, ipPage * ipPageSize);
  const pageStatus = document.getElementById("ip-page-status");
  if (pageStatus) {
    pageStatus.textContent = "第 " + ipPage + " / " + pages + " 页，共 " + items.length + " 条";
  }
  const pagePrev = document.getElementById("ip-page-prev");
  const pageNext = document.getElementById("ip-page-next");
  if (pagePrev) pagePrev.disabled = ipPage <= 1;
  if (pageNext) pageNext.disabled = ipPage >= pages;
  document.getElementById("ip-usage-body").innerHTML = pageItems.length ? pageItems.map(it => {
    const ip = String(it.ip || "");
    const count = Number(it.count) || 0;
    const eff = Number(it.limit_effective) || 0;
    const per = it.limit != null ? Number(it.limit) : 0;
    const pct = eff > 0 ? Math.min(100, Math.round(100 * count / eff)) : 0;
    const over = eff > 0 && count >= eff;
    return `<tr>
      <td class="mono">${esc(ip)}${over ? ' <span class="badge" style="color:var(--fail);border-color:var(--danger-border);padding:1px 6px;min-height:0">超限</span>' : ""}</td>
      <td class="mono">${esc(count)}</td>
      <td style="min-width:160px">
        <div style="display:flex;align-items:center;gap:8px">
          <div class="bar-wrap" style="flex:1;min-width:90px"><div class="bar" style="width:${pct}%;${over ? "background:var(--fail)" : ""}"></div></div>
          <span class="mono" style="color:${over ? "var(--fail)" : "var(--muted)"}">${eff > 0 ? pct + "%" : "--"}</span>
        </div>
      </td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <input type="number" min="0" max="100000" value="${per}" style="width:86px"
                 title="该 IP 单独上限（0=清除覆盖，使用全局上限）"
                 data-ip-limit-input="${esc(ip)}"/>
          <button onclick="savePerIpLimit('${esc(ip)}', this)">保存</button>
        </div>
      </td>
      <td>
        <button class="danger" onclick="deleteIpUsageItem('${esc(ip)}')" title="删除该 IP 的使用记录、上限与元数据">删除</button>
      </td>
    </tr>`;
  }).join("") : '<tr><td colspan="5" class="proxy-empty">暂无使用记录（注册成功或失败后自动累计）</td></tr>';
}
async function refreshIpPool(silent) {
  try {
    const j = await api("/api/ip-pool?_=" + Date.now(), { authHelp: !silent });
    const st = j.stats || {};
    const label = document.getElementById("ip-pool-status");
    if (label) label.textContent = "可用 " + (st.usable ?? 0) + " / 总数 " + (st.total ?? 0)
      + " / 超限 " + (st.over_limit ?? 0) + " / 占用 " + (st.in_use ?? 0)
      + (j.updated_at ? " / 更新 " + esc(j.updated_at) : "");
    const rows = (j.items || []).map(it => {
      const used = Number(it.used) || 0;
      const limit = Number(it.limit) || 0;
      let state = '<span class="badge" style="color:var(--ok)">可用</span>';
      if (it.consumer) state = '<span class="badge" style="color:var(--accent)">占用中</span>';
      else if (!it.usable) state = '<span class="badge" style="color:var(--fail)">超限</span>';
      const ttl = Math.floor(Number(it.ttl_remaining) / 60) + "m" + (Number(it.ttl_remaining) % 60) + "s";
      return `<tr>
        <td class="mono">${esc(it.exit_ip || "--")}</td>
        <td class="mono">${esc(used)}</td>
        <td class="mono">${limit > 0 ? esc(limit) : "不限"}</td>
        <td>${state}</td>
        <td class="mono">${ttl}</td>
        <td class="mono">${esc(it.consumer || "--")}</td>
      </tr>`;
    }).join("");
    const body = document.getElementById("ip-pool-body");
    if (body) body.innerHTML = rows || '<tr><td colspan="6" class="proxy-empty">池为空：点击「立即探测」或等待后台补池</td></tr>';
    document.getElementById("ip-pool-summary-label").textContent = "查看池详情（" + (j.items || []).length + " 条）";
  } catch (e) {
    if (!silent) setMsg("ip-pool-msg", String(e.message || e), "err");
  }
}
async function probeIpPool() {
  const btn = document.getElementById("ip-pool-probe-btn");
  if (btn) { btn.disabled = true; btn.textContent = "探测中…"; }
  try {
    const j = await api("/api/ip-pool/probe", { method: "POST", body: "{}" });
    const st = j.stats || {};
    setMsg("ip-pool-msg", "探测完成：新增可用 " + (j.added ?? 0) + " 个，池内可用 " + (st.usable ?? 0) + " 个", "ok");
    await refreshIpPool(true);
  } catch (e) {
    setMsg("ip-pool-msg", String(e.message || e), "err");
  }
  if (btn) { btn.disabled = false; btn.textContent = "立即探测"; }
}
async function savePerIpLimit(ip, btn) {
  const input = btn.closest("div").querySelector("input[data-ip-limit-input]");
  const value = Math.max(0, Math.min(100000, Number(input.value || 0)));
  try {
    const j = await api("/api/ip-usage/limit", { method: "POST", body: JSON.stringify({ ip, limit: value }) });
    setMsg("ip-usage-limit-msg", value > 0
      ? `已设置 ${ip} 单独上限 ${value}（超出后自动换 IP）`
      : `已清除 ${ip} 的单独上限，回退全局上限`, "ok");
    await refreshIpUsage(false);
  } catch (e) {
    setMsg("ip-usage-limit-msg", String(e.message || e), "err");
  }
}
async function deleteIpUsageItem(ip) {
  if (!confirm("删除 IP " + ip + " 的使用记录？其单独上限与元数据也会一并删除。")) return;
  try {
    const j = await api("/api/ip-usage/delete", { method: "POST", body: JSON.stringify({ ip }) });
    setMsg("ip-usage-limit-msg", j.deleted ? `已删除 ${ip} 的使用记录` : `${ip} 没有使用记录`, j.deleted ? "ok" : "err");
    await refreshIpUsage(false);
  } catch (e) {
    setMsg("ip-usage-limit-msg", String(e.message || e), "err");
  }
}
async function resetIpUsage() {
  if (!confirm("清空全部 IP 使用统计？将删除所有累计次数、每 IP 上限、软拉黑与 IP 元数据（log/ip_usage.json），不可恢复。")) return;
  const btn = document.getElementById("ip-usage-reset-btn");
  if (btn) btn.disabled = true;
  try {
    const j = await api("/api/ip-usage/reset", { method: "POST" });
    setMsg("ip-usage-limit-msg", j.cleared ? "已清空全部 IP 使用统计" : "清空失败", j.cleared ? "ok" : "err");
    await refreshIpUsage(false);
    await refreshIpPool(false);
  } catch (e) {
    setMsg("ip-usage-limit-msg", String(e.message || e), "err");
  } finally {
    if (btn) btn.disabled = false;
  }
}
async function saveIpUsageLimit() {
  const input = document.getElementById("ip-usage-limit-page");
  const value = Math.max(0, Math.min(100000, Number(input.value || 0)));
  try {
    const j = await api("/api/control", { method: "POST", body: JSON.stringify({ ip_usage_limit: value }) });
    input.value = j.ip_usage_limit;
    document.getElementById("ip-usage-limit-saved").textContent = "已保存：单 IP 上限 " + (j.ip_usage_limit > 0 ? j.ip_usage_limit : "不限");
    setMsg("ip-usage-limit-msg", "上限已更新，下次槽位完成时生效", "ok");
    if (ipUsageData) renderIpUsage({ ...ipUsageData, limit: j.ip_usage_limit });
  } catch (e) {
    setMsg("ip-usage-limit-msg", String(e.message || e), "err");
  }
}
async function exportConfig() {
  setMsg("config-backup-msg", "正在导出…", "");
  try {
    const data = await api("/api/config/export?_=" + Date.now());
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    const date = new Date().toISOString().slice(0, 10);
    a.download = "grok-register-config-" + date + ".json";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    flashMsg("config-backup-msg", "已导出（含敏感凭据，请妥善保管）", "ok");
  } catch (e) {
    flashMsg("config-backup-msg", String(e.message || e), "err");
  }
}
async function importConfigFile(file) {
  if (!file) return;
  if (!confirm("导入配置将覆盖当前 config.json、代理池、邮箱域名池、邮箱多配置档、控制参数与 IP 使用限制，确定继续？")) {
    document.getElementById("config-import-file").value = "";
    return;
  }
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    const j = await api("/api/config/import", { method: "POST", body: text });
    const msg = "导入完成：" + (j.written || []).join("、")
      + (j.skipped && j.skipped.length ? "；跳过：" + j.skipped.join("、") : "")
      + "。请重启面板/注册进程生效。";
    flashMsg("config-backup-msg", msg, "ok");
  } catch (e) {
    flashMsg("config-backup-msg", "导入失败：" + String(e.message || e), "err");
  } finally {
    document.getElementById("config-import-file").value = "";
  }
}
async function setProxyEnabled(id, enabled) {
  try {
    await api("/api/proxies/" + id, { method: "PATCH", body: JSON.stringify({ enabled }) });
    setMsg("proxy-msg", enabled ? "代理已启用" : "代理已停用", "ok");
    await refreshProxies(false);
  } catch (e) {
    setMsg("proxy-msg", String(e.message || e), "err");
    await refreshProxies(false);
  }
}
async function deleteProxyItem(id) {
  const item = (proxyData && proxyData.items || []).find(value => value.id === id);
  if (!confirm("删除代理 " + (item ? item.display_url : "") + "？")) return;
  try {
    await api("/api/proxies/" + id, { method: "DELETE" });
    proxySelected.delete(id);
    setMsg("proxy-msg", "代理已删除", "ok");
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
async function deleteSelectedProxies() {
  const ids = [...proxySelected];
  if (!ids.length) { setMsg("proxy-msg", "请先选择代理", "err"); return; }
  if (!confirm("确认删除所选 " + ids.length + " 条代理？此操作无法撤销。")) return;
  setMsg("proxy-msg", "正在删除 " + ids.length + " 条代理…", "");
  try {
    const result = await api("/api/proxies/delete", {
      method: "POST",
      body: JSON.stringify({ ids }),
    });
    ids.forEach(id => proxySelected.delete(id));
    setMsg("proxy-msg", "已删除 " + (result.deleted_count || ids.length) + " 条代理", "ok");
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
function currentEmailProviderDefinition(provider = selectedEmailProvider) {
  return (emailProviderData && emailProviderData.providers || []).find(item => item.id === provider) || null;
}
function emailProviderFieldControl(field) {
  const id = "mail-field-" + field.name;
  const raw = emailProviderData && emailProviderData.values ? emailProviderData.values[field.name] : "";
  const value = raw ?? field.default ?? "";
  if (field.type === "select") {
    const options = (field.options || []).map(option => {
      const optionValue = typeof option === "object" ? option.value : option;
      const optionLabel = typeof option === "object" ? option.label : option;
      return `<option value="${esc(optionValue)}" ${String(optionValue) === String(value) ? "selected" : ""}>${esc(optionLabel)}</option>`;
    }).join("");
    return `<select id="${esc(id)}" data-mail-field="${esc(field.name)}">${options}</select>`;
  }
  const isSecret = field.secret === true;
  const configured = isSecret && emailProviderData && emailProviderData.secret_configured && emailProviderData.secret_configured[field.name];
  const placeholder = configured ? "已配置，留空保留" : (field.placeholder || "");
  const type = isSecret ? "password" : (["url", "email"].includes(field.type) ? field.type : "text");
  const input = `<input id="${esc(id)}" data-mail-field="${esc(field.name)}" type="${type}" value="${isSecret ? "" : esc(value)}" placeholder="${esc(placeholder)}" autocomplete="${isSecret ? "new-password" : "off"}" spellcheck="false" ${isSecret ? `oninput="emailProviderSecretInput('${field.name}')"` : ""}/>`;
  if (!isSecret) return input;
  const clear = configured ? `<button type="button" data-mail-secret-button="${esc(field.name)}" onclick="toggleEmailProviderSecret('${field.name}')">清除</button>` : "";
  const note = configured ? "已保存密钥" : "尚未配置";
  return `<div class="mail-secret-wrap" data-mail-secret-wrap="${esc(field.name)}">${input}${clear}</div><div class="mail-secret-note" data-mail-secret-note="${esc(field.name)}">${note}</div>`;
}
function renderEmailProviderFields(provider) {
  const definition = currentEmailProviderDefinition(provider);
  if (!definition) return;
  selectedEmailProvider = definition.id;
  clearedEmailSecrets.clear();
  const select = document.getElementById("mail-provider-select");
  if (select) select.value = definition.id;
  document.getElementById("mail-provider-heading-label").textContent = definition.label;
  const persisted = emailProviderData && emailProviderData.provider === definition.id;
  document.getElementById("mail-provider-subtitle").textContent = persisted
    ? ("当前注册任务使用 " + definition.label)
    : ("待切换到 " + definition.label);
  const status = document.getElementById("mail-provider-status");
  status.textContent = definition.configured ? "已配置" : "待配置";
  status.className = "badge " + (definition.configured ? "ok" : "warn");
  document.getElementById("mail-provider-fields").innerHTML = (definition.fields || []).map(field =>
    `<div class="field"><label for="mail-field-${esc(field.name)}">${esc(field.label)}</label>${emailProviderFieldControl(field)}</div>`
  ).join("") || '<div class="field"><label>服务配置</label><input disabled value="该服务商没有可编辑字段"/></div>';
  const domainProvider = document.getElementById("domain-provider");
  if (domainProvider && ["cloudflare", "cloudmail", "moemail", "yyds"].includes(definition.id)) {
    domainProvider.value = definition.id;
    if (domainData) renderEmailDomainPool(domainData);
  }
}
function renderEmailProviderConfig(data) {
  emailProviderData = data || {};
  const select = document.getElementById("mail-provider-select");
  const providers = emailProviderData.providers || [];
  select.innerHTML = providers.map(provider =>
    `<option value="${esc(provider.id)}">${esc(provider.label)}</option>`
  ).join("");
  const provider = providers.some(item => item.id === emailProviderData.provider)
    ? emailProviderData.provider
    : (providers[0] && providers[0].id || "");
  const updated = emailProviderData.mtime ? new Date(emailProviderData.mtime * 1000) : null;
  document.getElementById("mail-provider-updated").textContent = updated && !Number.isNaN(updated.getTime())
    ? ("config.json " + updated.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }))
    : "config.json 尚未创建";
  renderEmailProviderFields(provider);
}
function selectEmailProvider(provider) {
  renderEmailProviderFields(provider);
  setMsg("mail-provider-msg", "", "");
}
function toggleEmailProviderSecret(name) {
  const clearing = !clearedEmailSecrets.has(name);
  if (clearing) clearedEmailSecrets.add(name);
  else clearedEmailSecrets.delete(name);
  const wrap = document.querySelector(`[data-mail-secret-wrap="${name}"]`);
  const button = document.querySelector(`[data-mail-secret-button="${name}"]`);
  const note = document.querySelector(`[data-mail-secret-note="${name}"]`);
  if (wrap) wrap.classList.toggle("pending-clear", clearing);
  if (button) button.textContent = clearing ? "撤销" : "清除";
  if (note) {
    note.textContent = clearing ? "保存后清除密钥" : "已保存密钥";
    note.className = "mail-secret-note" + (clearing ? " warn" : "");
  }
}
function emailProviderSecretInput(name) {
  const input = document.getElementById("mail-field-" + name);
  if (input && input.value && clearedEmailSecrets.has(name)) toggleEmailProviderSecret(name);
}
function collectEmailProviderSettings() {
  const definition = currentEmailProviderDefinition();
  const settings = {};
  (definition && definition.fields || []).forEach(field => {
    const input = document.getElementById("mail-field-" + field.name);
    if (!input) return;
    settings[field.name] = field.name === "moemail_expiry_ms" ? Number(input.value) : input.value;
  });
  return settings;
}
async function refreshEmailProvider(authHelp = false) {
  try {
    const data = await api("/api/email-provider?_=" + Date.now(), { authHelp });
    renderEmailProviderConfig(data);
    if (!data.ok && data.error) setMsg("mail-provider-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("mail-provider-heading-label").textContent = message.includes("令牌") ? "等待令牌" : "读取失败";
    setMsg("mail-provider-msg", message, "err");
  }
}
let emailProfilesData = null;
let editingEmailProfileId = null;
async function refreshEmailProfiles(authHelp = false) {
  try {
    const data = await api("/api/email-profiles?_=" + Date.now(), { authHelp });
    emailProfilesData = data;
    renderEmailProfiles(data);
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("email-profiles-summary").textContent = "读取失败";
    document.getElementById("email-profiles-body").innerHTML = '<tr><td colspan="5" class="proxy-empty">读取失败</td></tr>';
    setMsg("email-profiles-msg", message, "err");
  }
}
function renderEmailProfiles(data) {
  const profiles = data.profiles || [];
  const summary = data.summary || {};
  document.getElementById("email-profiles-summary").textContent =
    "共 " + (summary.total ?? 0) + " 档 / 启用 " + (summary.enabled ?? 0);
  document.getElementById("email-profiles-body").innerHTML = profiles.length ? profiles.map(p => {
    const configured = p.configured ? "已配置" : "缺字段";
    const detail = p.configured
      ? (Object.keys(p.values || {}).filter(n => p.values[n] !== "" && p.values[n] != null).length + " 项已填")
      : (p.secret_configured && Object.values(p.secret_configured).some(Boolean) ? "密钥已存" : "未配置");
    return `<tr>
      <td><input class="domain-toggle" type="checkbox" aria-label="启用 ${esc(p.name)}" ${p.enabled ? "checked" : ""} onchange="setEmailProfileEnabled('${esc(p.id)}', this.checked)"/></td>
      <td><div style="font-weight:560">${esc(p.name)}</div><div class="domain-meta">${esc(p.provider_label)} · ${esc(detail)}</div></td>
      <td>${esc(p.provider_label)}</td>
      <td><span class="badge ${p.configured ? "ok" : "warn"}">${esc(configured)}</span></td>
      <td><div class="proxy-actions">
        <button onclick="openEmailProfileEditor('${esc(p.id)}')">编辑</button>
        <button onclick="testEmailProfile('${esc(p.id)}')">测试</button>
        <button class="danger" onclick="deleteEmailProfile('${esc(p.id)}')">删除</button>
      </div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="5" class="proxy-empty">暂无配置档（启用多个配置档后，注册自动轮流使用）</td></tr>';
}
function openEmailProfileEditor(profileId) {
  editingEmailProfileId = profileId || null;
  const editor = document.getElementById("email-profile-editor");
  const select = document.getElementById("email-profile-provider");
  select.innerHTML = (emailProviderData && emailProviderData.providers || []).map(p =>
    `<option value="${esc(p.id)}">${esc(p.label)}</option>`
  ).join("");
  const profile = profileId ? (emailProfilesData && emailProfilesData.profiles || []).find(p => p.id === profileId) : null;
  document.getElementById("email-profile-name").value = profile ? profile.name : "";
  select.value = profile ? profile.provider : (emailProviderData && emailProviderData.provider || "");
  renderEmailProfileEditorFields(select.value, profile);
  editor.hidden = false;
  editor.scrollIntoView({ behavior: "smooth", block: "nearest" });
}
function renderEmailProfileEditorFields(provider, profile) {
  const definition = (emailProviderData && emailProviderData.providers || []).find(p => p.id === provider);
  const container = document.getElementById("email-profile-fields");
  if (!definition) { container.innerHTML = ""; return; }
  const values = (profile && profile.values) || {};
  const secretCfg = (profile && profile.secret_configured) || {};
  container.innerHTML = (definition.fields || []).map(field => {
    const name = field.name;
    const value = values[name] ?? "";
    const isSecret = field.secret === true;
    const configured = isSecret && secretCfg[name];
    let control;
    if (field.type === "select") {
      const options = (field.options || []).map(option => {
        const optionValue = typeof option === "object" ? option.value : option;
        const optionLabel = typeof option === "object" ? option.label : option;
        return `<option value="${esc(optionValue)}" ${String(optionValue) === String(value) ? "selected" : ""}>${esc(optionLabel)}</option>`;
      }).join("");
      control = `<select id="profile-field-${esc(name)}" data-profile-field="${esc(name)}">${options}</select>`;
    } else {
      const placeholder = configured ? "已配置，留空保留" : (field.placeholder || "");
      const type = isSecret ? "password" : (["url", "email"].includes(field.type) ? field.type : "text");
      control = `<input id="profile-field-${esc(name)}" data-profile-field="${esc(name)}" type="${type}" value="${isSecret ? "" : esc(value)}" placeholder="${esc(placeholder)}" autocomplete="${isSecret ? "new-password" : "off"}" spellcheck="false"/>`;
    }
    return `<div class="field"><label for="profile-field-${esc(name)}">${esc(field.label)}</label>${control}</div>`;
  }).join("") || '<div class="field"><label>该服务商没有可编辑字段</label></div>';
}
function collectEmailProfileFields() {
  const fields = {};
  document.querySelectorAll("#email-profile-fields [data-profile-field]").forEach(input => {
    fields[input.dataset.profileField] = input.value;
  });
  return fields;
}
async function saveEmailProfile() {
  const provider = document.getElementById("email-profile-provider").value;
  if (!provider) { setMsg("email-profiles-msg", "请先选择提供商", "err"); return; }
  try {
    const result = await api("/api/email-profiles", { method: "POST", body: JSON.stringify({
      provider,
      name: document.getElementById("email-profile-name").value,
      fields: collectEmailProfileFields(),
      profile_id: editingEmailProfileId || undefined,
    }) });
    setMsg("email-profiles-msg", "配置档「" + result.profile.name + "」已保存", "ok");
    closeEmailProfileEditor();
    await refreshEmailProfiles(false);
  } catch (e) { setMsg("email-profiles-msg", String(e.message || e), "err"); }
}
async function setEmailProfileEnabled(profileId, enabled) {
  try {
    await api("/api/email-profiles/enabled", { method: "POST", body: JSON.stringify({ profile_id: profileId, enabled }) });
    setMsg("email-profiles-msg", enabled ? "配置档已启用" : "配置档已停用", "ok");
    await refreshEmailProfiles(false);
  } catch (e) {
    setMsg("email-profiles-msg", String(e.message || e), "err");
    await refreshEmailProfiles(false);
  }
}
async function deleteEmailProfile(profileId) {
  const p = (emailProfilesData && emailProfilesData.profiles || []).find(x => x.id === profileId);
  if (!confirm("删除配置档「" + (p ? p.name : profileId) + "」？")) return;
  try {
    await api("/api/email-profiles/delete", { method: "POST", body: JSON.stringify({ profile_id: profileId }) });
    setMsg("email-profiles-msg", "配置档已删除", "ok");
    if (editingEmailProfileId === profileId) closeEmailProfileEditor();
    await refreshEmailProfiles(false);
  } catch (e) { setMsg("email-profiles-msg", String(e.message || e), "err"); }
}
async function testEmailProfile(profileId) {
  const p = (emailProfilesData && emailProfilesData.profiles || []).find(x => x.id === profileId);
  setMsg("email-profiles-msg", "正在测试「" + (p ? p.name : "") + "」…", "");
  try {
    const result = await api("/api/email-profiles/test", { method: "POST", body: JSON.stringify({ profile_id: profileId }) });
    setMsg("email-profiles-msg", result.detail || "连接正常", result.ok ? "ok" : "err");
  } catch (e) { setMsg("email-profiles-msg", String(e.message || e), "err"); }
}
function closeEmailProfileEditor() {
  document.getElementById("email-profile-editor").hidden = true;
  editingEmailProfileId = null;
}
async function saveEmailProviderConfig() {
  const button = document.getElementById("mail-provider-save");
  button.disabled = true;
  setMsg("mail-provider-msg", "正在保存…", "");
  try {
    const result = await api("/api/email-provider", { method: "POST", body: JSON.stringify({
      provider: selectedEmailProvider,
      settings: collectEmailProviderSettings(),
      clear_secrets: Array.from(clearedEmailSecrets),
    }) });
    renderEmailProviderConfig(result);
    setMsg("mail-provider-msg", result.provider_label + " 配置已保存", "ok");
  } catch (e) { setMsg("mail-provider-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function testEmailProviderConnection() {
  const button = document.getElementById("mail-provider-test");
  button.disabled = true;
  setMsg("mail-provider-msg", "正在测试连通性…", "");
  try {
    const result = await api("/api/email-provider/test", { method: "POST", body: JSON.stringify({
      provider: selectedEmailProvider,
      settings: collectEmailProviderSettings(),
      clear_secrets: Array.from(clearedEmailSecrets),
    }) });
    setMsg("mail-provider-msg", result.detail || "连接正常", "ok");
  } catch (e) { setMsg("mail-provider-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
function domainStatusLabel(status) {
  return ({ active: "轮换中", standby: "待命", blocked: "已拉黑", disabled: "已停用" })[status] || "待命";
}
function selectDomainProvider(value) {
  domainProviderTouched = true;
  if (domainData) renderEmailDomainPool(domainData);
}
function renderEmailDomainPool(data) {
  domainData = data || {};
  const summary = domainData.summary || {};
  const values = [
    ["总数", summary.total ?? 0, ""],
    ["轮换中", summary.active ?? 0, "ok"],
    ["待命", summary.standby ?? 0, (summary.standby || 0) > 0 ? "accent" : ""],
    ["已拉黑", summary.blocked ?? 0, (summary.blocked || 0) > 0 ? "fail" : ""],
    ["已停用", summary.disabled ?? 0, (summary.disabled || 0) > 0 ? "warn" : ""],
  ];
  document.getElementById("domain-summary").innerHTML = values.map(([label, value, cls]) =>
    `<div class="domain-summary-item"><div class="domain-summary-label">${esc(label)}</div><div class="domain-summary-value ${cls}">${esc(value)}</div></div>`
  ).join("");
  document.getElementById("domain-advanced-count").textContent = (summary.total ?? 0) + " 个域名";
  document.getElementById("domain-updated").textContent = domainData.updated_at ? ("更新 " + proxyTime(domainData.updated_at)) : "尚未写入";
  const settings = domainData.settings || {};
  const focused = document.activeElement && ["domain-threshold", "domain-max-active"].includes(document.activeElement.id);
  if (!focused) {
    document.getElementById("domain-threshold").value = settings.failure_threshold ?? 3;
    document.getElementById("domain-max-active").value = settings.max_active_domains ?? 0;
  }
  const providerSelect = document.getElementById("domain-provider");
  if (!domainProviderTouched && domainData.active_provider) {
    providerSelect.value = domainData.active_provider;
  }
  const provider = providerSelect.value || "cloudflare";
  const activeProvider = domainData.active_provider || "";
  const activeLabel = domainData.active_provider_label || activeProvider || "未识别";
  document.getElementById("domain-active-provider").textContent =
    "当前注册实际使用：" + activeLabel
    + (provider !== activeProvider ? "；当前下拉框不是运行服务商，请确认后再导入" : "；导入到这里的域名会参与轮换");
  const providerLabel = domainData.provider_labels && domainData.provider_labels[provider] || provider;
  const providerCount = domainData.providers && domainData.providers[provider] || 0;
  document.getElementById("domain-status").textContent = providerCount
    ? (providerLabel + " 已配置 " + providerCount + " 个域名")
    : "尚未导入当前服务商域名";
  const items = domainData.items || [];
  document.getElementById("domain-body").innerHTML = items.length ? items.map(item => {
    const status = item.status || "standby";
    const stateClass = ["active", "standby", "blocked", "disabled"].includes(status) ? status : "standby";
    const threshold = item.failure_threshold || settings.failure_threshold || 3;
    const rejected = Number(item.consecutive_rejections || 0);
    const total = Number(item.total_rejections || 0);
    const counts = `${rejected}/${threshold}<div class="domain-meta">累计 ${total} / 成功 ${Number(item.success_count || 0)}</div>`;
    const latest = item.last_error || (item.last_rejected_at ? ("拒绝 " + proxyTime(item.last_rejected_at)) : (item.last_success_at ? ("接受 " + proxyTime(item.last_success_at)) : "暂无结果"));
    const resetButton = rejected > 0 || status === "blocked" ? `<button onclick="resetEmailDomain('${item.id}')">重置</button>` : "";
    return `<tr>
      <td><span class="domain-state ${stateClass}">${esc(domainStatusLabel(status))}</span></td>
      <td><div class="mono domain-name">${esc(item.domain)}</div><div class="domain-meta">${esc(item.source || "panel")}</div></td>
      <td>${esc(item.provider_label || item.provider || "")}</td>
      <td class="mono">${counts}</td>
      <td title="${esc(item.last_error || "")}">${esc(latest)}</td>
      <td><input class="domain-toggle" type="checkbox" aria-label="启用 ${esc(item.domain)}" ${item.enabled ? "checked" : ""} onchange="setEmailDomainEnabled('${item.id}', this.checked)"/></td>
      <td><div class="domain-actions">${resetButton}<button class="danger" onclick="deleteEmailDomain('${item.id}')">删除</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="7" class="domain-empty">域名池为空，可在上方导入自有域名或子域名</td></tr>';
}
async function refreshEmailDomains(authHelp = false) {
  try {
    const data = await api("/api/email-domains?_=" + Date.now(), { authHelp });
    renderEmailDomainPool(data);
    if (!data.ok && data.error) setMsg("domain-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("domain-updated").textContent = message.includes("令牌") ? "等待令牌" : "读取失败";
    setMsg("domain-msg", message, "err");
  }
}
function domainImportMessage(result) {
  const errors = result.errors || [];
  const errorText = errors.length ? ("，跳过 " + errors.length + " 条：" + errors.slice(0, 2).map(item => "第 " + item.line + " 行 " + item.error).join("；")) : "";
  return "已导入 " + (result.imported_count || 0) + " 个域名，重复 " + (result.duplicate_count || 0) + " 个" + errorText;
}
async function importDomainInput() {
  const input = document.getElementById("domain-input");
  const button = document.getElementById("domain-import-button");
  const value = (input.value || "").trim();
  if (!value) { setMsg("domain-msg", "请输入至少一个域名", "err"); input.focus(); return; }
  const selectedProvider = document.getElementById("domain-provider").value;
  const activeProvider = domainData && domainData.active_provider;
  if (activeProvider && selectedProvider !== activeProvider) {
    const selectedLabel = domainData.provider_labels && domainData.provider_labels[selectedProvider] || selectedProvider;
    const activeLabel = domainData.active_provider_label || activeProvider;
    if (!confirm("当前注册使用 " + activeLabel + "，你选择的是 " + selectedLabel + "。仍要导入吗？")) return;
  }
  button.disabled = true;
  setMsg("domain-msg", "正在导入…", "");
  try {
    const result = await api("/api/email-domains/import", { method: "POST", body: JSON.stringify({ domains: value, provider: document.getElementById("domain-provider").value }) });
    renderEmailDomainPool(result);
    input.value = "";
    setMsg("domain-msg", domainImportMessage(result), result.errors && result.errors.length ? "" : "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function saveDomainSettings() {
  const button = document.getElementById("domain-settings-button");
  button.disabled = true;
  try {
    const result = await api("/api/email-domains/settings", { method: "POST", body: JSON.stringify({
      failure_threshold: Number(document.getElementById("domain-threshold").value || 3),
      max_active_domains: Number(document.getElementById("domain-max-active").value || 0),
    }) });
    renderEmailDomainPool(result);
    setMsg("domain-msg", "域名池规则已保存", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function setEmailDomainEnabled(id, enabled) {
  try {
    const result = await api("/api/email-domains/" + id, { method: "PATCH", body: JSON.stringify({ enabled }) });
    renderEmailDomainPool(result);
    setMsg("domain-msg", enabled ? "域名已启用" : "域名已停用", "ok");
  } catch (e) {
    setMsg("domain-msg", String(e.message || e), "err");
    await refreshEmailDomains(false);
  }
}
async function resetEmailDomain(id) {
  try {
    const result = await api("/api/email-domains/reset", { method: "POST", body: JSON.stringify({ id }) });
    renderEmailDomainPool(result);
    setMsg("domain-msg", "域名失败计数已重置", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
}
async function deleteEmailDomain(id) {
  const item = (domainData && domainData.items || []).find(value => value.id === id);
  if (!confirm("删除域名 " + (item ? item.domain : "") + "？")) return;
  try {
    const result = await api("/api/email-domains/" + id, { method: "DELETE" });
    renderEmailDomainPool(result);
    setMsg("domain-msg", "域名已删除", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
}
async function refresh() {
  try {
    const d = await api("/api/status?_=" + Date.now(), { authHelp: false });
    last = d;
    render(d);
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("clock").textContent = message.includes("令牌") ? "需要令牌" : "连接异常";
    const sync = document.getElementById("sync-label");
    if (sync) {
      sync.textContent = message.includes("令牌") ? "等待令牌" : "更新失败";
      sync.className = "badge fail";
    }
    if (message.includes("令牌")) setMsg("ctrl-msg", message, "err");
  }
}
function syncIpPolicyUi() {
  // 已无开关：每 IP 账号数=0 表示不限，连续失败换 IP 始终生效。
  const countInput = document.getElementById("accounts_per_ip");
  const failureInput = document.getElementById("ip_failure_rotate_threshold");
  if (countInput) countInput.disabled = false;
  if (failureInput) failureInput.disabled = false;
}
function fillControl(d) {
  const c = d.control || {};
  if (document.activeElement && ["workers-input","batch_count","add_count","risk_pause","accounts_per_ip","ip_failure_rotate_threshold","ip_usage_limit","mode"].includes(document.activeElement.id)) return;
  if (c.workers != null) document.getElementById("workers-input").value = c.workers;
  if (c.batch_count != null) document.getElementById("batch_count").value = c.batch_count;
  if (c.add_count != null && document.getElementById("add_count")) document.getElementById("add_count").value = c.add_count;
  if (c.risk_pause != null) document.getElementById("risk_pause").value = c.risk_pause;
  if (c.accounts_per_ip != null) document.getElementById("accounts_per_ip").value = c.accounts_per_ip;
  if (c.ip_failure_rotate_threshold != null) document.getElementById("ip_failure_rotate_threshold").value = c.ip_failure_rotate_threshold;
  if (c.ip_usage_limit != null && document.getElementById("ip_usage_limit")) document.getElementById("ip_usage_limit").value = c.ip_usage_limit;
  if (c.mode) document.getElementById("mode").value = c.mode;
  syncIpPolicyUi();
}
function controlBody() {
  return {
    workers: Number(document.getElementById("workers-input").value || 3),
    batch_count: Number(document.getElementById("batch_count").value || 40),
    add_count: Number((document.getElementById("add_count") || {}).value || 40),
    risk_pause: Number(document.getElementById("risk_pause").value || 10),
    accounts_per_ip: Number(document.getElementById("accounts_per_ip").value || 0),
    ip_failure_rotate_threshold: Number(document.getElementById("ip_failure_rotate_threshold").value || 3),
    ip_usage_limit: Number((document.getElementById("ip_usage_limit") || {}).value || 0),
    mode: document.getElementById("mode").value || "orch",
  };
}
async function saveCtrl() {
  try {
    const j = await api("/api/control", { method: "POST", body: JSON.stringify(controlBody()) });
    setMsg("ctrl-msg", "设置已保存，并发数 " + j.workers, "ok");
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
}
async function doStart() {
  document.getElementById("btn-start").disabled = true;
  setMsg("ctrl-msg", "正在启动…", "");
  try {
    await api("/api/control", { method: "POST", body: JSON.stringify(controlBody()) });
    const j = await api("/api/start", { method: "POST", body: JSON.stringify(controlBody()) });
    if (j.ok === false) throw new Error(j.error || "start failed");
    const msg = j.message || ("已启动，进程 " + (j.pid || "?") + "，模式 " + (j.mode || ""));
    setMsg("ctrl-msg", msg + (j.need != null ? "，剩余 " + j.need : ""), "ok");
    setTimeout(refresh, 1000);
    setTimeout(refresh, 3000);
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
  document.getElementById("btn-start").disabled = false;
}
async function doStop() {
  document.getElementById("btn-stop").disabled = true;
  try {
    const j = await api("/api/stop", { method: "POST", body: "{}" });
    const count = (j.killed || []).length;
    setMsg("ctrl-msg", count ? ("任务已停止，共结束 " + count + " 个主进程") : "当前没有运行中的任务", "ok");
    await refresh();
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
  document.getElementById("btn-stop").disabled = false;
}
let tailFollow = true;
function toggleTailFollow() {
  tailFollow = !tailFollow;
  const btn = document.getElementById("tail-follow");
  if (btn) btn.setAttribute("aria-pressed", String(tailFollow));
  if (tailFollow) {
    const tail = document.getElementById("tail");
    if (tail) tail.scrollTop = tail.scrollHeight;
  }
}
function bindTailFollow() {
  const tail = document.getElementById("tail");
  if (!tail || tail._followBound) return;
  tail._followBound = true;
  tail.addEventListener("scroll", () => {
    // 用户手动上滚时自动关闭跟随，避免新日志强行拉回底部
    if (tailFollow && tail.scrollHeight - tail.scrollTop - tail.clientHeight > 24) {
      tailFollow = false;
      const btn = document.getElementById("tail-follow");
      if (btn) btn.setAttribute("aria-pressed", "false");
    }
  });
}
async function cleanupLogs() {
  const days = Number(document.getElementById("log-retention-days").value || 7);
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    setMsg("log-cleanup-msg", "保留天数必须是 1-365 的整数", "err");
    return;
  }
  if (!confirm("删除 " + days + " 天以前的运行日志？状态文件和最新日志会保留。")) return;
  const button = document.getElementById("btn-clean-logs");
  button.disabled = true;
  setMsg("log-cleanup-msg", "正在清理…", "");
  try {
    const result = await api("/api/logs/cleanup", {
      method: "POST",
      body: JSON.stringify({ retention_days: days }),
    });
    const size = Number(result.freed_bytes || 0);
    const readable = size >= 1048576
      ? (size / 1048576).toFixed(1) + " MB"
      : (size / 1024).toFixed(1) + " KB";
    setMsg(
      "log-cleanup-msg",
      "已删除 " + Number(result.deleted_count || 0) + " 个日志，释放 " + readable,
      result.errors && result.errors.length ? "err" : "ok"
    );
    await refresh();
  } catch (e) {
    setMsg("log-cleanup-msg", String(e.message || e), "err");
  }
  button.disabled = false;
}
async function resetBlacklist(mode) {
  mode = mode || "baseline";
  if (!confirm(mode === "empty" ? "清空全部黑名单？" : "重置为基线熔断？")) return;
  try {
    const j = await api("/api/blacklist/reset", { method: "POST", body: JSON.stringify({ mode }) });
    setMsg("bl-msg", j.message || "已重置", "ok");
    setTimeout(refresh, 500);
  } catch (e) { setMsg("bl-msg", String(e.message || e), "err"); }
}
async function refreshBlacklist() {
  try {
    const j = await api("/api/blacklist?_=" + Date.now());
    renderBlacklist(j, last && last.blacklist_update);
    setMsg("bl-msg", "已刷新 / " + (j.mtime_human || "") + " / " + (j.count || 0) + " ASN", "ok");
  } catch (e) { setMsg("bl-msg", String(e.message || e), "err"); }
}
async function refreshStats(authHelp = true) {
  try {
    const j = await api("/api/stats?_=" + Date.now(), { authHelp });
    fullStats = j;
    renderStats(fullStats);
    setMsg("stats-msg", "统计已刷新 " + (j.refreshed_at || ""), "ok");
  } catch (e) { setMsg("stats-msg", String(e.message || e), "err"); }
}
function renderRecovery(data) {
  data = data || {};
  const report = data.last_report || {};
  document.getElementById("recovery-kpis").innerHTML = [
    ["待处理", data.pending_count ?? 0, (data.pending_count || 0) > 0 ? "warn" : "ok"],
    ["账号记录", data.account_record_count ?? 0, ""],
    ["可补录", data.recoverable_count ?? 0, (data.recoverable_count || 0) > 0 ? "accent" : "ok"],
    ["上次成功", report.success_count ?? "--", "ok"],
    ["上次失败", report.failure_count ?? "--", (report.failure_count || 0) > 0 ? "fail" : ""],
  ].map(([label, value, cls]) => `<div class="chip"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`).join("");
  document.getElementById("recovery-status").textContent = data.running ? ("补录中 #" + (data.pid || "?")) : "空闲";
  document.getElementById("recovery-pending").disabled = !!data.running || !(data.pending_count > 0);
  document.getElementById("recovery-accounts").disabled = !!data.running || !(data.recoverable_count > 0);
  document.getElementById("recovery-stop").disabled = !data.running;
}
async function refreshRecovery() {
  try {
    const data = await api("/api/recovery?_=" + Date.now(), { authHelp: false });
    renderRecovery(data);
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("recovery-status").textContent = message.includes("令牌") ? "等待令牌" : "检查失败";
  }
}
async function startRecovery(scope) {
  if (scope === "accounts" && !confirm("扫描全部账号文本并补录缺失 CPA？此操作可能持续较长时间。")) return;
  setMsg("recovery-msg", "正在启动补录…", "");
  try {
    const data = await api("/api/recovery/start", { method: "POST", body: JSON.stringify({ scope }) });
    setMsg("recovery-msg", "补录已启动，共 " + (data.input_count || 0) + " 条", "ok");
    await refreshRecovery();
  } catch (e) { setMsg("recovery-msg", String(e.message || e), "err"); }
}
async function stopRecovery() {
  try {
    const data = await api("/api/recovery/stop", { method: "POST", body: "{}" });
    setMsg("recovery-msg", "补录已停止，结束进程 " + JSON.stringify(data.killed || []), "ok");
    await refreshRecovery();
  } catch (e) { setMsg("recovery-msg", String(e.message || e), "err"); }
}
function renderGrok2api(data) {
  data = data || {};
  const report = data.last_report || {};
  const imported = report.imported || {};
  const converted = report.converted || {};
  const synced = report.synced || {};
  const statusEl = document.getElementById("grok2api-status");
  if (!statusEl) return;
  statusEl.textContent = data.running
    ? "上传中 #" + (data.pid || "?")
    : (data.configured ? "已配置（空闲）" : "未配置服务地址");
  const kpis = [
    ["配置", data.configured ? "就绪" : "未配置", data.configured ? "ok" : "warn"],
    ["上次导入", report.ok ? ((imported.created ?? 0) + " 新 / " + (imported.skipped ?? 0) + " 跳过") : "--", report.ok ? "ok" : ""],
    ["转 Build", report.ok ? ((converted.created ?? 0) + " 建 / " + (converted.skipped ?? 0) + " 跳过") : "--", report.ok ? "accent" : ""],
    ["转 Console", report.ok ? ((synced.created ?? 0) + " 建 / " + (synced.syncFailed ?? 0) + " 失败") : "--", report.ok ? "accent" : ""],
    ["账号总数", report.total_accounts ?? "--", ""],
  ];
  const el = document.getElementById("grok2api-kpis");
  if (el) el.innerHTML = kpis.map(([label, value, cls]) =>
    `<div class="chip"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`
  ).join("");
  document.getElementById("grok2api-upload").disabled = !!data.running || !data.configured;
  document.getElementById("grok2api-stop").disabled = !data.running;
}
async function refreshGrok2api() {
  try {
    const data = await api("/api/grok2api?_=" + Date.now(), { authHelp: false });
    renderGrok2api(data);
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("grok2api-status").textContent = message.includes("令牌") ? "等待令牌" : "检查失败";
  }
}
async function startGrok2apiUpload() {
  setMsg("grok2api-msg", "正在启动上传…", "");
  try {
    const data = await api("/api/grok2api/upload", { method: "POST", body: "{}" });
    setMsg("grok2api-msg", data.ok ? ("上传已启动，进程 " + (data.pid || "?")) : String(data.error || "启动失败"), data.ok ? "ok" : "err");
    await refreshGrok2api();
  } catch (e) { setMsg("grok2api-msg", String(e.message || e), "err"); }
}
async function stopGrok2apiUpload() {
  try {
    const data = await api("/api/grok2api/stop", { method: "POST", body: "{}" });
    setMsg("grok2api-msg", "上传已停止，结束进程 " + JSON.stringify(data.killed || []), "ok");
    await refreshGrok2api();
  } catch (e) { setMsg("grok2api-msg", String(e.message || e), "err"); }
}
function renderBfs(data) {
  data = data || {};
  const last = data.last_report || {};
  const rj = data.results_jsonl || {};
  const el = document.getElementById("bfs-kpis");
  if (!el) return;
  el.innerHTML = [
    ["上次扫描", last.total ?? "--", ""],
    ["BFS", last.bfs_count ?? "--", (last.bfs_count || 0) > 0 ? "warn" : "ok"],
    ["Clean", last.clean_count ?? "--", "ok"],
    ["比率", last.bfs_rate != null ? (last.bfs_rate + "%") : "--", (last.bfs_rate || 0) > 0 ? "warn" : ""],
    ["队列文件", data.flagged_file_count ?? 0, (data.flagged_file_count || 0) > 0 ? "warn" : ""],
    ["jsonl bfs", rj.bfs ?? 0, (rj.bfs || 0) > 0 ? "warn" : ""],
  ].map(([label, value, cls]) => `<div class="chip"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`).join("");
  const st = document.getElementById("bfs-status");
  if (st) st.textContent = last.scanned_at ? ("扫描 " + last.scanned_at) : "尚未扫描";
  const body = document.getElementById("bfs-body");
  if (body && Array.isArray(data.items)) {
    const rows = data.items.filter(it => it.has_bfs).slice(0, 50);
    body.innerHTML = rows.length ? rows.map(it =>
      `<tr><td class="mono">${esc(it.email || "-")}</td><td class="warn">${esc(it.bfs != null ? it.bfs : "yes")}</td><td class="mono">${esc(it.source || "")}</td><td class="mono">${esc(it.file || "")}</td></tr>`
    ).join("") : '<tr><td colspan="4" style="color:var(--muted)">无 bfs 记录（先点扫描）</td></tr>';
  }
}
async function refreshBfs(authHelp = false) {
  try {
    const data = await api("/api/bfs?_=" + Date.now(), { authHelp });
    renderBfs(data);
  } catch (e) {
    const st = document.getElementById("bfs-status");
    if (st) st.textContent = String(e.message || e).includes("令牌") ? "等待令牌" : "检查失败";
  }
}
async function runBfsScan() {
  setMsg("bfs-msg", "正在扫描 CPA / Grok2API auth …", "");
  const btn = document.getElementById("bfs-scan");
  if (btn) btn.disabled = true;
  try {
    const data = await api("/api/bfs/scan", { method: "POST", body: JSON.stringify({}) });
    renderBfs(Object.assign({}, data, { last_report: data, items: data.items || [] }));
    setMsg("bfs-msg",
      "完成 total=" + (data.total ?? 0) +
      " bfs=" + (data.bfs_count ?? 0) +
      " clean=" + (data.clean_count ?? 0) +
      " rate=" + (data.bfs_rate ?? 0) + "%" +
      (data.export_path ? (" → " + data.export_path) : ""),
      "ok");
  } catch (e) {
    setMsg("bfs-msg", String(e.message || e), "err");
  } finally {
    if (btn) btn.disabled = false;
  }
}
function setSsoSource(source) {
  if (!["paste", "pending", "accounts", "risk"].includes(source)) return;
  ssoSource = source;
  ["paste", "pending", "accounts", "risk"].forEach(name => {
    const btn = document.getElementById("sso-src-" + name);
    if (btn) btn.setAttribute("aria-pressed", String(name === source));
  });
  const hint = document.getElementById("sso-source-hint");
  const counts = (lastSsoState && lastSsoState.sources) || {};
  const labels = {
    paste: "粘贴 JWT 或 email----sso。判定规则与注册门禁一致：botFlag 1/2 或 policy=deny 记为标记。",
    pending: "扫描 accounts/sso_pending.txt（待补录队列，" + (counts.pending ?? 0) + " 行）。",
    accounts: "扫描 accounts/*.txt，不含已隔离风控和 bfs 名单（" + (counts.accounts ?? 0) + " 行）。",
    risk: "复检 accounts/sso_risk_rejected.txt（已隔离，" + (counts.risk ?? 0) + " 行）。",
  };
  if (hint) hint.textContent = labels[source] || labels.paste;
}
function setSsoFilter(name) {
  if (!["all", "flagged", "clean", "error"].includes(name)) return;
  ssoFilter = name;
  ["all", "flagged", "clean", "error"].forEach(key => {
    const btn = document.getElementById("sso-filter-" + key);
    if (btn) btn.setAttribute("aria-pressed", String(key === name));
  });
  renderSsoRows(lastSsoState);
}
function renderSsoState(data) {
  data = data || {};
  lastSsoState = data;
  const sum = data.summary || {};
  const running = !!data.running;
  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
  setText("sso-kpi-total", sum.total ?? data.total ?? "--");
  setText("sso-kpi-clean", sum.clean_count ?? "--");
  setText("sso-kpi-flagged", sum.flagged_count ?? "--");
  setText("sso-kpi-denied", sum.denied_count ?? "--");
  setText("sso-kpi-error", sum.error_count ?? "--");
  const progress = (data.progress || 0) + "/" + (data.total || sum.total || 0);
  setText("sso-kpi-progress", running ? progress : (sum.total ? String(sum.total) : "--"));
  const status = running
    ? ("扫描中 " + progress)
    : (data.error ? String(data.error) : (sum.scanned_at ? ("上次 " + sum.scanned_at) : "尚未扫描"));
  setText("sso-heading-status", status);
  setText("sso-job-status", status);
  setText("sso-dash-status", running ? "扫描中" : (sum.scanned_at || "grok.com botFlag"));
  const dash = document.getElementById("sso-dash-kpis");
  if (dash) {
    dash.innerHTML = [
      ["总数", sum.total ?? 0, ""],
      ["干净", sum.clean_count ?? 0, "ok"],
      ["标记", sum.flagged_count ?? 0, (sum.flagged_count || 0) > 0 ? "fail" : ""],
      ["deny", sum.denied_count ?? 0, (sum.denied_count || 0) > 0 ? "warn" : ""],
    ].map(([label, value, cls]) => `<div class="chip"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`).join("");
  }
  const startBtn = document.getElementById("sso-start");
  const stopBtn = document.getElementById("sso-stop");
  if (startBtn) startBtn.disabled = running;
  if (stopBtn) stopBtn.disabled = !running;
  setSsoSource(ssoSource);
  renderSsoRows(data);
}
function renderSsoRows(data) {
  const body = document.getElementById("sso-body");
  if (!body) return;
  const rows = ((data && data.items) || []).filter(it => {
    if (ssoFilter === "all") return true;
    if (ssoFilter === "error") return it.verdict === "error" || it.verdict === "unknown";
    return it.verdict === ssoFilter;
  });
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="sso-empty">没有匹配的检测结果</td></tr>';
    return;
  }
  body.innerHTML = rows.slice(-400).map(it => {
    const verdict = it.verdict || "unknown";
    const note = it.bot_flag_details || it.error || "-";
    return `<tr>
      <td class="mono">${esc(it.email || "-")}</td>
      <td class="mono">${esc(it.bot_flag_source == null ? "-" : it.bot_flag_source)}</td>
      <td class="mono">${esc(it.policy || "-")}</td>
      <td class="mono">${esc(it.risk == null ? "-" : it.risk)}</td>
      <td class="mono">${esc(it.event || "-")}</td>
      <td><span class="sso-verdict ${esc(verdict)}">${esc(verdict)}</span></td>
      <td>${esc(note)}</td>
    </tr>`;
  }).join("");
}
async function refreshSsoState(authHelp = false) {
  try {
    const data = await api("/api/sso-state?_=" + Date.now(), { authHelp });
    renderSsoState(data);
  } catch (e) {
    const st = document.getElementById("sso-dash-status");
    if (st) st.textContent = String(e.message || e).includes("令牌") ? "等待令牌" : "检查失败";
  }
}
async function startSsoScan() {
  setMsg("sso-msg", "正在启动 SSO 风控扫描 ...", "");
  try {
    const payload = {
      source: ssoSource,
      text: (document.getElementById("sso-input") || {}).value || "",
      delay: Number((document.getElementById("sso-delay") || {}).value || 0.4),
      proxy: (document.getElementById("sso-proxy") || {}).value || "",
    };
    const data = await api("/api/sso-state/start", { method: "POST", body: JSON.stringify(payload) });
    setMsg("sso-msg", "已启动，共 " + (data.total || 0) + " 条", "ok");
    await refreshSsoState();
  } catch (e) { setMsg("sso-msg", String(e.message || e), "err"); }
}
async function stopSsoScan() {
  try {
    await api("/api/sso-state/stop", { method: "POST", body: "{}" });
    setMsg("sso-msg", "已请求停止", "ok");
    await refreshSsoState();
  } catch (e) { setMsg("sso-msg", String(e.message || e), "err"); }
}
async function exportSsoState(kind) {
  try {
    const data = await api("/api/sso-state/export", { method: "POST", body: JSON.stringify({ kind }) });
    const blob = new Blob([data.content || ""], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = kind === "clean" ? "sso_clean.txt" : "sso_flagged.jsonl";
    a.click();
    URL.revokeObjectURL(url);
    setMsg("sso-msg", "已导出 " + (data.lines || 0) + " 行 → " + (data.path || kind), "ok");
  } catch (e) { setMsg("sso-msg", String(e.message || e), "err"); }
}
function renderBlacklist(bl, upd) {
  bl = bl || {};
  upd = upd || {};
  document.getElementById("bl-kpis").innerHTML = [
    ["ASN 数", bl.count ?? 0, "accent"],
    ["ISP 关键字", (bl.isp_keywords || []).length, ""],
    ["解析错误", (bl.errors || []).length, (bl.errors || []).length ? "fail" : "ok"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  document.getElementById("bl-body").innerHTML = (bl.items || []).map(i =>
    `<tr><td class="mono">AS${esc(i.asn)}</td><td>${esc(i.note || "")}</td></tr>`
  ).join("") || '<tr><td colspan="2" style="color:var(--muted)">空</td></tr>';
  document.getElementById("bl-err-chips").innerHTML = [
    ["更新错误合计", upd.error_count ?? 0, (upd.error_count ? "fail" : "ok")],
    ["lookup 失败", upd.lookup_fail_count ?? 0, "warn"],
    ["analyze 错误", upd.analyze_error_count ?? 0, "warn"],
    ["暂停扩黑次数", upd.hit_pause_count ?? 0, ""],
    ["历史新增记录", upd.added_total ?? 0, "accent"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  document.getElementById("bl-added").innerHTML = (upd.recent_added || []).slice().reverse().map(a =>
    `<tr><td class="mono">AS${esc(a.asn)}</td><td class="mono">${esc(a.log || "")}</td></tr>`
  ).join("") || '<tr><td colspan="2" style="color:var(--muted)">暂无自动新增</td></tr>';
}

function rateCls(r) {
  if (r == null) return "";
  if (r >= 70) return "ok";
  if (r >= 40) return "warn";
  return "fail";
}
function renderRates(rates) {
  rates = rates || {};
  const order = ["1h", "3h", "12h"];
  const labels = { "1h": "近 1 小时", "3h": "近 3 小时", "12h": "近 12 小时" };
  const cards = order.map(k => {
    const b = rates[k] || {};
    const r = b.success_rate;
    const val = r == null ? "--" : (r + "%");
    return `<div class="rate-item">
      <div class="rate-top">
        <span class="rate-label">${esc(labels[k] || k)}</span>
        <span class="rate-total">${b.total ?? 0} 次</span>
      </div>
      <div class="rate-value ${rateCls(r)}">${esc(val)}</div>
      <div class="rate-breakdown">
        <span class="ok">成功 ${b.ok ?? 0}</span>
        <span class="fail">失败 ${b.fail ?? 0}</span>
        <span class="warn">风控 ${b.risk ?? 0}</span>
      </div>
    </div>`;
  });
  const el = document.getElementById("rate-kpis");
  if (el) el.innerHTML = cards.join("");
}

function renderStats(s) {
  s = s || {};
  if (s.rates) renderRates(s.rates);
  document.getElementById("stats-chips").innerHTML = [
    ["CPA", s.cpa ?? "--", "accent"],
    ["CPA 变化", s.cpa_delta ?? "--", "ok"],
    ["本批成功", s.batch_ok ?? 0, "ok"],
    ["本批失败", s.batch_fail ?? 0, "fail"],
    ["jsonl ok", s.jsonl_ok ?? 0, "ok"],
    ["jsonl risk", s.jsonl_risk ?? 0, "warn"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  const days = Object.entries(s.by_day || {}).sort((a,b) => b[0].localeCompare(a[0])).slice(0, 10);
  document.getElementById("stats-day").innerHTML = days.length ? days.map(([d, v]) =>
    `<tr><td class="mono">${esc(d)}</td><td class="ok">${v.ok||0}</td><td class="warn">${v.risk||0}</td><td class="fail">${v.fail||0}</td></tr>`
  ).join("") : '<tr><td colspan="4" style="color:var(--muted)">无 jsonl 数据</td></tr>';
}
function statsForSnapshot(d) {
  const liveStats = {
    cpa: d.cpa,
    cpa_delta: d.cpa_delta,
    base_cpa: d.base_cpa,
    batch_ok: d.ok,
    batch_fail: d.fail,
    rates: d.rates || {},
  };
  if (!fullStats) {
    return Object.assign({}, liveStats, {
      jsonl_ok: "--",
      jsonl_risk: "--",
      by_day: {},
      refreshed_at: d.ts_human,
    });
  }
  return Object.assign({}, fullStats, liveStats, {
    rates: d.rates || fullStats.rates || {},
  });
}
function render(d) {
  document.getElementById("clock").textContent = d.ts_human || "--";
  document.getElementById("logname").textContent =
    (d.log_name || d.log || "--") + (d.process && d.process.etime ? " / 用时 " + d.process.etime : "");
  const on = !!(d.process && d.process.running);
  document.getElementById("run-dot").className = "dot " + (on ? "on" : (d.ended ? "done" : "off"));
  let runLabel = "已停止";
  if (d.process && d.process.orch_running) runLabel = "编排运行 #" + d.process.orch_pid;
  else if (d.process && d.process.batch_running) runLabel = "单批运行 #" + d.process.batch_pid;
  else if (d.ended) runLabel = "已完成";
  document.getElementById("run-label").textContent = runLabel;
  document.getElementById("run-status").setAttribute("aria-label", "任务状态：" + runLabel);
  const sync = document.getElementById("sync-label");
  if (sync) {
    sync.textContent = "实时更新";
    sync.className = "badge";
  }
  document.getElementById("ctrl-status").textContent = on ? "运行中" : "空闲";
  document.getElementById("btn-start").disabled = on;
  document.getElementById("btn-stop").disabled = !on;
  fillControl(d);

  const traffic = d.traffic || {};
  const hasTrafficBatch = !!traffic.batch_id;
  const trafficTotal = Number(traffic.bytes_total) || 0;
  const trafficState = traffic.running ? "运行中" : "上一批";
  const trafficSub = hasTrafficBatch
    ? trafficState + " / 上行 " + formatBytes(traffic.bytes_up) + " / 下行 " + formatBytes(traffic.bytes_down)
      + ((Number(traffic.unmetered_proxies) || 0) > 0 ? " / 未计量 " + traffic.unmetered_proxies : "")
    : "等待批次计量";
  const trafficSummary = d.traffic_summary || {};
  const trafficBatchCount = Number(trafficSummary.batch_count) || 0;
  const trafficSuccessCount = Number(trafficSummary.successful_accounts) || 0;
  const trafficAverageSub = trafficBatchCount
    ? trafficBatchCount + " 批样本 / 累计 " + formatBytes(trafficSummary.total_bytes)
      + (trafficSummary.includes_current ? " / 含本批" : "")
    : "等待批次样本";
  const trafficSuccessSub = trafficSuccessCount
    ? "累计成功 " + trafficSuccessCount + " / 含失败流量"
    : "等待成功账号样本";
  const kpis = [
    ["本批成功", d.ok ?? 0, "ok", "目标 " + (d.target ?? "--")],
    ["本批失败", d.fail ?? 0, "fail", d.success_rate != null ? "成功率 " + d.success_rate + "%" : "暂无数据"],
    ["CPA 总量", d.cpa ?? "--", "accent", "较基线 " + (d.cpa_delta != null ? ((Number(d.cpa_delta) >= 0 ? "+" : "") + d.cpa_delta) : "--")],
    ["正常 / 风控", (d.bot0 ?? 0) + " / " + (d.bot1 ?? 0), (d.bot1 ?? 0) > 0 ? "warn" : "ok", "注册结果采样"],
    ["BFS 标记", d.bfs ?? 0, (d.bfs ?? 0) > 0 ? "warn" : "ok", "JWT claim 命中"],
    ["黑名单 ASN", (d.blacklist && d.blacklist.count) ?? "--", "accent", "更新错误 " + ((d.blacklist_update && d.blacklist_update.error_count) ?? 0)],
    ["本批代理流量", hasTrafficBatch ? formatBytes(trafficTotal) : "--", "accent", trafficSub],
    ["预计完成", d.ended ? "已完成" : (d.eta || "--"), "", "并发 " + (d.workers ?? "--") + (d.rate_per_min != null ? " / " + d.rate_per_min + " 每分钟" : "")],
    ["每批平均流量", trafficSummary.bytes_per_batch != null ? formatBytes(trafficSummary.bytes_per_batch) : "--", "accent", trafficAverageSub],
    ["每个成功号平均流量", trafficSummary.bytes_per_success != null ? formatBytes(trafficSummary.bytes_per_success) : "--", "ok", trafficSuccessSub],
  ];
  document.getElementById("kpis").innerHTML = kpis.map(([label, val, cls, sub]) =>
    `<div class="metric"><div class="label">${esc(label)}</div><div class="value ${cls}">${esc(val)}</div><div class="sub">${esc(sub)}</div></div>`
  ).join("");
  renderRates(d.rates || {});
  const ru = document.getElementById("rates-updated");
  if (ru && d.ts_human) ru.textContent = "数据更新 " + d.ts_human;

  const pct = Math.min(100, Number(d.progress_pct) || 0);
  const target = Number(d.target) || 0;
  const done = Number(d.done_attempts) || 0;
  const remaining = Math.max(0, target - done);
  const taskTotal = Number(d.task_total) || 0;
  const taskDone = Number(d.task_done) || 0;
  if (taskTotal > 0) {
    // 任务级进度（整个任务的总数与已完成），批次明细放副标题
    const taskPct = Math.min(100, Math.round(100 * taskDone / taskTotal));
    document.getElementById("bar").style.width = taskPct + "%";
    document.getElementById("prog-text").textContent =
      "已完成 " + taskDone + " / " + taskTotal + " (" + taskPct + "%)";
    document.getElementById("prog-sub").textContent =
      "任务 " + taskDone + "/" + taskTotal
      + " | 本批 成功 " + (d.ok ?? 0) + " 失败 " + (d.fail ?? 0) + " 剩余 " + remaining
      + " | " + (on ? "进程运行中" : "未运行")
      + (d.ended ? " / 结束：成功 " + d.ended.success + "，失败 " + d.ended.fail : "");
  } else {
    document.getElementById("bar").style.width = pct + "%";
    document.getElementById("prog-text").textContent =
      "已完成 " + done + " / " + target + " (" + pct + "%)";
    document.getElementById("prog-sub").textContent =
      "成功 " + (d.ok ?? 0) + " | 失败 " + (d.fail ?? 0)
      + " | 剩余 " + remaining
      + " | " + (on ? "进程运行中" : "未运行")
      + (d.ended ? " / 结束：成功 " + d.ended.success + "，失败 " + d.ended.fail : "");
  }

  renderBlacklist(d.blacklist, d.blacklist_update);
  // Keep full jsonl/day statistics while the 2-second snapshot updates live counters.
  renderStats(statsForSnapshot(d));

  const wset = new Set([...(Object.keys(d.worker_ok || {})), ...(Object.keys(d.worker_fail || {}))]);
  const ws = [...wset].sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
  document.getElementById("workers-stats").innerHTML = ws.length ? ws.map(w =>
    `<div class="chip"><span>${esc(w)}</span><b><span class="ok">${d.worker_ok && d.worker_ok[w] || 0}</span> <span style="color:var(--muted)">/</span> <span class="fail">${d.worker_fail && d.worker_fail[w] || 0}</span></b></div>`
  ).join("") : '<span style="color:var(--muted)">暂无</span>';
  const fk = Object.entries(d.fail_kinds || {}).sort((a, b) => b[1] - a[1]);
  document.getElementById("fails").innerHTML = fk.length ? fk.map(([k, v]) =>
    `<div class="chip"><span>${esc(k)}</span><b class="fail">${v}</b></div>`
  ).join("") : '<span style="color:var(--muted)">暂无失败</span>';
  okItems = d.recent_ok || [];
  renderRecentOk();
  document.getElementById("fail-body").innerHTML = (d.recent_fail || []).map(r =>
    `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td>${esc(r.kind)}</td><td class="mono">${esc(r.msg)}</td></tr>`
  ).join("") || '<tr><td colspan="4" style="color:var(--muted)">暂无记录</td></tr>';
  const tailEl = document.getElementById("tail");
  const tailLines = d.tail || [];
  tailEl.textContent = tailLines.join("\n");
  const tailMeta = document.getElementById("tail-meta");
  if (tailMeta) tailMeta.textContent = "最近 " + tailLines.length + " 行 · 每 2 秒刷新";
  if (tailFollow) tailEl.scrollTop = tailEl.scrollHeight;
  document.getElementById("footer").textContent =
    "服务 " + location.host + " / 日志 " + (d.log || "") + " / 2 秒轮询 / "
    + (d.log_size ? (d.log_size / 1024).toFixed(0) + " KB" : "0 KB")
    + " / 黑名单 " + ((d.blacklist && d.blacklist.count) || 0) + " ASN";
}
function renderRecentOk() {
  const list = okItems || [];
  const pages = Math.max(1, Math.ceil(list.length / okPageSize));
  if (okPage > pages) okPage = pages;
  if (okPage < 1) okPage = 1;
  const start = (okPage - 1) * okPageSize;
  const slice = list.slice(start, start + okPageSize);
  document.getElementById("ok-body").innerHTML = slice.map(r => {
    const ipCell = r.ip ? `<td class="mono">${esc(r.ip)}${r.port ? ":" + esc(r.port) : ""}</td>` : '<td class="mono" style="color:var(--muted)">-</td>';
    return `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td class="mono">${esc(r.email)}</td>${ipCell}</tr>`;
  }).join("") || '<tr><td colspan="4" style="color:var(--muted)">暂无记录</td></tr>';
  const status = document.getElementById("ok-page-status");
  if (status) status.textContent = `第 ${okPage} / ${pages} 页（共 ${list.length} 条）`;
  const prev = document.getElementById("ok-page-prev");
  const next = document.getElementById("ok-page-next");
  if (prev) prev.disabled = okPage <= 1;
  if (next) next.disabled = okPage >= pages;
}
function changeOkPage(delta) {
  const list = okItems || [];
  const pages = Math.max(1, Math.ceil(list.length / okPageSize));
  const next = Math.max(1, Math.min(pages, okPage + Number(delta || 0)));
  if (next === okPage) return;
  okPage = next;
  renderRecentOk();
}
function changeOkPageSize(value) {
  okPageSize = Math.max(1, Math.min(500, Number(value || 10)));
  okPage = 1;
  renderRecentOk();
}
syncThemeButtons();
initHelp();
loadTokenField();
bindTailFollow();
refresh();
setInterval(refresh, 2000);
// full stats once on load, then refresh every 30s
refreshStats(false);
setInterval(() => refreshStats(false), 30000);
refreshRecovery();
setInterval(refreshRecovery, 5000);
setInterval(refreshGrok2api, 5000);
refreshBfs();
setInterval(refreshBfs, 15000);
refreshSsoState();
setInterval(() => {
  if (document.body.classList.contains("sso-view-open") || (lastSsoState && lastSsoState.running)) {
    refreshSsoState(false);
  }
}, 2000);
setInterval(() => {
  if (document.body.classList.contains("proxy-view-open")) refreshProxies(false);
  if (document.body.classList.contains("domain-view-open")) { refreshEmailDomains(false); refreshEmailProfiles(false); }
  if (document.body.classList.contains("ip-usage-view-open")) { refreshIpUsage(false); refreshIpPool(false); }
}, 3000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "GrokRegister"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def log_message(self, fmt, *args):
        msg = args[0] if args else ""
        if "/api/status" in str(msg):
            return
        super().log_message(fmt, *args)

    def _send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=()",
            )
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; base-uri 'none'; object-src 'none'; "
                "frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; "
                "font-src 'self'; connect-src 'self'; "
                "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
            )
            # No wildcard CORS — panel is same-origin. Optional explicit origin via env.
            allow = str(os.environ.get("MONITOR_CORS_ORIGIN", "") or "").strip()
            if allow and allow != "*":
                self.send_header("Access-Control-Allow-Origin", allow)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _auth_header(self) -> str:
        return (
            self.headers.get("Authorization")
            or self.headers.get("X-Monitor-Token")
            or ""
        )

    def _require_write(self) -> bool:
        if check_token_optional_read(self._auth_header(), write=True):
            return True
        self._json(401, {"ok": False, "error": "unauthorized: set MONITOR_TOKEN and pass Authorization: Bearer <token>"})
        return False

    def _require_read(self) -> bool:
        if check_token_optional_read(self._auth_header(), write=False):
            return True
        self._json(401, {"ok": False, "error": "unauthorized: enter the current monitor token"})
        return False

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"), "application/json; charset=utf-8")

    def _read_body(self, max_size=None):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if n <= 0:
            return {}
        limit = MAX_REQUEST_BODY if max_size is None else int(max_size)
        if n > limit:
            raise OverflowError("request body too large")
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        return body

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if u.path in FONT_ASSETS:
            path = FONT_ASSETS[u.path]
            if path.is_file():
                self._send(200, path.read_bytes(), "font/woff2")
            else:
                self._send(404, b"not found", "text/plain")
            return
        if u.path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        if u.path == "/api/health":
            self._json(200, {"ok": True})
            return
        if u.path in ("/api/status", "/api/blacklist", "/api/stats", "/api/control", "/api/recovery", "/api/grok2api", "/api/proxies", "/api/ip-usage", "/api/ip-pool", "/api/email-provider", "/api/email-profiles", "/api/email-domains", "/api/config/export", "/api/bfs", "/api/sso-state"):
            if not self._require_read():
                return
        if u.path == "/api/status":
            try:
                self._json(200, snapshot())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/blacklist":
            try:
                bl = read_blacklist()
                bl["update"] = blacklist_update_errors()
                self._json(200, bl)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/stats":
            try:
                self._json(200, success_stats())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/control":
            self._json(200, load_control())
            return
        if u.path == "/api/recovery":
            try:
                self._json(200, recovery_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/grok2api":
            try:
                from webui.grok2api_upload_ops import upload_status as _g2api_status

                self._json(200, _g2api_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/proxies":
            try:
                query = parse_qs(u.query)
                self._json(
                    200,
                    read_proxy_pool(
                        page=(query.get("page") or ["1"])[0],
                        page_size=(query.get("page_size") or ["50"])[0],
                    ),
                )
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/ip-usage":
            try:
                from ip_usage_store import (
                    get_all_ip_usage_detail,
                    get_total_usage,
                    usage_file_path,
                )

                control = load_control()
                global_limit = int(control.get("ip_usage_limit", 0) or 0)
                updated = ""
                try:
                    data = json.loads(usage_file_path().read_text(encoding="utf-8"))
                    updated = str(data.get("updated_at") or "")
                except Exception:
                    pass
                items = get_all_ip_usage_detail()
                for item in items:
                    # 生效上限：该 IP 单独覆盖优先，否则回退全局
                    per = item.get("limit")
                    item["limit_effective"] = int(per) if per else global_limit
                self._json(
                    200,
                    {
                        "items": items,
                        "ip_count": len(items),
                        "total_usage": get_total_usage(),
                        "limit": global_limit,
                        "updated_at": updated,
                    },
                )
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/ip-pool":
            try:
                from webui.ip_ready_pool import get_pool_state

                self._json(200, get_pool_state())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/config/export":
            try:
                from webui.config_backup import export_all

                # 导出含敏感凭据，返回完整配置 JSON；由前端下载为备份文件
                self._json(200, export_all())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/bfs":
            try:
                self._json(200, bfs_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/sso-state":
            try:
                self._json(200, sso_state_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider":
            try:
                self._json(200, read_email_provider_config())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-profiles":
            try:
                from webui.email_provider_store import list_email_profiles

                self._json(200, list_email_profiles())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains":
            try:
                self._json(200, _email_domain_pool_view())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        # All POST endpoints require MONITOR_TOKEN
        if not self._require_write():
            return
        try:
            body_limit = 4 * 1024 * 1024 if u.path == "/api/sso-state/start" else None
            body = self._read_body(max_size=body_limit)
        except OverflowError as exc:
            self._json(413, {"ok": False, "error": str(exc)})
            return
        except ValueError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        if u.path == "/api/ip-usage/delete":
            try:
                from ip_usage_store import delete_ip_usage

                ip = str((body or {}).get("ip") or "").strip()
                if not ip:
                    self._json(400, {"ok": False, "error": "缺少 ip 参数"})
                    return
                deleted = delete_ip_usage(ip)
                self._json(200, {"ok": True, "deleted": deleted})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/ip-usage/reset":
            try:
                from ip_usage_store import reset_ip_usage

                reset_ip_usage()
                self._json(200, {"ok": True, "cleared": True})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/ip-usage/limit":
            try:
                from ip_usage_store import set_ip_usage_limit

                ip = str((body or {}).get("ip") or "").strip()
                if not ip:
                    self._json(400, {"ok": False, "error": "缺少 ip 参数"})
                    return
                try:
                    limit = max(0, min(100000, int((body or {}).get("limit") or 0)))
                except (TypeError, ValueError):
                    self._json(400, {"ok": False, "error": "limit 必须为 0..100000 的整数"})
                    return
                set_ip_usage_limit(ip, limit)
                self._json(
                    200,
                    {
                        "ok": True,
                        "ip": ip,
                        "limit": limit if limit > 0 else None,
                        "note": "0=清除覆盖，回退全局上限",
                    },
                )
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/ip-pool/probe":
            try:
                from webui.ip_ready_pool import get_pool_state, probe_round

                cfg = _runtime_config()
                stats_before = get_pool_state()["stats"]
                stats = probe_round(
                    target_count=int(cfg.get("ip_pool_target") or 20),
                    concurrency=int(cfg.get("ip_pool_probe_concurrency") or 12),
                    ttl=float(cfg.get("ip_pool_identity_ttl") or 600),
                )
                self._json(
                    200,
                    {
                        "ok": True,
                        "stats": stats,
                        "added": max(
                            0,
                            int(stats.get("total") or 0) - int(stats_before.get("total") or 0),
                        ),
                    },
                )
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/control":
            try:
                self._json(200, save_control(body))
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/config/import":
            try:
                from webui.config_backup import import_all

                self._json(200, import_all(body))
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/bfs/scan":
            try:
                limit = int((body or {}).get("limit") or 0)
                include_clean = bool((body or {}).get("include_clean"))
                result = run_bfs_scan(limit=limit, include_clean=include_clean)
                self._json(200, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/bfs/check":
            try:
                token = str((body or {}).get("token") or "").strip()
                if not token:
                    self._json(400, {"ok": False, "error": "token required"})
                    return
                self._json(200, check_token_text(token))
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/start":
            try:
                if body:
                    save_control(body)
                mode = (body or {}).get("mode") or load_control().get("mode") or "orch"
                if mode == "batch":
                    self._json(200, start_batch_only())
                else:
                    self._json(200, start_orch())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/stop":
            try:
                self._json(200, kill_all())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/logs/cleanup":
            try:
                result = cleanup_old_logs((body or {}).get("retention_days", 7))
                self._json(200 if result.get("ok") else 207, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": str(e)})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/recovery/start":
            try:
                with START_LOCK:
                    result = start_recovery((body or {}).get("scope") or "pending")
                self._json(200 if result.get("ok") else 409, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/sso-state/start":
            try:
                result = start_sso_state_scan(
                    source=str((body or {}).get("source") or "paste"),
                    text=str((body or {}).get("text") or ""),
                    delay=(body or {}).get("delay", 0.4),
                    proxy=str((body or {}).get("proxy") or ""),
                )
                code = 200 if result.get("ok") else (409 if result.get("running") else 400)
                self._json(code, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/sso-state/stop":
            try:
                self._json(200, stop_sso_state_scan())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/sso-state/export":
            try:
                result = read_sso_state_export(str((body or {}).get("kind") or "flagged"))
                self._json(200 if result.get("ok") else 404, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/grok2api/upload":
            try:
                from webui.grok2api_upload_ops import start_upload as _g2api_start

                with START_LOCK:
                    result = _g2api_start()
                self._json(200 if result.get("ok") else 409, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/grok2api/stop":
            try:
                from webui.grok2api_upload_ops import stop_upload as _g2api_stop

                result = _g2api_stop()
                self._json(200, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/recovery/stop":
            try:
                self._json(200, stop_recovery())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/proxies/import":
            try:
                if body.get("legacy") is True:
                    result = import_legacy_proxies()
                else:
                    result = import_proxies(body.get("proxies"), source="panel")
                if result.get("ok"):
                    result = {
                        key: value for key, value in result.items() if key != "items"
                    }
                self._json(200 if result.get("ok") else 400, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/proxies/test":
            try:
                result = start_proxy_tests(body.get("ids"))
                if result.get("ok"):
                    code = 202
                elif result.get("running"):
                    code = 409
                else:
                    code = 400
                self._json(code, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider":
            try:
                result = save_email_provider_config(
                    body.get("provider"),
                    body.get("settings") or {},
                    clear_secrets=body.get("clear_secrets"),
                )
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider/test":
            try:
                result = test_email_provider_config(
                    body.get("provider"),
                    body.get("settings") or {},
                    clear_secrets=body.get("clear_secrets"),
                )
                self._json(200 if result.get("ok") else 424, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-profiles":
            try:
                from webui.email_provider_store import save_email_profile

                result = save_email_profile(
                    body.get("provider"),
                    body.get("fields") or {},
                    name=body.get("name"),
                    enabled=body.get("enabled"),
                    profile_id=body.get("profile_id"),
                    clear_secrets=body.get("clear_secrets"),
                )
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-profiles/delete":
            try:
                from webui.email_provider_store import delete_email_profile

                deleted = delete_email_profile(body.get("profile_id"))
                self._json(200, {"ok": True, "deleted": deleted})
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-profiles/enabled":
            try:
                from webui.email_provider_store import set_email_profile_enabled

                result = set_email_profile_enabled(body.get("profile_id"), body.get("enabled"))
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-profiles/test":
            try:
                from webui.email_provider_store import test_email_profile

                result = test_email_profile(body.get("profile_id"))
                self._json(200 if result.get("ok") else 424, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/proxies/delete":
            try:
                result = delete_proxies(body.get("ids"))
                self._json(200 if result.get("ok") else 400, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/import":
            try:
                result = import_domains(
                    body.get("domains"),
                    body.get("provider"),
                    source="panel",
                )
                result = _email_domain_pool_view(result)
                self._json(200 if result.get("ok") else 400, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/settings":
            try:
                result = update_email_domain_settings(
                    failure_threshold=body.get("failure_threshold"),
                    max_active_domains=body.get("max_active_domains"),
                )
                result = _email_domain_pool_view(result)
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/reset":
            try:
                result = _email_domain_pool_view(reset_domain(body.get("id")))
                self._json(200 if result.get("ok", True) else 404, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/blacklist/refresh":
            try:
                bl = read_blacklist()
                bl["update"] = blacklist_update_errors()
                self._json(200, bl)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/blacklist/reset":
            try:
                from webui.blacklist_ops import reset_blacklist as _reset_bl
            except ImportError:
                try:
                    from blacklist_ops import reset_blacklist as _reset_bl  # type: ignore
                except ImportError:
                    _reset_bl = None
            if _reset_bl is None:
                self._json(501, {"ok": False, "error": "blacklist_ops unavailable"})
                return
            try:
                mode = (body or {}).get("mode") or "baseline"
                self._json(200, _reset_bl(mode))
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/stats/refresh":
            try:
                self._json(200, success_stats())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        self._send(404, b"not found", "text/plain")

    def do_PATCH(self):
        u = urlparse(self.path)
        proxy_match = re.fullmatch(r"/api/proxies/([a-f0-9]{20})", u.path)
        domain_match = re.fullmatch(r"/api/email-domains/([a-f0-9]{20})", u.path)
        if proxy_match is None and domain_match is None:
            self._send(404, b"not found", "text/plain")
            return
        if not self._require_write():
            return
        try:
            body = self._read_body()
        except OverflowError as exc:
            self._json(413, {"ok": False, "error": str(exc)})
            return
        except ValueError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        try:
            if proxy_match is not None:
                result = update_proxy(proxy_match.group(1), enabled=body.get("enabled"))
            else:
                result = _email_domain_pool_view(
                    update_domain(domain_match.group(1), enabled=body.get("enabled"))
                )
            if proxy_match is not None and result.get("ok"):
                result = {
                    key: value for key, value in result.items() if key != "items"
                }
            self._json(200 if result.get("ok") else 404, result)
        except ValueError as exc:
            self._json(400, {"ok": False, "error": redact_log_line(str(exc))})
        except Exception as exc:
            self._json(500, {"ok": False, "error": redact_log_line(str(exc))})

    def do_DELETE(self):
        u = urlparse(self.path)
        proxy_match = re.fullmatch(r"/api/proxies/([a-f0-9]{20})", u.path)
        domain_match = re.fullmatch(r"/api/email-domains/([a-f0-9]{20})", u.path)
        if proxy_match is None and domain_match is None:
            self._send(404, b"not found", "text/plain")
            return
        if not self._require_write():
            return
        try:
            result = (
                delete_proxy(proxy_match.group(1))
                if proxy_match is not None
                else _email_domain_pool_view(delete_domain(domain_match.group(1)))
            )
            if proxy_match is not None and result.get("ok"):
                result = {
                    key: value for key, value in result.items() if key != "items"
                }
            self._json(200 if result.get("ok") else 404, result)
        except Exception as exc:
            self._json(500, {"ok": False, "error": redact_log_line(str(exc))})


def main():
    host = BIND_HOST
    tok = expected_token()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.strip().lower() == "localhost"
    if not tok and not loopback:
        raise SystemExit(
            "MONITOR_TOKEN is required when MONITOR_HOST is not loopback"
        )
    ThreadingHTTPServer.allow_reuse_address = True
    try:
        httpd = ThreadingHTTPServer((host, BIND_PORT), Handler)
    except OSError as e1:
        raise SystemExit(
            f"cannot bind {BIND_HOST}:{BIND_PORT} ({e1}); "
            "set MONITOR_HOST/MONITOR_PORT (no 0.0.0.0 fallback)"
        )
    if not tok:
        print(
            "[monitor] WARNING: MONITOR_TOKEN unset — write APIs (start/stop/control) will return 401",
            flush=True,
        )
    print(f"[monitor] http://{host}:{BIND_PORT}/  (bound {host}:{BIND_PORT})", flush=True)

    # 可用 IP 池后台补池线程：定时清理过期项，可用项不足目标时探测补充。
    # 探测走代理（每身份 2-8s），并发进行；daemon 线程不阻塞 HTTP。
    def _ip_pool_loop(stop_event: threading.Event):
        import time as _time

        while not stop_event.is_set():
            try:
                from webui.ip_ready_pool import probe_round, refresh_pool

                cfg = _runtime_config()
                target = max(1, int(cfg.get("ip_pool_target") or 20))
                interval = max(20.0, float(cfg.get("ip_pool_refresh_interval") or 120))
                concurrency = max(1, int(cfg.get("ip_pool_probe_concurrency") or 12))
                ttl = max(30.0, float(cfg.get("ip_pool_identity_ttl") or 600))
                stats = refresh_pool()
                if int(stats.get("usable") or 0) < target:
                    stats = probe_round(
                        target_count=target,
                        concurrency=concurrency,
                        ttl=ttl,
                    )
                    if stats.get("usable"):
                        print(
                            f"[monitor] ip-pool usable={stats.get('usable')} "
                            f"total={stats.get('total')}",
                            flush=True,
                        )
            except Exception as exc:
                print(f"[monitor] ip-pool loop error: {redact_log_line(str(exc))}", flush=True)
            stop_event.wait(interval)

    _ip_pool_stop = threading.Event()
    threading.Thread(
        target=_ip_pool_loop,
        args=(_ip_pool_stop,),
        name="ip-pool-refresh",
        daemon=True,
    ).start()
    stop_tasks_on_exit = os.environ.get(
        "MONITOR_STOP_TASKS_ON_EXIT",
        "1",
    ).strip().lower() not in {"0", "false", "no"}
    previous_handlers = {}

    def _request_shutdown(_signum, _frame):
        raise KeyboardInterrupt

    for signum in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if signum is None:
            continue
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, _request_shutdown)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _ip_pool_stop.set()
        httpd.server_close()
        if stop_tasks_on_exit:
            stopped = kill_all()
            if stopped.get("killed"):
                print(
                    f"[monitor] stopped task processes: {stopped['killed']}",
                    flush=True,
                )
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        print("[monitor] stopped", flush=True)


if __name__ == "__main__":
    main()
