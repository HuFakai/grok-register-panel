"""出口 IP 健康档案：注册结果自动回写，支撑可信 IP 复用与会话核验。

数据落盘 log/ip_health.json。resin sticky 会话租期可达 7 天，注册成功过
的出口按周期用其最近成功的会话身份重探出口 IP 验证存活；存活的直接
回灌 ip_ready_pool 供 worker 优先复用，连续死亡则降级不再推荐。
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import requests

from secure_files import atomic_write_json

_HEALTH_FILE = Path(__file__).resolve().parent.parent / "log" / "ip_health.json"
_HEALTH_LOCK = threading.Lock()

LogFn = Optional[Callable[[str], None]]

# 单出口保留的最近会话身份上限（防止文件膨胀；sticky 身份可重建）
_MAX_IDENTITIES = 5
# 连续核验死亡 N 次后标记会话失效（身份过期，等下次注册成功重建）
_DEAD_STREAK_LIMIT = 2


def health_file() -> Path:
    return _HEALTH_FILE


def _read() -> dict:
    try:
        data = json.loads(_HEALTH_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("exits"), dict):
            return data
    except Exception:
        pass
    return {"version": 1, "updated_at": "", "exits": {}}


def _write(data: dict) -> None:
    data["version"] = 1
    data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    atomic_write_json(_HEALTH_FILE, data)


def _identity_id(url: str) -> str:
    return hashlib.sha256(str(url or "").encode("utf-8", "replace")).hexdigest()[:16]


def _ipapi_meta(ip: str) -> dict:
    """轻量查 ASN/归属（失败不阻塞，返回空 meta）。"""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode,as,asname,isp,proxy,hosting,mobile",
            timeout=(2, 3),
        )
        d = r.json()
        if isinstance(d, dict) and d.get("as"):
            return {
                "country": d.get("countryCode") or "",
                "as": d.get("as") or "",
                "asname": d.get("asname") or "",
                "isp": d.get("isp") or "",
                "hosting": bool(d.get("hosting")),
                "mobile": bool(d.get("mobile")),
            }
    except Exception:
        pass
    return {}


def get_exit_health(ip: str) -> dict:
    with _HEALTH_LOCK:
        return dict(_read()["exits"].get(str(ip or "").strip()) or {})


def record_exit_result(ip, ok, *, proxy_url="", log_callback=None) -> Optional[dict]:
    """注册结果回写：成功提升可信度并归档会话身份，失败累计黑历史。

    成功时把该出口（连同最近成功身份）交 ip_ready_pool 的 trusted 区
    供 worker 优先复用；失败仅记档案，由取口侧过滤。
    """
    ip = str(ip or "").strip()
    if not ip:
        return None
    now = time.time()
    with _HEALTH_LOCK:
        data = _read()
        exits = data["exits"]
        e = exits.setdefault(ip, {
            "ip": ip, "successes": 0, "fails": 0,
            "identities": {}, "session_alive": None,
            "session_checked_at": 0.0, "session_alive_streak": 0,
            "session_dead_streak": 0,
        })
        if ok:
            e["successes"] = int(e.get("successes") or 0) + 1
            e["last_success_at"] = now
            e["session_alive"] = True
            e["session_alive_streak"] = int(e.get("session_alive_streak") or 0) + 1
            e["session_dead_streak"] = 0
            e["session_checked_at"] = now
        else:
            e["fails"] = int(e.get("fails") or 0) + 1
            e["last_fail_at"] = now
        if proxy_url and ok:
            ident = e.setdefault("identities", {})
            iid = _identity_id(proxy_url)
            slot = ident.get(iid) or {"url": "", "first_seen": 0.0}
            slot.update({"url": proxy_url, "first_seen": slot.get("first_seen") or now,
                         "last_ok": now, "last_seen": now})
            ident[iid] = slot
            while len(ident) > _MAX_IDENTITIES:
                oldest = min(ident, key=lambda k: ident[k].get("last_seen") or 0)
                ident.pop(oldest, None)
        if not e.get("as"):
            e.update({k: v for k, v in _ipapi_meta(ip).items() if v})
        exits[ip] = e
        _write(data)
    if ok:
        try:
            from webui import ip_ready_pool
            ip_ready_pool.upsert_trusted_exit(ip, proxy_url=proxy_url, meta=e)
        except Exception:
            pass
    if log_callback:
        tag = "成功" if ok else "失败"
        log_callback(f"[IP健康] 出口 {ip} 记录{tag}（累计 成功{e['successes']}/失败{e['fails']}）")
    return dict(e)


def mark_session_check(ip, alive, *, proxy_url="") -> Optional[dict]:
    """会话核验结果回写：存活续期 trusted 池项，连续死亡降级。"""
    ip = str(ip or "").strip()
    now = time.time()
    with _HEALTH_LOCK:
        data = _read()
        e = data["exits"].get(ip)
        if not e:
            return None
        e["session_checked_at"] = now
        if alive:
            e["session_alive"] = True
            e["session_alive_streak"] = int(e.get("session_alive_streak") or 0) + 1
            e["session_dead_streak"] = 0
            if proxy_url:
                ident = e.setdefault("identities", {})
                iid = _identity_id(proxy_url)
                slot = ident.get(iid) or {"url": proxy_url, "first_seen": now}
                slot.update({"url": proxy_url, "last_seen": now})
                ident[iid] = slot
        else:
            e["session_alive"] = False
            e["session_dead_streak"] = int(e.get("session_dead_streak") or 0) + 1
            e["session_alive_streak"] = 0
        data["exits"][ip] = e
        _write(data)
    if alive:
        try:
            from webui import ip_ready_pool
            ip_ready_pool.upsert_trusted_exit(ip, proxy_url=proxy_url, meta=e)
        except Exception:
            pass
    elif int(e.get("session_dead_streak") or 0) >= _DEAD_STREAK_LIMIT:
        try:
            from webui import ip_ready_pool
            ip_ready_pool.demote_trusted_exit(ip, reason="session-dead")
        except Exception:
            pass
    return dict(e)


def _best_identity(e: dict) -> str:
    idents = e.get("identities") or {}
    if not idents:
        return ""
    best = max(idents.values(), key=lambda s: s.get("last_ok") or 0)
    return str(best.get("url") or "")


def trusted_exits(min_successes: int = 1) -> list:
    """可信出口：成功≥阈值、未被连续死亡拉黑。按成功数+新近排序。"""
    with _HEALTH_LOCK:
        exits = [dict(e) for e in _read()["exits"].values()]
    out = []
    for e in exits:
        if int(e.get("successes") or 0) < min_successes:
            continue
        if int(e.get("session_dead_streak") or 0) >= _DEAD_STREAK_LIMIT:
            continue
        e["best_identity"] = _best_identity(e)
        out.append(e)
    out.sort(key=lambda e: (int(e.get("successes") or 0), e.get("last_success_at") or 0),
             reverse=True)
    return out


def bad_ips(min_fails: int = 2) -> set:
    """黑历史出口：失败≥阈值且从未成功，取口时应跳过。"""
    with _HEALTH_LOCK:
        exits = _read()["exits"]
    return {
        ip for ip, e in exits.items()
        if int(e.get("fails") or 0) >= min_fails and int(e.get("successes") or 0) == 0
    }


def session_due_exits(max_age: float = 1800.0, limit: int = 8) -> list:
    """需要核验会话存活的可信出口（距上次核验超过 max_age）。"""
    now = time.time()
    out = []
    for e in trusted_exits():
        if now - float(e.get("session_checked_at") or 0) < max_age:
            continue
        if not e.get("best_identity"):
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


def verify_exit_session(e: dict, timeout: float = 8.0) -> tuple:
    """用最近成功身份重探出口 IP，验证 sticky 会话是否仍指向同一出口。"""
    ip = e["ip"]
    url = e.get("best_identity") or ""
    if not url:
        return False, ""
    try:
        r = requests.get("http://checkip.amazonaws.com/",
                         proxies={"http": url, "https": url}, timeout=timeout)
        cur = r.text.strip()
        return (cur == ip), cur
    except Exception:
        return False, ""


def verify_due_sessions(max_age: float = 1800.0, limit: int = 6,
                        log_callback: LogFn = None) -> dict:
    """核验一批到期出口；存活回灌 trusted 池，连续死亡降级。"""
    due = session_due_exits(max_age=max_age, limit=limit)
    alive = dead = 0
    for e in due:
        ok, cur = verify_exit_session(e)
        mark_session_check(e["ip"], ok and bool(cur), proxy_url=e.get("best_identity") or "")
        if ok:
            alive += 1
        else:
            dead += 1
        if log_callback:
            log_callback(
                f"[IP健康] 会话核验 {e['ip']}: {'存活' if ok else '失效（当前 ' + (cur or '?') + '）'}"
            )
    return {"checked": len(due), "alive": alive, "dead": dead}


def delete_exit(ip: str) -> bool:
    with _HEALTH_LOCK:
        data = _read()
        ip = str(ip or "").strip()
        if ip in data["exits"]:
            data["exits"].pop(ip)
            _write(data)
            return True
    return False


def stats() -> dict:
    with _HEALTH_LOCK:
        exits = _read()["exits"]
    now = time.time()
    trusted = [e for e in exits.values() if int(e.get("successes") or 0) >= 1]
    return {
        "total": len(exits),
        "trusted": len(trusted),
        "alive": sum(1 for e in trusted if e.get("session_alive")),
        "dead": sum(1 for e in trusted if int(e.get("session_dead_streak") or 0) >= _DEAD_STREAK_LIMIT),
        "due_check": sum(1 for e in trusted
                         if now - float(e.get("session_checked_at") or 0) >= 1800.0),
    }
