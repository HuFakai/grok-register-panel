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

# 旧数据纠正：成功过的出口被旧版本限流策略打上 banned / 永久软拉黑，
# 新策略下应恢复复用。按进程缓存，每个 IP 只纠正一次。
_RECONCILED_SUCCESS_IPS: set[str] = set()

# 冷静期默认值（秒）。注册成功过的出口不再终身拉黑，改用分级冷静：
# 成功一次休息 15 分钟；失败按 1h/2h/4h/8h/24h 递增；限流取 24h 上限。
# 均可被 config.json 覆盖（面板「策略设置」页可改）。
SUCCESS_COOLDOWN_DEFAULT = 900
FAIL_COOLDOWN_BASE_DEFAULT = 3600
FAIL_COOLDOWN_MAX_DEFAULT = 86400
THROTTLE_COOLDOWN_DEFAULT = 86400


def health_file() -> Path:
    return _HEALTH_FILE


def _config_int(key: str, default: int) -> int:
    """读取 config.json 的冷静期参数（缺失/异常一律回退默认值）。"""
    try:
        cfg = json.loads(
            (_HEALTH_FILE.parent.parent / "config.json").read_text(encoding="utf-8")
        )
        value = int(cfg.get(key, default))
    except Exception:
        return int(default)
    return max(0, value)


def success_cooldown_seconds() -> int:
    return _config_int("ip_success_cooldown_sec", SUCCESS_COOLDOWN_DEFAULT)


def throttle_cooldown_seconds() -> int:
    return _config_int("ip_throttle_cooldown_sec", THROTTLE_COOLDOWN_DEFAULT)


def failure_cooldown_seconds(streak: int) -> int:
    """连续失败冷静期：基数起每级翻倍，封顶上限。"""
    base = _config_int("ip_fail_cooldown_sec", FAIL_COOLDOWN_BASE_DEFAULT)
    cap = _config_int("ip_fail_cooldown_max_sec", FAIL_COOLDOWN_MAX_DEFAULT)
    if cap <= 0:
        cap = FAIL_COOLDOWN_MAX_DEFAULT
    level = max(0, min(int(streak or 1) - 1, 6))
    return min(cap, max(0, base) * (2 ** level))


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


def _is_banned(entry: dict) -> bool:
    """历史拉黑判定：成功过的出口不再受旧 banned 标记影响（兼容旧数据）。"""
    return bool(entry.get("banned")) and int(entry.get("successes") or 0) == 0


def _reconcile_successful_exit(entry: dict) -> None:
    """纠正旧数据：成功过的出口清掉 banned 标记与永久软拉黑哨兵。"""
    ip = str(entry.get("ip") or "").strip()
    if not ip or ip in _RECONCILED_SUCCESS_IPS:
        return
    if int(entry.get("successes") or 0) <= 0:
        return
    _RECONCILED_SUCCESS_IPS.add(ip)
    legacy_ban = bool(entry.get("banned") or entry.get("ban_reason"))
    if legacy_ban:
        entry.pop("banned", None)
        entry.pop("ban_reason", None)
        entry.pop("banned_at", None)
        with _HEALTH_LOCK:
            data = _read()
            current = data["exits"].get(ip)
            if current and int(current.get("successes") or 0) > 0:
                current.pop("banned", None)
                current.pop("ban_reason", None)
                current.pop("banned_at", None)
                _write(data)
    if legacy_ban:
        try:
            from ip_usage_store import clear_permanent_soft_blacklist

            clear_permanent_soft_blacklist(ip)
        except Exception:
            pass


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


def cooldown_until(ip: str) -> float:
    return float(get_exit_health(ip).get("cooldown_until") or 0.0)


def cooldown_remaining(ip: str, now: float | None = None) -> float:
    now = time.time() if now is None else now
    return max(0.0, cooldown_until(ip) - now)


def is_cooling(ip: str, now: float | None = None) -> bool:
    return cooldown_remaining(ip, now) > 0


def cooling_ips(now: float | None = None) -> set:
    now = time.time() if now is None else now
    with _HEALTH_LOCK:
        exits = _read()["exits"]
    return {
        ip for ip, e in exits.items()
        if float(e.get("cooldown_until") or 0) > now
    }


def cooldown_map(now: float | None = None) -> dict:
    """{ip: 剩余冷静期秒数}，只包含仍在冷静期的出口。"""
    now = time.time() if now is None else now
    with _HEALTH_LOCK:
        exits = _read()["exits"]
    return {
        ip: int(float(e.get("cooldown_until") or 0) - now)
        for ip, e in exits.items()
        if float(e.get("cooldown_until") or 0) > now
    }


def cool_exit(
    ip,
    seconds: float,
    *,
    reason: str = "",
    log_callback=None,
) -> Optional[dict]:
    """给出口设置/延长冷静期（不改成功/失败计数，不永久拉黑）。"""
    ip = str(ip or "").strip()
    if not ip:
        return None
    now = time.time()
    until = now + max(0.0, float(seconds or 0))
    with _HEALTH_LOCK:
        data = _read()
        exits = data["exits"]
        e = exits.setdefault(ip, {
            "ip": ip, "successes": 0, "fails": 0,
            "identities": {}, "session_alive": None,
            "session_checked_at": 0.0, "session_alive_streak": 0,
            "session_dead_streak": 0,
        })
        e["cooldown_until"] = max(float(e.get("cooldown_until") or 0), until)
        e["cooldown_reason"] = str(reason or "")[:120]
        exits[ip] = e
        _write(data)
    if log_callback:
        log_callback(
            f"[IP健康] 出口 {ip} 进入冷静期 {int(seconds)}s（{reason or 'cool'}）"
        )
    return dict(e)


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
            e["fail_streak"] = 0
            # 成功即进入短冷静期：不立刻反复压同一个出口，等轮换一圈再复用。
            cooldown = success_cooldown_seconds()
            if cooldown > 0:
                e["cooldown_until"] = now + cooldown
                e["cooldown_reason"] = "success"
            else:
                # 关闭成功冷静期：成功即清除历史冷静/限流计时。
                e.pop("cooldown_until", None)
                e.pop("cooldown_reason", None)
            # 成功即证明出口可用：自动解除历史拉黑（如限流误伤/手动恢复）
            e.pop("banned", None)
            e.pop("ban_reason", None)
            e.pop("banned_at", None)
        else:
            e["fails"] = int(e.get("fails") or 0) + 1
            e["last_fail_at"] = now
            streak = int(e.get("fail_streak") or 0) + 1
            e["fail_streak"] = streak
            # 成功过的出口只进冷静期，绝不因单次失败终身拉黑；冷静期逐次加长。
            if int(e.get("successes") or 0) > 0:
                cd = failure_cooldown_seconds(streak)
                until = now + cd
                e["cooldown_until"] = max(float(e.get("cooldown_until") or 0), until)
                e["cooldown_reason"] = f"fail-{streak}"
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
    """可信出口：成功≥阈值、未被连续死亡拉黑。按成功数+新近排序。

    冷静期内的出口仍在此列表（供健康页展示与会话核验），但取口侧应优先
    使用 available_trusted_exits()，避免冷静期内被重复压号。
    """
    with _HEALTH_LOCK:
        exits = [dict(e) for e in _read()["exits"].values()]
    out = []
    for e in exits:
        _reconcile_successful_exit(e)
        if _is_banned(e):
            continue
        if int(e.get("successes") or 0) < min_successes:
            continue
        if int(e.get("session_dead_streak") or 0) >= _DEAD_STREAK_LIMIT:
            continue
        e["best_identity"] = _best_identity(e)
        out.append(e)
    out.sort(key=lambda e: (int(e.get("successes") or 0), e.get("last_success_at") or 0),
             reverse=True)
    return out


def available_trusted_exits(min_successes: int = 1, now: float | None = None) -> list:
    """当前可直接复用的可信出口：排除冷静期与会话连续死亡。"""
    now = time.time() if now is None else now
    return [
        e for e in trusted_exits(min_successes)
        if float(e.get("cooldown_until") or 0) <= now
    ]


def bad_ips(min_fails: int = 2) -> set:
    """黑名单出口：显式拉黑（banned）或失败≥阈值且从未成功，取口时跳过。"""
    with _HEALTH_LOCK:
        exits = _read()["exits"]
    return {
        ip for ip, e in exits.items()
        if _is_banned(e)
        or (int(e.get("fails") or 0) >= min_fails and int(e.get("successes") or 0) == 0)
    }


def ban_exit(ip, *, reason: str = "", log_callback=None) -> Optional[dict]:
    """注册限流的出口处置：从未成功的拉黑，成功过的只进最长冷静期。

    - 从无成功记录的出口：保持原策略，banned + 计数置超限（确定性拒绝无
      复用价值）。
    - 注册成功过的出口：不终身拉黑，改用限流最长冷静期（默认 24h），到期
      后自动回到可信池复用；期间取口/换口全部跳过。
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
        e["last_fail_at"] = now
        if int(e.get("successes") or 0) > 0:
            e["cooldown_until"] = max(
                float(e.get("cooldown_until") or 0),
                now + throttle_cooldown_seconds(),
            )
            e["cooldown_reason"] = str(reason or "signup-throttle")[:120]
            # 成功过的出口不保留任何历史拉黑标记，冷静期结束即可复用。
            e.pop("banned", None)
            e.pop("ban_reason", None)
            e.pop("banned_at", None)
        else:
            e["banned"] = True
            e["ban_reason"] = str(reason or "")[:120]
            e["banned_at"] = now
        if not e.get("as"):
            e.update({k: v for k, v in _ipapi_meta(ip).items() if v})
        exits[ip] = e
        _write(data)
    if log_callback:
        if e.get("banned"):
            log_callback(f"[IP健康] 出口 {ip} 已拉黑（{reason or '手动'}）")
        else:
            log_callback(
                f"[IP健康] 出口 {ip} 进入限流冷静期 "
                f"{int(throttle_cooldown_seconds())}s"
            )
    return dict(e)


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
    trusted = [
        e for e in exits.values()
        if int(e.get("successes") or 0) >= 1 and not _is_banned(e)
    ]
    available = [
        e for e in trusted
        if float(e.get("cooldown_until") or 0) <= now
        and int(e.get("session_dead_streak") or 0) < _DEAD_STREAK_LIMIT
    ]
    return {
        "total": len(exits),
        "trusted": len(trusted),
        "available_trusted": len(available),
        "cooling": sum(
            1 for e in trusted if float(e.get("cooldown_until") or 0) > now
        ),
        "alive": sum(1 for e in trusted if e.get("session_alive")),
        "dead": sum(1 for e in trusted if int(e.get("session_dead_streak") or 0) >= _DEAD_STREAK_LIMIT),
        "due_check": sum(1 for e in trusted
                         if now - float(e.get("session_checked_at") or 0) >= 1800.0),
    }
