"""可用出口 IP 池（ip_ready_pool）：预探测 sticky 身份，供注册 worker 择优消费。

背景：树脂聚合订阅下"sticky 身份 → 出口 IP"的映射无法预知，worker 换口只能
随机试错（起浏览器探测 → 发现超限 → 再换），命中率低、成本高。本模块在后台
批量展开新身份并轻量探测出口 IP（不启动浏览器），筛出"未超限 + 非黑名单"的
可用项存入 log/ip_ready_pool.json；worker 换口时优先从这里取已确认可用的项。

池项生命周期：probe_round 探测入池 → pick_usable 标记占用（in_use）→
worker 核验后 remove_item（用完即弃，一次性）。探测结果在 sticky 会话有效期
（ip_pool_identity_ttl）内有效，过期项由 refresh_pool 清理。

文件结构：
{
  "items": [
    {
      "id": "sha256(expanded_url)[:16]",
      "template_url": "...",        # 池模板（含 {session} 占位）
      "expanded_url": "...",        # 已展开身份（可直接使用的完整代理 URL）
      "exit_ip": "1.2.3.4",
      "used": 0,                    # 探测时的累计使用次数
      "limit": 10,                  # 探测时的生效上限（0=不限）
      "usable": true,               # used < limit 且非黑名单
      "checked_at": 1723180000.0,   # 探测时间（epoch）
      "expires_at": 1723180600.0,   # checked_at + ttl
      "consumer": "",               # 占用者（如 "W1"）
      "consumed_at": 0.0            # 占用时间
    }
  ],
  "updated_at": "2026-..."
}
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

from secure_files import atomic_write_json, exclusive_file_lock
from proxy_templates import expand_proxy_template, has_proxy_template

_POOL_FILE = Path(__file__).resolve().parent.parent / "log" / "ip_ready_pool.json"
_ROOT = _POOL_FILE.parent.parent
_POOL_LOCK = threading.Lock()

# 占用后未核验/未移除的最长保留时间：worker 进程崩溃时释放残留项
_IN_USE_GRACE_SECONDS = 300.0

LogFn = Callable[[str], None]


def pool_file() -> Path:
    return _POOL_FILE


def _read_items() -> list[dict]:
    try:
        data = json.loads(_POOL_FILE.read_text(encoding="utf-8") or "{}")
        items = data.get("items") or []
        return [it for it in items if isinstance(it, dict)]
    except Exception:
        return []


def _write_items(items: list[dict]) -> None:
    _POOL_FILE.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        _POOL_FILE,
        {
            "items": items,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )


def _item_id(expanded_url: str) -> str:
    return hashlib.sha256(str(expanded_url or "").encode("utf-8", "replace")).hexdigest()[:16]


def _stats(items: list[dict], now: float | None = None) -> dict[str, int]:
    now = time.time() if now is None else now
    total = len(items)
    usable = 0
    over_limit = 0
    in_use = 0
    expired = 0
    for it in items:
        if float(it.get("expires_at") or 0) <= now:
            expired += 1
            continue
        if it.get("consumer"):
            in_use += 1
            continue
        if it.get("usable"):
            usable += 1
        else:
            over_limit += 1
    return {
        "total": total,
        "usable": usable,
        "over_limit": over_limit,
        "in_use": in_use,
        "expired": expired,
    }


def _datacenter_filter_enabled() -> bool:
    """面板「数据中心出口过滤」开关；异常一律视为关闭。"""
    try:
        from webui.proxy_store import datacenter_filter_enabled

        return datacenter_filter_enabled()
    except Exception:
        return False


def _is_datacenter_org(asn_org: object) -> bool:
    try:
        from webui.proxy_store import is_datacenter_org

        return is_datacenter_org(asn_org)
    except Exception:
        return False


def _lookup_asn_org(exit_ip: str, timeout: float = 5.0) -> str:
    """按出口 IP 尽力查一次 ASN 组织名（ipwho.is）；失败返回空串。"""
    ip = str(exit_ip or "").strip()
    if not ip:
        return ""
    try:
        import requests

        resp = requests.get(f"https://ipwho.is/{ip}", timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
        connection = payload.get("connection") if isinstance(payload, dict) else None
        if isinstance(connection, dict):
            return str(connection.get("org") or connection.get("isp") or "").strip()
        return str(payload.get("org") or payload.get("isp") or "").strip()
    except Exception:
        return ""


def _usage_limit(ip: str) -> int:
    """每 IP 覆盖优先，未设置回退 config.json 的 ip_usage_limit（0..100000）。

    与 grok_register_ttk.get_ip_usage_limit 口径一致；不 import 注册主模块
    以避免循环依赖。
    """
    from ip_usage_store import get_per_ip_limit

    ip = str(ip or "").strip()
    if ip:
        try:
            per = get_per_ip_limit(ip)
        except Exception:
            per = None
        if per is not None:
            return max(0, min(int(per), 100000))
    try:
        cfg = json.loads((_ROOT / "config.json").read_text(encoding="utf-8"))
        v = int(cfg.get("ip_usage_limit", 0) or 0)
    except Exception:
        v = 0
    return max(0, min(v, 100000))


def probe_one(
    template_url: str,
    expanded_url: str,
    ttl: float = 600.0,
    log_callback: Optional[LogFn] = None,
) -> Optional[dict]:
    """轻量探测一个已展开身份：出口 IP → 黑名单 → 累计上限。

    探测失败/拿不到 IP 返回 None（该身份不可用，不入池）。
    """
    try:
        from browser_session import _resolve_proxy_exit_ip, is_blocked_exit_ip
        from ip_usage_store import get_ip_usage, is_soft_blacklisted

        exit_ip = _resolve_proxy_exit_ip(expanded_url, timeout=6.0)
    except Exception as exc:
        if log_callback:
            log_callback(f"[ip-pool] probe failed: {type(exc).__name__}")
        return None
    exit_ip = str(exit_ip or "").strip()
    if not exit_ip:
        return None
    try:
        if is_soft_blacklisted(exit_ip):
            if log_callback:
                log_callback(f"[ip-pool] skip soft-blacklisted {exit_ip}")
            return None
    except Exception:
        pass
    try:
        blocked, reason = is_blocked_exit_ip(exit_ip)
        if blocked:
            if log_callback:
                log_callback(f"[ip-pool] skip blocked {exit_ip}: {reason}")
            return None
    except Exception:
        pass
    try:
        limit = _usage_limit(exit_ip)
        used = get_ip_usage(exit_ip)
    except Exception:
        limit = 0
        used = 0
    # 机房过滤（面板开关）：入池前按出口 IP 查一次 ASN 组织名，命中关键词不入池。
    # 查询失败/限流不拦（保留条目），避免误杀。
    if _datacenter_filter_enabled():
        asn_org = _lookup_asn_org(exit_ip)
        if _is_datacenter_org(asn_org):
            if log_callback:
                log_callback(f"[ip-pool] skip datacenter {exit_ip} ({asn_org})")
            return None
    now = time.time()
    return {
        "id": _item_id(expanded_url),
        "template_url": str(template_url or ""),
        "expanded_url": str(expanded_url),
        "exit_ip": exit_ip,
        "used": int(used),
        "limit": int(limit),
        "usable": not (limit > 0 and used >= limit),
        "checked_at": now,
        "expires_at": now + max(30.0, float(ttl or 600.0)),
        "consumer": "",
        "consumed_at": 0.0,
    }


def probe_round(
    target_count: int = 20,
    concurrency: int = 12,
    ttl: float = 600.0,
    log_callback: Optional[LogFn] = None,
) -> dict:
    """展开新身份批量探测一轮，去重合并入池。

    只对模板代理展开身份；非模板代理展开无效（原 URL），探测一次后
    按 expanded_url 去重只保留一项。返回最新池统计。
    """
    from webui.proxy_store import worker_proxy_snapshot

    urls = list(worker_proxy_snapshot().get("urls") or [])
    if not urls:
        return _stats(_read_items())
    with _POOL_LOCK:
        existing = _read_items()
        seen = {it.get("expanded_url") for it in existing}

    stamp = int(time.time())
    candidates: list[tuple[str, str]] = []
    i = 0
    while len(candidates) < max(1, int(target_count)) and i < max(1, int(target_count)) * 4:
        for url in urls:
            if len(candidates) >= max(1, int(target_count)):
                break
            if has_proxy_template(url):
                expanded = expand_proxy_template(url, identity=f"ipool-{stamp}-{i}")
            else:
                expanded = str(url or "").strip()
            i += 1
            if not expanded or expanded in seen:
                continue
            candidates.append((url, expanded))
            seen.add(expanded)

    results: list[dict] = []
    if candidates:
        with ThreadPoolExecutor(max_workers=max(1, int(concurrency))) as pool:
            futures = [
                pool.submit(probe_one, turl, eurl, float(ttl), log_callback)
                for turl, eurl in candidates
            ]
            for fut in futures:
                try:
                    item = fut.result()
                except Exception:
                    item = None
                if item:
                    results.append(item)

    if results:
        with _POOL_LOCK:
            items = _read_items()
            by_id = {it.get("id"): it for it in items}
            for item in results:
                by_id[item["id"]] = item
            _write_items(sorted(by_id.values(), key=lambda it: it.get("checked_at") or 0))
    return _stats(_read_items())


def refresh_pool(now: float | None = None) -> dict:
    """清理过期/僵死项，并按当前 ip_usage 计数与软拉黑状态重算 usable。"""
    from ip_usage_store import get_ip_usage, is_soft_blacklisted

    now = time.time() if now is None else now
    with _POOL_LOCK:
        items = _read_items()
        kept: list[dict] = []
        for it in items:
            if float(it.get("expires_at") or 0) <= now:
                continue
            if it.get("consumer") and float(it.get("consumed_at") or 0) > 0:
                if now - float(it["consumed_at"]) > _IN_USE_GRACE_SECONDS:
                    continue  # 占用者崩溃残留
            ip = str(it.get("exit_ip") or "").strip()
            if ip:
                try:
                    if is_soft_blacklisted(ip):
                        it["usable"] = False
                    else:
                        limit = _usage_limit(ip)
                        used = get_ip_usage(ip)
                        it["used"] = int(used)
                        it["limit"] = int(limit)
                        it["usable"] = not (limit > 0 and used >= limit)
                except Exception:
                    pass
            kept.append(it)
        _write_items(kept)
        return _stats(kept, now)


def pick_usable(
    consumer: str,
    exclude_ips: frozenset[str] = frozenset(),
    now: float | None = None,
) -> Optional[dict]:
    """挑一个可用项（未过期、未占用、IP 不在 exclude），标记占用后返回。

    优先返回 trusted=True 的出口（注册成功过的 IP 复用项），其余按入池
    顺序。返回的项由调用方核验后 remove_item（用完即弃）；无可用项返回
    None。bad_ips 由调用方在 exclude 中传入。
    """
    now = time.time() if now is None else now
    exclude = set(exclude_ips or ())
    with _POOL_LOCK:
        items = _read_items()
        ordered = sorted(
            items,
            key=lambda it: 0 if it.get("trusted") else 1,
        )
        for it in ordered:
            if float(it.get("expires_at") or 0) <= now:
                continue
            if it.get("consumer"):
                continue
            if not it.get("usable"):
                continue
            ip = str(it.get("exit_ip") or "").strip()
            if ip in exclude:
                continue
            it["consumer"] = str(consumer or "")
            it["consumed_at"] = now
            _write_items(items)
            return dict(it)
    return None


def upsert_trusted_exit(ip: str, *, proxy_url: str = "", meta: dict | None = None) -> bool:
    """把注册成功过的出口（连同会话身份）写入/续期池内 trusted 项。

    trusted 项在 pick_usable 中优先被取用；会话核验存活时由 ip_health
    续期 expires_at，实现"成功 IP 在 resin 7 天租期内反复复用"。
    """
    ip = str(ip or "").strip()
    if not ip:
        return False
    now = time.time()
    with _POOL_LOCK:
        items = _read_items()
        target = next((it for it in items if it.get("exit_ip") == ip), None)
        if target is None:
            target = {
                "id": _item_id(f"trusted-{ip}"),
                "template_url": "",
                "expanded_url": "",
                "exit_ip": ip,
                "used": 0,
                "limit": 0,
                "usable": True,
                "checked_at": now,
                "expires_at": 0.0,
                "consumer": "",
                "consumed_at": 0.0,
            }
            items.append(target)
        target["trusted"] = True
        target["usable"] = True
        target["expires_at"] = now + 604800.0  # resin sticky 租期 7 天
        if proxy_url:
            target["expanded_url"] = proxy_url
        if meta:
            target["health"] = {
                "successes": int(meta.get("successes") or 0),
                "fails": int(meta.get("fails") or 0),
                "session_alive": meta.get("session_alive"),
            }
        _write_items(items)
    return True


def demote_trusted_exit(ip: str, *, reason: str = "") -> bool:
    """会话连续死亡等原因下放 trusted 项为普通项（不删，等待补池清理）。"""
    ip = str(ip or "").strip()
    with _POOL_LOCK:
        items = _read_items()
        hit = False
        for it in items:
            if it.get("exit_ip") == ip and it.get("trusted"):
                it["trusted"] = False
                it["demoted_reason"] = str(reason or "")
                it["usable"] = False
                hit = True
        if hit:
            _write_items(items)
    return hit


def remove_item(item_id: str) -> bool:
    """核验成功/失败后从池中剔除该项（用完即弃）。"""
    if not item_id:
        return False
    with _POOL_LOCK:
        items = _read_items()
        kept = [it for it in items if it.get("id") != item_id]
        if len(kept) == len(items):
            return False
        _write_items(kept)
        return True


def get_pool_state() -> dict:
    """面板展示：公开字段 items + 统计。"""
    items = _read_items()
    now = time.time()
    public = []
    for it in items:
        public.append(
            {
                "id": it.get("id", ""),
                "exit_ip": it.get("exit_ip", ""),
                "used": it.get("used", 0),
                "limit": it.get("limit", 0),
                "usable": bool(it.get("usable")),
                    "trusted": bool(it.get("trusted")),
                    "health": it.get("health") or {},
                "consumer": it.get("consumer", ""),
                "checked_at": it.get("checked_at", 0),
                "expires_at": it.get("expires_at", 0),
                "ttl_remaining": max(0, int(float(it.get("expires_at") or 0) - now)),
            }
        )
    try:
        updated = str(
            json.loads(_POOL_FILE.read_text(encoding="utf-8") or "{}").get("updated_at") or ""
        )
    except Exception:
        updated = ""
    return {
        "items": public,
        "stats": _stats(items, now),
        "updated_at": updated,
    }
