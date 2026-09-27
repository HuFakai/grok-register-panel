"""服务端历史邮件自动清理（自建 cloudflare_temp_email Worker + D1）。

背景：raw_mails 只增不减时 D1 会涨到 500MB 上限，address 建号批量失败；
同时大表上的高频轮询会烧穿 D1 免费版每日行读取配额。

清理策略按保留时长分流：
- 不足 24 小时（如默认保留 1 小时）：不走批量端点——部署版本对小数天
  cleanDays 的处理无法保证，直接分页拉 /admin/mails 逐封删（created_at
  秒级字符串比较，行为可证明精确）；
- 达到 24 小时：走 Worker 自带 POST /admin/cleanup（cleanDays 向上取整到
  整天，保证绝不删除保留期内的邮件；单批删除量受 CLEANUP_BATCH_SIZE
  限制的部署会循环调用直到数量不再下降）。

面板展示的邮件数只在清理执行（定时/手动）时更新，读接口只返回缓存值，
不做任何后台轮询——每次对 /admin/mails 的查询都消耗 D1 每日行读取配额。

凭据复用注册配置：cloudflare_api_key 在 x-admin-auth 模式下即管理员密码，
本模块不新增任何密钥，也不把凭据写进日志。
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

import requests

from email_providers.cloudflare import delete_mail

ROOT = Path(__file__).resolve().parent.parent

MIN_KEEP_HOURS = 1
MAX_KEEP_HOURS = 720
SCAN_PAGE_SIZE = 100
MAX_SCAN_PAGES = 200
DELETE_CONCURRENCY = 8
CLEANUP_TIMEOUT = 60
BATCH_MAX_ROUNDS = 5
PROGRESS_REPORT_STEP = 25

# 与 monitor_control.json 键对齐；面板设置读写都经过这里归一化
DEFAULT_SETTINGS = {
    "mail_cleanup_enabled": True,
    "mail_cleanup_keep_hours": 1,
    "mail_cleanup_interval_hours": 1,
    "mail_cleanup_clean_unknow": True,
}


class MailCleanupError(RuntimeError):
    pass


def load_runtime_config() -> dict:
    try:
        return json.loads((ROOT / "config.json").read_text(encoding="utf-8") or "{}")
    except (OSError, ValueError, TypeError):
        return {}


def resolve_creds(config: dict | None = None) -> dict:
    cfg = config if config is not None else load_runtime_config()
    api_base = str(cfg.get("cloudflare_api_base", "") or "").strip().rstrip("/")
    admin_auth = str(cfg.get("cloudflare_api_key", "") or "").strip()
    custom_auth = str(cfg.get("cloudflare_custom_auth", "") or "").strip()
    if not api_base or not admin_auth:
        raise MailCleanupError(
            "需要先配置 cloudflare_api_base 与 cloudflare_api_key（x-admin-auth 管理员密码）"
        )
    return {"api_base": api_base, "admin_auth": admin_auth, "custom_auth": custom_auth}


def _admin_headers(creds: dict) -> dict:
    headers = {"x-admin-auth": creds["admin_auth"]}
    if creds.get("custom_auth"):
        headers["x-custom-auth"] = creds["custom_auth"]
    return headers


def _default_get(url: str, **kwargs):
    return requests.get(url, **kwargs)


def _default_post(url: str, **kwargs):
    return requests.post(url, **kwargs)


def _default_delete(url: str, **kwargs):
    return requests.delete(url, **kwargs)


def normalize_settings(payload: dict | None) -> dict:
    """校验面板提交的清理设置，返回可写回 control 的规范化键。"""
    body = dict(payload or {})
    out: dict[str, Any] = {}
    if "mail_cleanup_enabled" in body:
        out["mail_cleanup_enabled"] = bool(body.get("mail_cleanup_enabled"))
    if "mail_cleanup_clean_unknow" in body:
        out["mail_cleanup_clean_unknow"] = bool(body.get("mail_cleanup_clean_unknow"))
    if "mail_cleanup_keep_hours" in body:
        try:
            hours = int(body.get("mail_cleanup_keep_hours"))
        except (TypeError, ValueError) as exc:
            raise ValueError("保留时间必须是整数小时") from exc
        if not MIN_KEEP_HOURS <= hours <= MAX_KEEP_HOURS:
            raise ValueError(
                f"保留时间必须在 {MIN_KEEP_HOURS}-{MAX_KEEP_HOURS} 小时之间"
            )
        out["mail_cleanup_keep_hours"] = hours
    if "mail_cleanup_interval_hours" in body:
        try:
            hours = int(body.get("mail_cleanup_interval_hours"))
        except (TypeError, ValueError) as exc:
            raise ValueError("清理间隔必须是整数小时") from exc
        if not 1 <= hours <= 168:
            raise ValueError("清理间隔必须在 1-168 小时之间")
        out["mail_cleanup_interval_hours"] = hours
    if not out:
        raise ValueError("缺少可保存的清理设置项")
    return out


def fetch_mail_count(
    creds: dict | None = None,
    *,
    config: dict | None = None,
    http_get: Callable[..., Any] | None = None,
) -> int:
    """GET /admin/mails?limit=1，取响应里的 count（兼容 total）。"""
    c = creds or resolve_creds(config)
    get = http_get or _default_get
    resp = get(
        f"{c['api_base']}/admin/mails",
        params={"limit": 1, "offset": 0},
        headers=_admin_headers(c),
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    for key in ("count", "total"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, (int, float)):
            return int(value)
    results = data.get("results") if isinstance(data, dict) else None
    return len(results) if isinstance(results, list) else 0


# ---- 最近一次已知的服务端邮件数（仅清理执行时更新；面板只读缓存） ----

_COUNT_LOCK = threading.Lock()
_LAST_COUNT: dict[str, Any] = {"value": None, "error": None}


def record_count_snapshot(value: int | None, error: str | None = None) -> None:
    with _COUNT_LOCK:
        _LAST_COUNT.update({"value": value, "error": error})


def last_known_count() -> tuple[int | None, str | None]:
    with _COUNT_LOCK:
        return _LAST_COUNT["value"], _LAST_COUNT["error"]


def _cutoff_text(keep_hours: int, now: float | None) -> str:
    moment = float(time.time() if now is None else now)
    cutoff = _dt.datetime.fromtimestamp(moment, _dt.timezone.utc) - _dt.timedelta(
        hours=keep_hours
    )
    # raw_mails.created_at 由 D1 datetime('now') 生成，固定 UTC 'YYYY-MM-DD HH:MM:SS'
    return cutoff.strftime("%Y-%m-%d %H:%M:%S")


def _post_cleanup_once(
    creds: dict,
    clean_type: str,
    clean_days: int,
    http_post: Callable[..., Any],
) -> tuple[str, str]:
    """单次 POST /admin/cleanup；返回 (状态, 说明)，状态为 ok/unsupported/error。"""
    try:
        resp = http_post(
            f"{creds['api_base']}/admin/cleanup",
            json={"cleanType": clean_type, "cleanDays": clean_days},
            headers=_admin_headers(creds),
            timeout=CLEANUP_TIMEOUT,
        )
    except Exception as exc:
        return "error", str(exc)[:160]
    if resp.status_code in (404, 405):
        return "unsupported", f"部署版本无 /admin/cleanup（HTTP {resp.status_code}）"
    if resp.status_code >= 400:
        try:
            detail = (resp.text or "")[:120]
        except Exception:
            detail = ""
        return "error", f"HTTP {resp.status_code} {detail}"
    return "ok", ""


def _safe_progress(progress_cb: Callable[[dict], None] | None, **fields: Any) -> None:
    if progress_cb is None:
        return
    try:
        progress_cb(fields)
    except Exception:
        pass


def _server_batch_cleanup(
    creds: dict,
    clean_days: int,
    clean_unknow: bool,
    *,
    http_post: Callable[..., Any] | None,
    http_get: Callable[..., Any] | None,
    progress_cb: Callable[[dict], None] | None = None,
) -> tuple[bool, list[str]]:
    """整日保留走 Worker 批量端点。

    部分部署受 CLEANUP_BATCH_SIZE（≤5000）限制单批删除量，重复调用直到
    数量不再下降；端点缺失或失败返回 False，由调用方退回逐封删除。
    """
    post = http_post or _default_post
    get = http_get or _default_get
    errors: list[str] = []
    _safe_progress(progress_cb, phase="batch", clean_days=clean_days)
    previous: int | None = None
    for _ in range(BATCH_MAX_ROUNDS):
        state, detail = _post_cleanup_once(creds, "mails", clean_days, post)
        if state != "ok":
            errors.append(f"mails: {detail}")
            return False, errors
        try:
            remaining = fetch_mail_count(creds, http_get=get)
        except Exception as exc:
            errors.append(f"mails: 删除后计数失败 {exc}")
            return False, errors
        _safe_progress(progress_cb, phase="batch", clean_days=clean_days, remaining=remaining)
        if remaining == 0 or (previous is not None and remaining >= previous):
            break
        previous = remaining
    if clean_unknow:
        state, detail = _post_cleanup_once(creds, "mails_unknow", clean_days, post)
        if state != "ok":
            errors.append(f"mails_unknow: {detail}")
            return False, errors
    return True, errors


def _local_paging_cleanup(
    creds: dict,
    keep_hours: int,
    *,
    http_get: Callable[..., Any] | None,
    http_delete: Callable[..., Any] | None,
    now: float | None,
    progress_cb: Callable[[dict], None] | None = None,
) -> dict:
    """分页扫描 /admin/mails，删除 created_at 早于保留期的邮件（单封失败不中断）。"""
    get = http_get or _default_get
    do_delete = http_delete or _default_delete
    cutoff = _cutoff_text(keep_hours, now)
    stale_ids: list[Any] = []
    scanned = 0
    fatal: list[str] = []
    for page in range(MAX_SCAN_PAGES):
        try:
            resp = get(
                f"{creds['api_base']}/admin/mails",
                params={"limit": SCAN_PAGE_SIZE, "offset": page * SCAN_PAGE_SIZE},
                headers=_admin_headers(creds),
                timeout=20,
            )
            resp.raise_for_status()
            results = (resp.json() or {}).get("results") or []
        except Exception as exc:
            # 列表拉取失败即停，避免在未知状态下继续删
            fatal.append(f"列表第 {page + 1} 页拉取失败: {exc}")
            break
        if not results:
            break
        scanned += len(results)
        for row in results:
            if not isinstance(row, dict):
                continue
            mail_id = row.get("id")
            created = str(row.get("created_at") or "")
            if mail_id is None:
                continue
            # created_at 缺失/异常格式一律保留，宁可漏删不可误删
            if not created or created >= cutoff:
                continue
            stale_ids.append(mail_id)
        _safe_progress(
            progress_cb, phase="scan", scanned=scanned, stale=len(stale_ids)
        )
        if len(results) < SCAN_PAGE_SIZE:
            break

    deleted = 0
    failed = 0
    total = len(stale_ids)

    def _delete_one(mail_id) -> bool:
        try:
            delete_mail(
                do_delete,
                creds["api_base"],
                mail_id,
                admin_auth=creds["admin_auth"],
                custom_auth=creds.get("custom_auth", ""),
            )
            return True
        except Exception:
            return False

    if stale_ids:
        done = 0
        with ThreadPoolExecutor(max_workers=DELETE_CONCURRENCY) as pool:
            futures = [pool.submit(_delete_one, mail_id) for mail_id in stale_ids]
            for future in as_completed(futures):
                ok = future.result()
                done += 1
                if ok:
                    deleted += 1
                else:
                    failed += 1
                if done % PROGRESS_REPORT_STEP == 0 or done == total:
                    _safe_progress(
                        progress_cb,
                        phase="delete",
                        done=done,
                        total=total,
                        deleted=deleted,
                        failed=failed,
                    )
    return {
        "scanned": scanned,
        "stale": total,
        "deleted_by_api": deleted,
        "failed": failed,
        "fatal": fatal,
    }


def run_mail_cleanup(
    keep_hours: object = 1,
    *,
    clean_unknow: bool = True,
    creds: dict | None = None,
    config: dict | None = None,
    http_get: Callable[..., Any] | None = None,
    http_post: Callable[..., Any] | None = None,
    http_delete: Callable[..., Any] | None = None,
    now: float | None = None,
    progress_cb: Callable[[dict], None] | None = None,
) -> dict:
    """执行一次服务端历史邮件清理，返回统计（含前后 count 差值）。"""
    try:
        hours = int(keep_hours)
    except (TypeError, ValueError) as exc:
        raise MailCleanupError("保留时间必须是整数小时") from exc
    if not MIN_KEEP_HOURS <= hours <= MAX_KEEP_HOURS:
        raise MailCleanupError(
            f"保留时间必须在 {MIN_KEEP_HOURS}-{MAX_KEEP_HOURS} 小时之间"
        )

    c = creds or resolve_creds(config)
    before = fetch_mail_count(c, http_get=http_get)

    if hours < 24:
        # 不足 24 小时：不赌部署对小数天 cleanDays 的处理，直接逐封删
        server_ok = False
        server_errors = [f"保留 {hours} 小时不足 24 小时，走逐封删除"]
    else:
        # 非整天倍数向上取整到整天（36h→2 天），保证绝不删除保留期内的邮件
        clean_days = max(1, -(-hours // 24))
        server_ok, server_errors = _server_batch_cleanup(
            c,
            clean_days,
            clean_unknow,
            http_post=http_post,
            http_get=http_get,
            progress_cb=progress_cb,
        )

    if server_ok:
        mode = "server_batch"
        detail: dict[str, Any] = {"errors": server_errors}
    else:
        mode = "local_paging"
        detail = _local_paging_cleanup(
            c,
            hours,
            http_get=http_get,
            http_delete=http_delete,
            now=now,
            progress_cb=progress_cb,
        )
        detail["server_batch_errors"] = server_errors

    try:
        after = fetch_mail_count(c, http_get=http_get)
    except Exception as exc:
        after = None
        detail["count_after_error"] = str(exc)[:120]

    deleted = max(0, before - after) if after is not None else None
    fatal = detail.get("fatal") or []
    # 面板展示的邮件数只在清理执行时更新，读接口不做任何实时查询
    if after is not None:
        record_count_snapshot(after)
    else:
        record_count_snapshot(before, detail.get("count_after_error"))
    return {
        "ok": not fatal,
        "mode": mode,
        "keep_hours": hours,
        "clean_unknow": bool(clean_unknow),
        "before": before,
        "after": after,
        "deleted": deleted,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **detail,
    }


# ---- 面板后台任务状态（monitor 进程内单例） ----

_STATE_LOCK = threading.Lock()
_STATE: dict[str, Any] = {
    "running": False,
    "started_at": None,
    "last_result": None,
    "last_error": None,
    "progress": {},
}


def _set_progress(**fields: Any) -> None:
    """更新运行中任务的进度（逐封删除一次要几分钟，面板靠它反馈）。"""
    with _STATE_LOCK:
        current = dict(_STATE.get("progress") or {})
        current.update(fields)
        _STATE["progress"] = current


def cleanup_status() -> dict:
    with _STATE_LOCK:
        state = dict(_STATE)
        state["progress"] = dict(state.get("progress") or {})
    result = state.get("last_result")
    if isinstance(result, dict):
        state["last_result"] = {
            key: result.get(key)
            for key in (
                "ok",
                "mode",
                "before",
                "after",
                "deleted",
                "keep_hours",
                "failed",
                "finished_at",
            )
        }
    return state


def start_cleanup(
    keep_hours: object,
    *,
    clean_unknow: bool = True,
    creds: dict | None = None,
) -> dict:
    """非阻塞启动一次清理；已有任务在跑时拒绝并提示。"""
    try:
        hours = int(keep_hours)
    except (TypeError, ValueError):
        return {"started": False, "error": "保留时间必须是整数小时"}
    if not MIN_KEEP_HOURS <= hours <= MAX_KEEP_HOURS:
        return {
            "started": False,
            "error": f"保留时间必须在 {MIN_KEEP_HOURS}-{MAX_KEEP_HOURS} 小时之间",
        }
    with _STATE_LOCK:
        if _STATE.get("running"):
            return {"started": False, "error": "已有清理任务在运行"}
        _STATE["running"] = True
        _STATE["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _STATE["progress"] = {}
    thread = threading.Thread(
        target=_run_and_record,
        args=(hours, bool(clean_unknow), creds),
        name="mail-cleanup",
        daemon=True,
    )
    thread.start()
    return {"started": True, "keep_hours": hours}


def _run_and_record(hours: int, clean_unknow: bool, creds: dict | None):
    try:
        result = run_mail_cleanup(
            hours, clean_unknow=clean_unknow, creds=creds, progress_cb=_set_progress
        )
        with _STATE_LOCK:
            _STATE["last_result"] = result
            _STATE["last_error"] = None if result.get("ok") else "; ".join(
                (result.get("fatal") or result.get("server_batch_errors") or [])[:3]
            )[:200]
    except Exception as exc:
        with _STATE_LOCK:
            _STATE["last_result"] = None
            _STATE["last_error"] = str(exc)[:200]
    finally:
        with _STATE_LOCK:
            _STATE["running"] = False
