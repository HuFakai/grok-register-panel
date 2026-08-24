"""Inbucket 自托管临时邮箱提供商。

项目地址：https://github.com/inbucket/inbucket
邮箱即建即用：任意本地部分 + 指向实例的收信域名即可收信，
REST API 为 GET/DELETE /api/v1/mailbox/{name}，{name} 传完整
邮箱地址即可，服务端会按自身 MailboxNaming（local/full）解析。
"""

from __future__ import annotations

import random
import re
import string
import threading
import time
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import quote, urlparse

from email_providers.common import extract_verification_code, generate_username

HttpGet = Callable[..., Any]
HttpDelete = Callable[..., Any]

# 随机子域最多叠加的标签数，防止手改配置写出超长域名
MAX_RANDOM_LEVELS = 4

_domain_index = 0
_domain_lock = threading.Lock()


def reset_runtime_state() -> None:
    """测试用：重置根域名轮换游标。"""
    global _domain_index
    with _domain_lock:
        _domain_index = 0


def normalize_base(base_url: str = "") -> str:
    """实例根 URL（去尾斜杠，保留 INBUCKET_WEB_BASEPATH 前缀）。"""
    raw = str(base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    path = (parsed.path or "").rstrip("/")
    return f"{origin}{path}" if path else origin


def _api(base_url: str, path: str) -> str:
    base = normalize_base(base_url)
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _mailbox_path(address: str) -> str:
    return quote(str(address or "").strip().lower(), safe="")


def _raise_http(resp, action: str) -> None:
    status = int(getattr(resp, "status_code", 0) or 0)
    if status < 400:
        return
    detail = str(getattr(resp, "text", "") or "")[:300]
    raise Exception(f"Inbucket {action}失败 HTTP {status}: {detail or 'unknown'}")


def parse_domains(raw: object) -> List[str]:
    """解析逗号/空白分隔的多个收信根域名。"""
    parts = re.split(r"[,，\s]+", str(raw or "").strip())
    seen: set[str] = set()
    domains = []
    for part in parts:
        domain = part.strip().lstrip("@").lower().rstrip(".")
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def parse_levels(spec: object) -> Tuple[int, int]:
    """解析随机子域级数：'0'→(0,0)；'2'→(2,2)；'1-3'→(1,3)。

    非法值退回 (0,0)，上限 MAX_RANDOM_LEVELS。
    """
    text = str(spec or "0").strip()
    match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", text)
    if match:
        low, high = int(match.group(1)), int(match.group(2))
    else:
        try:
            low = high = int(text)
        except ValueError:
            return 0, 0
    if high < low:
        low, high = high, low
    low = max(0, min(low, MAX_RANDOM_LEVELS))
    high = max(0, min(high, MAX_RANDOM_LEVELS))
    return low, high


def _random_label() -> str:
    """一级随机子域标签：短随机串，偶尔带邮箱词汇更像真实域名。"""
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 10)))
    if random.random() < 0.35:
        word = random.choice([
            "mail", "inbox", "box", "get", "app", "go", "my", "use", "fast", "safe",
            "home", "note", "post", "send", "hub", "net", "lab", "pro",
        ])
        label = f"{word}{random.randint(10, 99)}"
    return label


def random_email_domain(raw_roots: object, levels: object = "0") -> str:
    """轮换选一个根域名，并按级数设置叠加随机子域标签。

    多根域名轮询均摊；随机级数需要泛解析（*.root 的 MX 指向实例）。
    """
    roots = parse_domains(raw_roots)
    if not roots:
        raise Exception("Inbucket 收信域名未配置（inbucket_domain）")
    global _domain_index
    with _domain_lock:
        root = roots[_domain_index % len(roots)]
        _domain_index += 1
    low, high = parse_levels(levels)
    count = random.randint(low, high) if high > low else low
    domain = root
    for _ in range(count):
        domain = f"{_random_label()}.{domain}"
    return domain


def create_address(domain: str, username: str = "", random_levels: object = "0") -> Tuple[str, str]:
    """Inbucket 无需建号 API：本地生成地址（域名需指向实例收信）。"""
    chosen = random_email_domain(domain, random_levels)
    address = f"{(username or generate_username(10)).strip().lower()}@{chosen}"
    return address, address


def list_messages(http_get: HttpGet, base_url: str, address: str) -> List[dict]:
    """GET /api/v1/mailbox/{name} → [{id, from, subject, date, size, seen}]。"""
    resp = http_get(
        _api(base_url, f"/api/v1/mailbox/{_mailbox_path(address)}"),
        headers={"Accept": "application/json"},
        timeout=20,
        proxies={},
    )
    _raise_http(resp, "拉取邮件")
    try:
        data = resp.json()
    except Exception as exc:
        preview = str(getattr(resp, "text", "") or "")[:300]
        raise Exception(f"Inbucket 拉取邮件返回非 JSON: {preview}") from exc
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def get_message_detail(
    http_get: HttpGet,
    base_url: str,
    address: str,
    message_id: str,
) -> dict:
    """GET /api/v1/mailbox/{name}/{id} → {..., body: {text, html}}。"""
    resp = http_get(
        _api(
            base_url,
            f"/api/v1/mailbox/{_mailbox_path(address)}/{quote(str(message_id), safe='')}",
        ),
        headers={"Accept": "application/json"},
        timeout=20,
        proxies={},
    )
    _raise_http(resp, "获取邮件详情")
    try:
        data = resp.json()
    except Exception as exc:
        preview = str(getattr(resp, "text", "") or "")[:300]
        raise Exception(f"Inbucket 获取邮件详情返回非 JSON: {preview}") from exc
    return data if isinstance(data, dict) else {}


def purge_mailbox(http_delete: Optional[HttpDelete], base_url: str, address: str) -> None:
    """DELETE /api/v1/mailbox/{name}，清理用完的邮箱（尽力而为）。"""
    if http_delete is None or not str(address or "").strip():
        return
    try:
        http_delete(
            _api(base_url, f"/api/v1/mailbox/{_mailbox_path(address)}"),
            headers={"Accept": "application/json"},
            timeout=15,
            proxies={},
        )
    except Exception:
        return


def _message_text(detail: dict, subject: str = "") -> Tuple[str, str]:
    parts: List[str] = []
    subj = str(subject or detail.get("subject") or "")
    body = detail.get("body")
    if isinstance(body, dict):
        for field in ("text", "html"):
            value = body.get(field)
            if isinstance(value, str) and value.strip():
                parts.append(re.sub(r"<[^>]+>", " ", value))
    for field in ("text", "html", "body", "content"):
        value = detail.get(field)
        if isinstance(value, str) and value.strip():
            parts.append(re.sub(r"<[^>]+>", " ", value))
    return subj, "\n".join(parts)


def wait_for_code(
    http_get: HttpGet,
    base_url: str,
    address: str,
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    http_delete: Optional[HttpDelete] = None,
    cleanup: bool = True,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    """轮询邮箱列表 + 详情，提取 xAI 验证码。"""
    base = normalize_base(base_url)
    mailbox = str(address or "").strip().lower()
    if not base:
        raise Exception("Inbucket 实例地址未配置（inbucket_api_base）")
    if not mailbox:
        raise Exception("Inbucket 邮箱地址为空")

    deadline = time.time() + timeout
    seen_attempts: dict[str, int] = {}
    next_resend_at = time.time() + 35

    try:
        while time.time() < deadline:
            raise_if_cancelled(cancel_callback)
            if resend_callback and time.time() >= next_resend_at:
                try:
                    resend_callback()
                    if log_callback:
                        log_callback("[*] 已触发重新发送验证码")
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] 触发重发验证码失败: {exc}")
                next_resend_at = time.time() + 35

            try:
                messages = list_messages(http_get, base, mailbox)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] Inbucket 拉取邮件失败: {exc}")
                sleep_with_cancel(poll_interval, cancel_callback)
                continue

            if log_callback:
                log_callback(f"[Debug] Inbucket 本轮邮件数量: {len(messages)}")

            for msg in messages:
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id:
                    continue
                attempt = int(seen_attempts.get(msg_id, 0))
                if attempt >= 5:
                    continue
                seen_attempts[msg_id] = attempt + 1

                list_subject = str(msg.get("subject") or "")
                # xAI 主题常带验证码，先按主题提取一次，避免多拉详情
                code = extract_verification_code(list_subject, list_subject)
                if code:
                    if log_callback:
                        log_callback(f"[*] Inbucket 从主题提取到验证码: {code}")
                    return code

                try:
                    detail = get_message_detail(http_get, base, mailbox, msg_id)
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] Inbucket 获取邮件详情失败: {exc}")
                    continue

                subject, combined = _message_text(detail, list_subject)
                if log_callback:
                    log_callback(f"[Debug] Inbucket 收到邮件: {subject or list_subject}")
                code = extract_verification_code(combined, subject or list_subject)
                if code:
                    if log_callback:
                        log_callback(f"[*] Inbucket 从邮件中提取到验证码: {code}")
                    return code
                if log_callback:
                    log_callback(
                        "[Debug] 邮件已解析但未提取到验证码 "
                        f"id={msg_id} attempt={seen_attempts[msg_id]}"
                    )

            sleep_with_cancel(poll_interval, cancel_callback)
        raise Exception(f"Inbucket 在 {timeout}s 内未收到验证码邮件")
    finally:
        if cleanup:
            purge_mailbox(http_delete, base, mailbox)
