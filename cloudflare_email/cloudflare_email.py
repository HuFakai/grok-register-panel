"""Cloudflare Worker 临时邮箱核心功能（cloudflare_temp_email 兼容）— 精简版。

覆盖一条完整链路：建号（catch-all 免建号 / admin 建号）→ 轮询收信 →
提取 xAI 验证码 → 删信。仅标准库；HTTP 请求通过注入 requests 兼容的
http_get / http_post / http_delete 回调完成，便于测试与复用。

相对主工程完整版（email_providers/cloudflare.py + common.py）的裁剪：
- 移除旧版 address/password 建号 fallback（get_domains/create_account/
  get_token/create_mailbox_fallback）与配置胶水（path_from_config、
  next_default_domain），主工程仍有；
- 验证码提取、用户名生成做等价压缩（启发式保留、词表缩小）；
- wait_for_code 的取消/睡眠改为内置实现，签名更简单。
行为细节与来源映射见同目录 README.md。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import secrets
import string
import time
from typing import Any, Callable, List, Optional

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]

__all__ = [
    "build_headers", "apply_auth_params", "apply_custom_auth", "is_admin_create_path",
    "generate_username", "random_subdomain_domain",
    "cloudflare_catchall_email_and_token",
    "create_temp_address", "get_messages", "get_message_detail",
    "wait_for_code", "delete_mail", "extract_verification_code",
]


# ---------------------------------------------------------------------------
# 鉴权（五种 auth_mode + 全局访问密码叠加）
# ---------------------------------------------------------------------------
def apply_custom_auth(headers: dict, custom_auth: str = "") -> dict:
    """全局访问密码（服务端 PASSWORDS）：所有请求附加 x-custom-auth。"""
    if custom_auth:
        headers["x-custom-auth"] = custom_auth
    return headers


def build_headers(api_key: str = "", auth_mode: str = "none", custom_auth: str = "", content_type: bool = False) -> dict:
    headers = {"Content-Type": "application/json"} if content_type else {}
    mode = (auth_mode or "none").lower()
    if api_key:
        if mode == "x-api-key":
            headers["X-API-Key"] = api_key
        elif mode == "x-admin-auth":
            headers["x-admin-auth"] = api_key
        elif mode != "none":
            headers["Authorization"] = f"Bearer {api_key}"
    return apply_custom_auth(headers, custom_auth)


def apply_auth_params(params: Optional[dict], api_key: str = "", auth_mode: str = "none") -> dict:
    merged = dict(params or {})
    if api_key and (auth_mode or "").lower() == "query-key":
        merged["key"] = api_key
    return merged


def is_admin_create_path(path: str) -> bool:
    return str(path or "").rstrip("/").lower() == "/admin/new_address"


# ---------------------------------------------------------------------------
# 地址生成
# ---------------------------------------------------------------------------
_FIRST = ("james", "john", "michael", "david", "daniel", "mary", "jennifer", "emily", "sarah", "olivia")
_LAST = ("smith", "johnson", "williams", "brown", "jones", "miller", "davis", "wilson", "taylor", "moore", "lee", "clark")


def generate_username(length: int = 10) -> str:
    """拟真邮箱本地部分（姓名池 + 变体 + 短随机后缀防并发撞名）。"""
    first, last = random.choice(_FIRST), random.choice(_LAST)
    n = random.randint(0, 99)
    name = random.choice([
        f"{first}.{last}", f"{first}{last}", f"{first}.{last}{n}",
        f"{first}{n}", f"{first}_{last}", f"{first[0]}{last}{n}",
    ])
    name = "".join(ch for ch in name if ch.isalnum() or ch in "._-")[:24]
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=3))
    return f"{name}{suffix}"


def random_subdomain_domain(apex: str) -> str:
    """在根域下生成一次性随机子域（需服务端对 *.根域 开 catch-all 收信）。"""
    apex = str(apex or "").strip().lower().lstrip("@")
    if not apex or "." not in apex:
        return apex
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 10)))
    parts = apex.split(".")
    if len(parts) >= 3:
        parts[0] = label
        return ".".join(parts)
    return f"{label}.{apex}"


def _sign_cloudflare_address_jwt(secret: str, address: str, address_id: int = 0) -> str:
    """按服务端格式自签地址 JWT：HS256，payload={address, address_id}（纯标准库）。"""
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    payload = _b64url(
        json.dumps({"address": str(address), "address_id": int(address_id or 0)}, ensure_ascii=False).encode("utf-8")
    )
    signing = f"{header}.{payload}".encode("utf-8")
    signature = _b64url(hmac.new(str(secret).encode("utf-8"), signing, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def cloudflare_catchall_email_and_token(jwt_secret: str, domain: str = "") -> tuple[str, str]:
    """catch-all 免建号：随机账号 + 随机子域 + 自签收信 JWT，零 API 调用。

    要求服务端开启 *.根域 全子域 catch-all。返回 (address, jwt)。
    """
    base_domain = str(domain or "").strip()
    if not base_domain:
        raise Exception("Cloudflare catch-all 未配置收信域名（defaultDomains）")
    address = f"{generate_username(10)}@{random_subdomain_domain(base_domain)}"
    return address, _sign_cloudflare_address_jwt(jwt_secret, address, 0)


# ---------------------------------------------------------------------------
# 建号（admin / 直建，含撞名重试）
# ---------------------------------------------------------------------------
_COLLISION_MARKERS = ("already exists", "address exists", "duplicate address")


def create_temp_address(
    http_post: HttpPost,
    api_base: str,
    *,
    accounts_path: str = "/api/new_address",
    domain: str = "",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
    name: str = "",
    randomize_subdomain: bool = True,
) -> tuple[str, str]:
    """建号并返回 (address, jwt)。

    - /admin/new_address：管理员模式，payload={name, enablePrefix:False, domain?}；
      不能用旧版 address/password payload（服务端会 400 Required field）。
    - 其他路径（如 /api/new_address）：开放模式，payload={domain?}。
    - 并发撞名（400/409 Address already exists）自动换随机名重试，最多 4 次；
      其余错误立即抛出，且不回显响应体（避免泄露服务端敏感信息）。
    - randomize_subdomain：建号地址挂随机子域，降低根域被批量风控的权重。
    """
    path = accounts_path if accounts_path.startswith("/") else f"/{accounts_path}"
    url = f"{api_base.rstrip('/')}{path}"
    if domain and randomize_subdomain:
        domain = random_subdomain_domain(domain)

    last_err: Exception | None = None
    for attempt in range(4):
        local_name = str(name or "").strip()
        if not local_name or attempt > 0:
            local_name = f"{generate_username(10)}{secrets.token_hex(2)}"
        if is_admin_create_path(path):
            payload = {"name": local_name, "enablePrefix": False}
            if domain:
                payload["domain"] = domain
            headers = build_headers(api_key, auth_mode, custom_auth, content_type=True)
        else:
            payload = {"domain": domain} if domain else {}
            headers = apply_custom_auth({"Content-Type": "application/json"}, custom_auth)
        try:
            resp = http_post(url, json=payload, headers=headers)
            if resp.status_code >= 400:
                body = str(getattr(resp, "text", "") or "").lower()
                if attempt < 3 and resp.status_code in (400, 409) and any(m in body for m in _COLLISION_MARKERS):
                    name = ""  # 下一轮换随机名
                    time.sleep(0.15 * (attempt + 1))
                    continue
                raise Exception(f"Cloudflare {path} HTTP {resp.status_code}")
            data = resp.json()
            address, jwt = data.get("address"), data.get("jwt")
            if not address or not jwt:
                raise Exception(f"Cloudflare {path} 返回缺少 address/jwt 字段")
            return address, jwt
        except Exception as exc:
            if attempt < 3 and any(m in str(exc).lower() for m in _COLLISION_MARKERS):
                name = ""
                last_err = exc
                time.sleep(0.15 * (attempt + 1))
                continue
            raise
    raise Exception("Cloudflare 创建邮箱失败（地址冲突重试耗尽）") from last_err


# ---------------------------------------------------------------------------
# 收信
# ---------------------------------------------------------------------------
def pick_list_payload(data: Any) -> List[dict]:
    """兼容裸列表与 results / messages / data（含 data.messages）包裹的响应。"""
    if isinstance(data, dict):
        nested = data.get("data")
        for candidate in (data.get("results"), data.get("messages"), data.get("data"),
                          nested.get("messages") if isinstance(nested, dict) else None):
            if isinstance(candidate, list):
                data = candidate
                break
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _auth_headers(token: str, custom_auth: str) -> dict:
    return apply_custom_auth({"Authorization": f"Bearer {token}"}, custom_auth)


def get_messages(http_get: HttpGet, api_base: str, token: str, *, messages_path: str = "/messages",
                 api_key: str = "", auth_mode: str = "none", custom_auth: str = "") -> List[dict]:
    headers = _auth_headers(token, custom_auth)
    path = messages_path if messages_path.startswith("/") else f"/{messages_path}"
    resp = http_get(
        f"{api_base.rstrip('/')}{path}",
        headers=headers,
        params=apply_auth_params({"limit": 20, "offset": 0}, api_key, auth_mode),
    )
    resp.raise_for_status()
    try:
        return pick_list_payload(resp.json())
    except Exception:
        raise Exception(f"Cloudflare messages 返回非JSON: {resp.text[:300]}")


def get_message_detail(http_get: HttpGet, api_base: str, token: str, message_id: Any, *,
                       messages_path: str = "/messages", api_key: str = "",
                       auth_mode: str = "none", custom_auth: str = "") -> dict:
    """邮件详情：不同部署详情路径不同，先试 /api/mail/{id} 再试 {收信接口}/{id}。"""
    headers = _auth_headers(token, custom_auth)
    path = messages_path if messages_path.startswith("/") else f"/{messages_path}"
    base = api_base.rstrip("/")
    last_err: Exception | None = None
    for url in (f"{base}/api/mail/{message_id}", f"{base}{path}/{message_id}"):
        try:
            resp = http_get(url, headers=headers,
                            params=apply_auth_params({}, api_key, auth_mode))
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                return data["data"]
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            last_err = exc
    raise Exception(f"Cloudflare 获取邮件详情失败: {last_err}")


# ---------------------------------------------------------------------------
# 验证码提取（xAI：XXX-YYY，如 QO7-TUD；新模板主题可为全数字 427-599）
# ---------------------------------------------------------------------------
_CODE_RE = re.compile(r"\b([A-Za-z0-9]{3}-[A-Za-z0-9]{3})\b")
# 邮件 HTML 模板常见伪码左词（per-100 / max-100 …）
_BAD_LEFT = {
    "per", "max", "min", "top", "all", "col", "row", "box", "pad", "gap",
    "css", "img", "src", "div", "span", "flex", "grid", "auto", "btn",
    "tab", "nav", "png", "jpg", "svg", "pdf", "key", "val", "num", "pct",
}
_CODE_KEYWORDS = {
    "spacexai": 10, "x.ai": 8, "xai": 8, "confirmation code": 8,
    "verification": 6, "security code": 6, "verify": 5, "one-time": 5,
    "your code": 5, "code is": 4, "code:": 4, "验证码": 6, "确认码": 6,
}
_HTML_MARKERS = ("class=", "stylesheet", "width:", "percent", "padding", "margin")


def extract_verification_code(text: str, subject: str = "") -> Optional[str]:
    """从主题/正文提取 xAI 验证码（形如 XXX-YYY）。

    先按主题/句式锚定，再对全文候选打分（字母数字混合加分、靠近
    verification/xai 等关键词加分、靠近 HTML 样式特征扣分），过滤模板伪码。
    """
    hay = f"{(subject or '').strip()}\n{text or ''}"
    low = hay.lower()
    numeric_ok = any(k in low for k in ("spacexai", "confirmation code", "x.ai", "noreply@x.ai"))

    def plausible(code: str, allow_numeric: bool = False) -> bool:
        left, _, right = str(code).partition("-")
        if len(left) != 3 or len(right) != 3 or not (left.isalnum() and right.isalnum()):
            return False
        if left.isdigit() and right.isdigit():
            return allow_numeric or numeric_ok
        return not (left.isalpha() and right.isdigit() and left.lower() in _BAD_LEFT)

    # 1) 主题/句式锚定：显式上下文里的码允许两侧全数字
    for pattern in (
        r"^([A-Za-z0-9]{3}-[A-Za-z0-9]{3})\s+xAI\b",
        r"(?:spacexai|x\.?ai|verification|security|confirm(?:ation)?)\s+code[:\s]+([A-Za-z0-9]{3}-[A-Za-z0-9]{3})\b",
    ):
        m = re.search(pattern, hay, re.IGNORECASE)
        if m and plausible(m.group(1), allow_numeric=True):
            return m.group(1).upper()

    # 2) 全文候选打分
    best, best_score = None, -10**9
    for m in _CODE_RE.finditer(hay):
        code = m.group(1)
        if not plausible(code):
            continue
        window = low[max(0, m.start() - 48): m.start() + len(code) + 48]
        score = 3 if (any(c.isalpha() for c in code) and any(c.isdigit() for c in code)) else 0
        score += sum(pts for kw, pts in _CODE_KEYWORDS.items() if kw in window)
        score -= 4 * sum(marker in window for marker in _HTML_MARKERS)
        if score > best_score:
            best, best_score = code, score
    if best:
        return best.upper()

    # 3) 兜底：明确的纯数字验证码句式
    m = re.search(
        r"(?:verification|confirm(?:ation)?)\s*code[:\s]+(\d{4,8})\b|验证码[：:\s]+(\d{4,8})",
        hay, re.IGNORECASE,
    )
    return (m.group(1) or m.group(2)) if m else None


# ---------------------------------------------------------------------------
# 轮询取码 + 删信
# ---------------------------------------------------------------------------
def _sleep(seconds: float, cancel_callback=None) -> None:
    end = time.time() + seconds
    while time.time() < end:
        if cancel_callback and cancel_callback():
            raise Exception("已取消")
        time.sleep(min(0.2, max(0.0, end - time.time())))


def _address_matched(msg: dict, email: str) -> bool:
    recipients = [str(t.get("address", "")).lower() for t in (msg.get("to") or [])]
    msg_addr = str(msg.get("address", "")).lower()
    if recipients:
        return email.lower() in recipients
    return not msg_addr or msg_addr == email.lower()


def _collect_text(payload: dict) -> str:
    """拼合邮件文本字段并去掉 HTML 标签，供验证码提取。"""
    parts = [
        value for field in ("text", "raw", "content", "intro", "body", "snippet")
        if isinstance(value := payload.get(field), str) and value.strip()
    ]
    html = payload.get("html") or []
    if isinstance(html, str):
        html = [html]
    return "\n".join(parts + [re.sub(r"<[^>]+>", " ", h) for h in html])


def wait_for_code(
    http_get: HttpGet,
    api_base: str,
    token: str,
    email: str,
    *,
    messages_path: str = "/messages",
    api_key: str = "",
    auth_mode: str = "none",
    custom_auth: str = "",
    timeout: int = 180,
    poll_interval: int = 3,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
    on_code_mail: Optional[Callable[[Any], None]] = None,
) -> str:
    """轮询收件箱直到提取到验证码；拿到后触发 on_code_mail 删信（失败不阻塞）。

    - 收件人过滤：to[].address / address 必须匹配目标邮箱，防止多 worker 串信；
    - 每 35s 未取到码触发一次 resend_callback（注册页重发验证码）；
    - 每封邮件最多解析 5 次，防止坏邮件阻塞轮询。
    """
    if not api_base:
        raise Exception("Cloudflare API Base 未配置")
    log = log_callback or (lambda _msg: None)
    deadline = time.time() + timeout
    seen_attempts: dict = {}
    next_resend_at = time.time() + 35
    while time.time() < deadline:
        if cancel_callback and cancel_callback():
            raise Exception("已取消")
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                log("[*] 已触发重新发送验证码")
            except Exception as exc:
                log(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        try:
            messages = get_messages(http_get, api_base, token, messages_path=messages_path,
                                    api_key=api_key, auth_mode=auth_mode, custom_auth=custom_auth)
        except Exception as exc:
            log(f"[Debug] Cloudflare 拉取邮件列表失败: {exc}")
            _sleep(poll_interval, cancel_callback)
            continue
        log(f"[Debug] Cloudflare 本轮邮件数量: {len(messages)}")
        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id or seen_attempts.get(msg_id, 0) >= 5:
                continue
            seen_attempts[msg_id] = seen_attempts.get(msg_id, 0) + 1
            if not _address_matched(msg, email):
                log(f"[Debug] 跳过疑似非目标邮件 id={msg_id}")
                continue
            subject = str(msg.get("subject") or "")
            combined = _collect_text(msg)
            try:
                detail = get_message_detail(http_get, api_base, token, msg_id, messages_path=messages_path,
                                            api_key=api_key, auth_mode=auth_mode, custom_auth=custom_auth)
                combined += "\n" + _collect_text(detail)
                subject = subject or str(detail.get("subject") or "")
            except Exception as exc:
                log(f"[Debug] Cloudflare detail接口失败，改用列表内容解析: {exc}")
            log(f"[Debug] Cloudflare 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                log(f"[*] Cloudflare 从邮件中提取到验证码: {code}")
                if on_code_mail:
                    try:
                        on_code_mail(msg_id)
                    except Exception as exc:
                        log(f"[Debug] Cloudflare 删除验证码邮件失败: {exc}")
                return code
        _sleep(poll_interval, cancel_callback)
    raise Exception(f"Cloudflare 在 {timeout}s 内未收到验证码邮件")


def delete_mail(http_delete: HttpGet, api_base: str, mail_id: Any, *,
                admin_auth: str = "", custom_auth: str = "") -> dict:
    """删除单封邮件：DELETE /admin/mails/{id}，鉴权 x-admin-auth（管理员密码）。"""
    url = f"{str(api_base or '').rstrip('/')}/admin/mails/{int(mail_id)}"
    headers = build_headers(admin_auth, "x-admin-auth", custom_auth)
    resp = http_delete(url, headers=headers, timeout=10)
    resp.raise_for_status()
    try:
        return resp.json()
    except Exception:
        return {"ok": True}
