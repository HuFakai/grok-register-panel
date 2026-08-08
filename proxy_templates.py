"""Safe expansion and matching for sticky proxy identity templates."""

from __future__ import annotations

import re
from urllib.parse import quote, unquote, urlsplit


SESSION_TOKENS = ("{session}", "{account}")
WORKER_TOKEN = "{worker}"
ALL_TOKENS = (*SESSION_TOKENS, WORKER_TOKEN)
_IDENTITY_RE = r"[A-Za-z0-9._-]+"


def _username(url: object) -> str:
    try:
        return unquote(urlsplit(str(url or "")).username or "")
    except Exception:
        return ""


def has_proxy_template(url: object) -> bool:
    username = _username(url)
    return any(token in username for token in ALL_TOKENS)


def validate_proxy_template_parts(url: object) -> None:
    """Allow supported tokens only in the username portion of a proxy URL."""
    raw = str(url or "")
    parsed = urlsplit(raw)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    for token in ALL_TOKENS:
        if token in raw and token not in username:
            raise ValueError("Resin 占位符只能写在代理用户名中")
    leftovers = re.findall(r"\{[^{}]+\}", username)
    unsupported = [token for token in leftovers if token not in ALL_TOKENS]
    if unsupported:
        raise ValueError("仅支持 {session}、{account}、{worker} 占位符")
    if any(token in password for token in ALL_TOKENS):
        raise ValueError("Resin 占位符不能写在代理密码中")


def expand_proxy_template(
    url: object,
    worker_id: int = 0,
    rotate_idx: int = 0,
    *,
    identity: str | None = None,
) -> str:
    """Expand a proxy username template while preserving credentials safely."""
    raw = str(url or "").strip()
    if not has_proxy_template(raw):
        return raw
    parsed = urlsplit(raw)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    worker_id = max(0, int(worker_id))
    rotate_idx = max(0, int(rotate_idx))
    session_identity = identity or f"grokreg-w{worker_id + 1}-r{rotate_idx}"
    username = username.replace("{session}", session_identity)
    username = username.replace("{account}", session_identity)
    username = username.replace(WORKER_TOKEN, f"w{worker_id + 1}")
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"{parsed.scheme}://{auth}{host}:{parsed.port}"


def proxy_template_matches(template_url: object, effective_url: object) -> bool:
    """Return whether an expanded URL originated from the stored template."""
    template = str(template_url or "")
    effective = str(effective_url or "")
    if template == effective:
        return True
    if not has_proxy_template(template):
        return False
    try:
        left = urlsplit(template)
        right = urlsplit(effective)
        if (
            left.scheme.lower(),
            (left.hostname or "").lower(),
            left.port,
            unquote(left.password or ""),
        ) != (
            right.scheme.lower(),
            (right.hostname or "").lower(),
            right.port,
            unquote(right.password or ""),
        ):
            return False
        pattern = re.escape(unquote(left.username or ""))
        for token in ALL_TOKENS:
            pattern = pattern.replace(re.escape(token), _IDENTITY_RE)
        return re.fullmatch(pattern, unquote(right.username or "")) is not None
    except (TypeError, ValueError):
        return False
