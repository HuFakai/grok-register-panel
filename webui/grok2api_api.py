"""Grok2API 管理 API 客户端（Web SSO 导入 / 转 Build / 转 Console）。

对接 grok2api 管理 API（文档 §2，基础路径 /api/admin/v1）：
- POST /auth/login → accessToken（进程内缓存，401 自动重登）
- POST /accounts/web/import      导入 Grok Web SSO（multipart + SSE）
- POST /accounts/web/convert-to-build  Web → Build（Device Flow OAuth，SSE）
- POST /accounts/web/sync-to-console   Web → Console（SSE）

所有长任务接口用 SSE（text/event-stream）返回进度：event 为
progress / error / complete。本模块只负责请求构造与 SSE 解析，不含
面板/进程编排（见 grok2api_upload / grok2api_upload_ops）。
"""

from __future__ import annotations

import json
import logging
from typing import Iterator

import requests

ADMIN_API_BASE = "/api/admin/v1"
IMPORT_CHUNK_SIZE = 10000  # 单次导入上限（文档 §2.15）
LOGIN_PATH = f"{ADMIN_API_BASE}/auth/login"
IMPORT_WEB_PATH = f"{ADMIN_API_BASE}/accounts/web/import"
CONVERT_BUILD_PATH = f"{ADMIN_API_BASE}/accounts/web/convert-to-build"
SYNC_CONSOLE_PATH = f"{ADMIN_API_BASE}/accounts/web/sync-to-console"


class Grok2apiError(RuntimeError):
    """grok2api 调用失败（含服务端 error 事件）。"""

    def __init__(self, message: str, *, code: str = ""):
        super().__init__(message)
        self.code = code


def _json_or_text(response) -> object:
    try:
        return response.json()
    except Exception:
        return response.text


def iter_sse(stream: Iterator[str]) -> Iterator[tuple[str, object]]:
    """把 SSE 文本行解析为 (event, data) 序列。

    data 尝试按 JSON 解析，失败保留原文。忽略注释行（: ...）。
    """
    event = "message"
    data_lines: list[str] = []
    for raw_line in stream:
        line = (raw_line or "").rstrip("\r\n")
        if line == "":
            # 空行 = 事件边界；累积的 data 行组成一个事件
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines = []
                try:
                    yield event, json.loads(payload)
                except (ValueError, TypeError):
                    yield event, payload
                event = "message"
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
            continue
        if line.startswith("data:"):
            data_lines.append(line[len("data:"):].strip())
            continue
    if data_lines:
        payload = "\n".join(data_lines)
        try:
            yield event, json.loads(payload)
        except (ValueError, TypeError):
            yield event, payload


def drain_sse_to_report(
    response,
    *,
    label: str,
    logger: logging.Logger | None = None,
) -> dict:
    """消费 SSE 流直到 complete/error，返回 complete 的 data（dict）。

    error 事件抛 Grok2apiError；网络中断抛 Grok2apiError。
    """
    report: dict = {}
    try:
        chunks = response.iter_lines(decode_unicode=True)
    except Exception as exc:
        raise Grok2apiError(f"{label}: SSE 读取失败: {exc}") from exc
    for event, data in iter_sse(chunks):
        if logger:
            if event == "progress" and isinstance(data, dict):
                logger.info(
                    "%s progress: %s", label,
                    json.dumps(data, ensure_ascii=False, sort_keys=True),
                )
        if event == "error":
            code = ""
            message = str(data)
            if isinstance(data, dict):
                code = str(data.get("code") or "")
                message = str(data.get("message") or message)
            raise Grok2apiError(f"{label} 失败: {message}", code=code)
        if event == "complete":
            if isinstance(data, dict):
                report = data
            else:
                report = {"detail": str(data)}
            break
    return report


class Grok2apiClient:
    """管理 API 客户端。持有 base_url 与凭据，登录 token 缓存并自动重登。"""

    def __init__(
        self,
        base_url: str,
        username: str = "",
        password: str = "",
        *,
        timeout: float = 30.0,
        logger: logging.Logger | None = None,
        session: requests.Session | None = None,
    ):
        self.base_url = str(base_url or "").rstrip("/")
        self.username = str(username or "")
        self.password = str(password or "")
        self.timeout = float(timeout)
        self.logger = logger
        self._token = ""
        self._session = session if session is not None else requests.Session()

    # ---- auth ----
    def login(self) -> str:
        if not self.base_url or not self.username or not self.password:
            raise Grok2apiError("grok2api 未配置（url/user/password）", code="notConfigured")
        resp = self._session.post(
            f"{self.base_url}{LOGIN_PATH}",
            json={"username": self.username, "password": self.password},
            timeout=self.timeout,
        )
        if resp.status_code >= 400:
            raise Grok2apiError(
                f"grok2api 登录失败 HTTP {resp.status_code}: {_json_or_text(resp)[:200]}",
                code="loginFailed",
            )
        try:
            data = resp.json()
            token = str(
                ((data.get("data") or {}).get("tokens") or {}).get("accessToken") or ""
            )
        except Exception:
            token = ""
        if not token:
            raise Grok2apiError("grok2api 登录响应缺少 accessToken", code="loginFailed")
        self._token = token
        if self.logger:
            self.logger.info("grok2api 登录成功")
        return token

    def _auth_headers(self) -> dict:
        if not self._token:
            self.login()
        return {"Authorization": f"Bearer {self._token}"}

    # ---- Web SSO 导入 ----
    def import_web_accounts(self, jsonl_content: str, filename: str = "web_accounts.jsonl") -> dict:
        """上传 Grok Web SSO（JSONL 内容），SSE 到 complete 返回导入结果。"""
        payload = {"files": (filename, str(jsonl_content or "").encode("utf-8"))}
        resp = self._session.post(
            f"{self.base_url}{IMPORT_WEB_PATH}",
            files=payload,
            headers=self._auth_headers(),
            timeout=(10.0, self.timeout * 10),
            stream=True,
        )
        if resp.status_code >= 400:
            raise Grok2apiError(
                f"grok2api 导入失败 HTTP {resp.status_code}: {_json_or_text(resp)[:200]}",
                code="importFailed",
            )
        return drain_sse_to_report(resp, label="导入 Web 账号", logger=self.logger)

    # ---- Web → Build ----
    def convert_to_build(self) -> dict:
        """转换全部未转换的 Web 账号为 Build（strategy=missing，幂等）。"""
        resp = self._session.post(
            f"{self.base_url}{CONVERT_BUILD_PATH}",
            json={"all": True, "strategy": "missing"},
            headers=self._auth_headers(),
            timeout=(10.0, self.timeout * 20),
            stream=True,
        )
        if resp.status_code >= 400:
            raise Grok2apiError(
                f"grok2api 转 Build 失败 HTTP {resp.status_code}: {_json_or_text(resp)[:200]}",
                code="convertFailed",
            )
        return drain_sse_to_report(resp, label="转 Build", logger=self.logger)

    # ---- Web → Console ----
    def sync_to_console(self) -> dict:
        """同步全部 Web 账号到 Console（strategy=all）。"""
        resp = self._session.post(
            f"{self.base_url}{SYNC_CONSOLE_PATH}",
            json={"all": True, "strategy": "all"},
            headers=self._auth_headers(),
            timeout=(10.0, self.timeout * 20),
            stream=True,
        )
        if resp.status_code >= 400:
            raise Grok2apiError(
                f"grok2api 转 Console 失败 HTTP {resp.status_code}: {_json_or_text(resp)[:200]}",
                code="syncFailed",
            )
        return drain_sse_to_report(resp, label="转 Console", logger=self.logger)
