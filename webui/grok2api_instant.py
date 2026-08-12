"""grok2api 即时上传：注册成功即一号一传（导入 + 转Build + 转Console）。

注册成功块调用 enqueue_instant_upload() 把账号丢进内存队列（毫秒级返回，
绝不阻塞注册 worker），独立的单个 daemon worker 线程串行消费：对每个账号
login → import（单行 JSONL）→ 按邮箱查 id → convert-to-build → sync-to-console。

设计要点：
- 队列 + 单 worker 天然串行，不会并发打爆 grok2api 服务端；
- 配置开关 grok2api_instant_upload 为 true 且 url/user/password 就绪才入队；
- 任何异常只在日志里记录（log/grok2api_instant.log，0o600），永不抛出；
- 日志脱敏：只记 email 与结果计数，密码 / sso 全文一律不落盘。
"""

from __future__ import annotations

import json
import logging
import queue
import re
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secure_files import best_effort_fchmod, ensure_private_dir

LOG_DIR = ROOT / "log"
INSTANT_LOG = LOG_DIR / "grok2api_instant.log"
CONFIG_FILE = ROOT / "config.json"


def _account_jsonl(email: str, sso: str) -> str:
    record = {
        "provider": "grok_web",
        "name": email,
        "email": email,
        "sso_token": sso,
        "tier": "auto",
    }
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"


class _InstantUploader:
    """模块级单例：队列 + 单个 daemon worker 线程。"""

    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._logger: logging.Logger | None = None
        # 进程内统计（供 instant_status() 展示）
        self._stats = {"processed": 0, "succeeded": 0, "failed": 0}

    # ---- logger（懒初始化，写 log/grok2api_instant.log，0o600）----
    def _log(self, level: int, message: str) -> None:
        if self._logger is None:
            with self._lock:
                if self._logger is None:
                    self._logger = self._make_logger()
        if self._logger is not None:
            self._logger.log(level, message)

    def _make_logger(self) -> logging.Logger | None:
        try:
            ensure_private_dir(LOG_DIR)
            handler = logging.FileHandler(INSTANT_LOG, encoding="utf-8")
            try:
                best_effort_fchmod(handler.stream.fileno(), 0o600)
            except OSError:
                pass
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            )
            logger = logging.getLogger("grok2api_instant")
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            logger.propagate = False
            return logger
        except Exception:
            return None

    # ---- 入队（注册成功块调用，永不阻塞、永不抛出）----
    def enqueue(
        self,
        email: str,
        sso: str,
        password: str,
        task_subdir: str | None = None,
    ) -> bool:
        try:
            from webui.grok2api_upload import configured, load_config

            config = load_config(CONFIG_FILE)
            if not config.get("grok2api_instant_upload"):
                return False
            if not configured(config):
                return False
            item = {
                "email": str(email or ""),
                "sso": str(sso or ""),
                "password": str(password or ""),
                "task_subdir": task_subdir,
                "time": _now_str(),
            }
            if not item["email"] or not item["sso"]:
                return False
            self._queue.put(item)
            self._ensure_worker()
            return True
        except Exception:
            return False

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                thread = threading.Thread(
                    target=self._run,
                    name="grok2api-instant-uploader",
                    daemon=True,
                )
                self._thread = thread
                thread.start()

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get()
            except Exception:
                return
            try:
                self._upload_one(item)
            finally:
                self._queue.task_done()

    # ---- 单个账号：login → import → 查 id → 转 Build → 转 Console ----
    def _upload_one(self, item: dict) -> None:
        email = item.get("email") or ""
        self._stats["processed"] += 1
        try:
            from webui.grok2api_api import Grok2apiClient
            from webui.grok2api_upload import configured, load_config

            config = load_config(CONFIG_FILE)
            if not configured(config):
                raise RuntimeError("grok2api 未配置（grok2api_admin_url/user/password）")
            client = Grok2apiClient(
                config["grok2api_admin_url"],
                username=str(config.get("grok2api_admin_user", "")),
                password=str(config.get("grok2api_admin_password", "")),
                logger=self._logger,
            )
            self._log(logging.INFO, f"[即时上传] {email} 开始")
            client.login()
            import_report = client.import_web_accounts(
                _account_jsonl(email, item.get("sso") or "")
            )
            self._log(
                logging.INFO,
                f"[即时上传] {email} 导入完成 created={import_report.get('created', 0)} "
                f"updated={import_report.get('updated', 0)} skipped={import_report.get('skipped', 0)}",
            )
            account_id = client.find_web_account_id(email)
            if not account_id:
                self._stats["failed"] += 1
                self._log(logging.WARNING, f"[即时上传] {email} 未查到账号 id，跳过转换")
                return
            convert_report = client.convert_accounts_by_ids([account_id])
            self._log(
                logging.INFO,
                f"[即时上传] {email} 转 Build 完成 created={convert_report.get('created', 0)} "
                f"linked={convert_report.get('linked', 0)}",
            )
            sync_report = client.sync_accounts_by_ids([account_id])
            self._log(
                logging.INFO,
                f"[即时上传] {email} 转 Console 完成 synced={sync_report.get('synced', 0)}",
            )
            self._stats["succeeded"] += 1
            self._log(logging.INFO, f"[即时上传] {email} 全部完成")
        except Exception as exc:
            self._stats["failed"] += 1
            self._log(logging.ERROR, f"[即时上传] {email} 失败: {_safe_message(exc)}")

    def status(self) -> dict:
        lines = _tail_log(INSTANT_LOG, limit=20)
        return {
            "queued": self._queue.qsize(),
            "processed": self._stats["processed"],
            "succeeded": self._stats["succeeded"],
            "failed": self._stats["failed"],
            "log_tail": lines,
        }


# 模块级单例
_UPLOADER = _InstantUploader()


def enqueue_instant_upload(
    email: str,
    sso: str,
    password: str,
    task_subdir: str | None = None,
) -> bool:
    """注册成功块调用：把账号丢进即时上传队列（异步，不阻塞注册）。

    开关未开启 / grok2api 未配置 / 参数非法时静默返回 False。
    """
    return _UPLOADER.enqueue(email, sso, password, task_subdir=task_subdir)


def instant_status() -> dict:
    """即时上传状态（进程内统计 + 日志尾部），供面板/调试展示。"""
    return _UPLOADER.status()


def _now_str() -> str:
    import datetime

    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _safe_message(exc: Exception) -> str:
    """异常信息脱敏：sso / password / token 值统一替换为 [redacted]。"""
    text = str(exc or "")
    for key in ("sso", "password", "token", "passwd", "secret"):
        text = re.sub(
            rf"{key}[=:]\s*[^\s,;\"]+",
            f"{key}=[redacted]",
            text,
            flags=re.IGNORECASE,
        )
    return text


def _tail_log(path: Path, limit: int = 20) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        return lines[-max(0, int(limit)):]
    except OSError:
        return []
