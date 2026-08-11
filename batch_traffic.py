"""Per-batch HTTP proxy metering without persisting upstream proxy details."""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import select
import secrets
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

from secure_files import atomic_write_json, ensure_private_dir, exclusive_file_lock


TRAFFIC_FILE_ENV = "GROK_BATCH_TRAFFIC_FILE"
HISTORY_FILE_ENV = "GROK_BATCH_TRAFFIC_HISTORY_FILE"
BATCH_ID_ENV = "GROK_BATCH_ID"
SCHEMA_VERSION = 2
HISTORY_SCHEMA_VERSION = 1
HISTORY_LIMIT = 500
HEADER_LIMIT = 64 * 1024


def _empty_metrics() -> dict:
    return {
        "version": SCHEMA_VERSION,
        "batch_id": "",
        "running": False,
        "started_at": None,
        "updated_at": None,
        "finished_at": None,
        "bytes_up": 0,
        "bytes_down": 0,
        "bytes_total": 0,
        "connections": 0,
        "active_connections": 0,
        "metered_proxies": 0,
        "unmetered_proxies": 0,
        "target": 0,
        "workers": 0,
        "successful_accounts": 0,
        "exit_code": None,
    }


def read_metrics(path: str | os.PathLike[str]) -> dict:
    metrics = _empty_metrics()
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return metrics
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return metrics
    for key in metrics:
        if key in raw:
            metrics[key] = raw[key]
    for key in (
        "bytes_up",
        "bytes_down",
        "connections",
        "active_connections",
        "metered_proxies",
        "unmetered_proxies",
        "target",
        "workers",
        "successful_accounts",
    ):
        try:
            metrics[key] = max(0, int(metrics.get(key, 0) or 0))
        except (TypeError, ValueError):
            metrics[key] = 0
    metrics["bytes_total"] = metrics["bytes_up"] + metrics["bytes_down"]
    metrics["batch_id"] = str(metrics.get("batch_id") or "")[:96]
    metrics["running"] = bool(metrics.get("running"))
    return metrics


def _empty_history() -> dict:
    return {"version": HISTORY_SCHEMA_VERSION, "batches": []}


def _history_entry(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    batch_id = str(raw.get("batch_id") or "")[:96]
    if not batch_id:
        return None
    entry = {
        "batch_id": batch_id,
        "started_at": raw.get("started_at"),
        "finished_at": raw.get("finished_at"),
        "bytes_up": 0,
        "bytes_down": 0,
        "bytes_total": 0,
        "successful_accounts": 0,
        "target": 0,
        "workers": 0,
        "exit_code": raw.get("exit_code"),
    }
    for key in (
        "bytes_up",
        "bytes_down",
        "successful_accounts",
        "target",
        "workers",
    ):
        try:
            entry[key] = max(0, int(raw.get(key, 0) or 0))
        except (TypeError, ValueError):
            entry[key] = 0
    entry["bytes_total"] = entry["bytes_up"] + entry["bytes_down"]
    try:
        entry["exit_code"] = int(entry["exit_code"])
    except (TypeError, ValueError):
        entry["exit_code"] = None
    return entry


def read_history(path: str | os.PathLike[str]) -> dict:
    history = _empty_history()
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return history
    if not isinstance(raw, dict) or not isinstance(raw.get("batches"), list):
        return history
    history["batches"] = [
        entry
        for item in raw["batches"][-HISTORY_LIMIT:]
        if (entry := _history_entry(item)) is not None
    ]
    return history


def _history_sort_key(entry: dict) -> float:
    try:
        return float(entry.get("finished_at") or entry.get("started_at") or 0)
    except (TypeError, ValueError):
        return 0.0


def archive_batch(path: str | os.PathLike[str], metrics: object) -> bool:
    entry = _history_entry(metrics)
    if entry is None or entry["bytes_total"] <= 0:
        return False
    target = Path(path)
    ensure_private_dir(target.parent)
    with exclusive_file_lock(target.with_suffix(target.suffix + ".lock")):
        history = read_history(target)
        batches = [
            item
            for item in history["batches"]
            if item.get("batch_id") != entry["batch_id"]
        ]
        batches.append(entry)
        batches.sort(key=_history_sort_key)
        history["batches"] = batches[-HISTORY_LIMIT:]
        atomic_write_json(target, history)
    return True


def summarize_history(history: object, current: object | None = None) -> dict:
    stored = history if isinstance(history, dict) else _empty_history()
    entries = [
        entry
        for raw in (stored.get("batches") or [])
        if (entry := _history_entry(raw)) is not None and entry["bytes_total"] > 0
    ]
    archived_ids = {entry["batch_id"] for entry in entries}
    includes_current = False
    current_entry = _history_entry(current)
    if (
        current_entry is not None
        and current_entry["bytes_total"] > 0
        and current_entry["batch_id"] not in archived_ids
    ):
        entries.append(current_entry)
        includes_current = True
    total_bytes = sum(entry["bytes_total"] for entry in entries)
    successful_accounts = sum(entry["successful_accounts"] for entry in entries)
    batch_count = len(entries)
    return {
        "batch_count": batch_count,
        "completed_batch_count": batch_count - int(includes_current),
        "includes_current": includes_current,
        "total_bytes": total_bytes,
        "successful_accounts": successful_accounts,
        "bytes_per_batch": total_bytes // batch_count if batch_count else None,
        "bytes_per_success": (
            total_bytes // successful_accounts if successful_accounts else None
        ),
    }


def read_summary(
    history_path: str | os.PathLike[str],
    current: object | None = None,
) -> dict:
    return summarize_history(read_history(history_path), current)


def initialize_batch(
    path: str | os.PathLike[str],
    batch_id: str,
    *,
    target: int,
    workers: int,
) -> dict:
    now = time.time()
    metrics = _empty_metrics()
    metrics.update(
        {
            "batch_id": str(batch_id)[:96],
            "running": True,
            "started_at": now,
            "updated_at": now,
            "target": max(1, int(target)),
            "workers": max(1, int(workers)),
        }
    )
    atomic_write_json(path, metrics)
    return metrics


def finalize_batch(path: str | os.PathLike[str], batch_id: str, exit_code: int) -> dict:
    close_runtime(path=path, batch_id=batch_id)
    metrics = read_metrics(path)
    if metrics.get("batch_id") != str(batch_id):
        return metrics
    now = time.time()
    metrics.update(
        {
            "running": False,
            "updated_at": now,
            "finished_at": now,
            "active_connections": 0,
            "exit_code": int(exit_code),
        }
    )
    atomic_write_json(path, metrics)
    return metrics


class _TrafficState:
    def __init__(self, path: Path, batch_id: str):
        self.path = path
        self.batch_id = batch_id
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        existing = read_metrics(path)
        if existing.get("batch_id") != batch_id:
            existing = initialize_batch(path, batch_id, target=1, workers=1)
        self.metrics = existing
        self.metrics["running"] = True
        self.metrics["active_connections"] = 0
        self.writer = threading.Thread(target=self._writer_loop, daemon=True)
        self.writer.start()

    def _writer_loop(self) -> None:
        while not self.stop_event.wait(0.5):
            self.flush()

    def update(self, **changes: int) -> None:
        with self.lock:
            for key, delta in changes.items():
                current = max(0, int(self.metrics.get(key, 0) or 0))
                self.metrics[key] = max(0, current + int(delta))
            self.metrics["bytes_total"] = int(self.metrics["bytes_up"]) + int(
                self.metrics["bytes_down"]
            )
            self.metrics["updated_at"] = time.time()

    def flush(self) -> None:
        with self.lock:
            payload = dict(self.metrics)
        atomic_write_json(self.path, payload)

    def close(self) -> None:
        self.stop_event.set()
        self.writer.join(timeout=2)
        self.flush()


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            raise ConnectionError("connection closed before proxy headers")
        data.extend(chunk)
        if len(data) > HEADER_LIMIT:
            raise ValueError("proxy headers too large")
    head, rest = bytes(data).split(b"\r\n\r\n", 1)
    return head, rest


def _basic_authorization(username: str, password: str) -> bytes:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}".encode("ascii")


def _proxy_authorization(parsed) -> bytes | None:
    if parsed.username is None:
        return None
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    return _basic_authorization(username, password)


def _header_value(head: bytes, name: bytes) -> bytes:
    prefix = name.lower() + b":"
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(prefix):
            return line.split(b":", 1)[1].strip()
    return b""


def _rewrite_headers(head: bytes, authorization: bytes | None) -> bytes:
    lines = head.split(b"\r\n")
    output = [lines[0]]
    for line in lines[1:]:
        lowered = line.lower()
        if lowered.startswith(b"proxy-authorization:"):
            continue
        if lowered.startswith(b"proxy-connection:"):
            continue
        output.append(line)
    if authorization:
        output.append(authorization)
    return b"\r\n".join(output) + b"\r\n\r\n"


class _MeterHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.meter.handle_client(self.request)  # type: ignore[attr-defined]


class _MeterServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ProxyMeter:
    def __init__(self, upstream_url: str, state: _TrafficState):
        parsed = urlparse(upstream_url)
        self.state = state
        self.scheme = parsed.scheme
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.authorization = _proxy_authorization(parsed)
        self.local_username = "meter"
        self.local_password = secrets.token_urlsafe(18)
        self.local_authorization = _basic_authorization(
            self.local_username,
            self.local_password,
        ).split(b":", 1)[1].strip()
        self.server = _MeterServer(("127.0.0.1", 0), _MeterHandler)
        self.server.meter = self  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.state.update(metered_proxies=1)

    @property
    def local_url(self) -> str:
        return (
            f"http://{self.local_username}:{self.local_password}"
            f"@127.0.0.1:{self.server.server_address[1]}"
        )

    def _connect_upstream(self) -> socket.socket:
        if not self.host:
            raise ValueError("upstream proxy host is missing")
        upstream = socket.create_connection((self.host, self.port), timeout=15)
        if self.scheme == "https":
            context = ssl.create_default_context()
            upstream = context.wrap_socket(upstream, server_hostname=self.host)
        return upstream

    def _send_error(self, client: socket.socket) -> None:
        try:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
        except OSError:
            pass

    def _send_proxy_auth_required(self, client: socket.socket) -> None:
        try:
            client.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Basic realm="grok-batch-meter"\r\n'
                b"Connection: close\r\nContent-Length: 0\r\n\r\n"
            )
        except OSError:
            pass

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        while True:
            readable, _, _ = select.select(sockets, [], [], 120)
            if not readable:
                return
            for source in readable:
                target = upstream if source is client else client
                data = source.recv(65536)
                if not data:
                    return
                target.sendall(data)
                if source is client:
                    self.state.update(bytes_up=len(data))
                else:
                    self.state.update(bytes_down=len(data))

    def handle_client(self, client: socket.socket) -> None:
        self.state.update(connections=1, active_connections=1)
        upstream = None
        tunnel_established = False
        try:
            client.settimeout(30)
            head, rest = _read_headers(client)
            if _header_value(head, b"Proxy-Authorization") != self.local_authorization:
                self._send_proxy_auth_required(client)
                return
            first_line = head.split(b"\r\n", 1)[0]
            method = first_line.split(b" ", 1)[0].upper()
            upstream = self._connect_upstream()
            upstream.settimeout(30)
            outbound = _rewrite_headers(head, self.authorization)
            if method != b"CONNECT":
                outbound += rest
            upstream.sendall(outbound)
            self.state.update(bytes_up=len(outbound))
            if method == b"CONNECT":
                response_head, response_rest = _read_headers(upstream)
                response = response_head + b"\r\n\r\n" + response_rest
                client.sendall(response)
                self.state.update(bytes_down=len(response))
                status_line = response_head.split(b"\r\n", 1)[0]
                if b" 200 " not in status_line:
                    return
                tunnel_established = True
                if rest:
                    upstream.sendall(rest)
                    self.state.update(bytes_up=len(rest))
            client.settimeout(None)
            upstream.settimeout(None)
            self._relay(client, upstream)
        except (OSError, ValueError, ConnectionError, ssl.SSLError):
            if not tunnel_established:
                self._send_error(client)
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            self.state.update(active_connections=-1)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _MeterManager:
    def __init__(self, state: _TrafficState):
        self.state = state
        self.lock = threading.Lock()
        self.meters: dict[str, _ProxyMeter] = {}
        self.unmetered: set[str] = set()

    def wrap(self, upstream_url: str) -> str:
        parsed = urlparse(str(upstream_url or "").strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            key = hashlib.sha256(str(upstream_url or "").encode()).hexdigest()
            with self.lock:
                if key not in self.unmetered:
                    self.unmetered.add(key)
                    self.state.update(unmetered_proxies=1)
            return upstream_url
        with self.lock:
            key = hashlib.sha256(str(upstream_url).encode()).hexdigest()
            meter = self.meters.get(key)
            if meter is None:
                meter = _ProxyMeter(upstream_url, self.state)
                self.meters[key] = meter
            return meter.local_url

    def close(self) -> None:
        with self.lock:
            meters = list(self.meters.values())
            self.meters.clear()
        for meter in meters:
            meter.close()
        self.state.close()


_RUNTIME_LOCK = threading.Lock()
_RUNTIME_KEY: tuple[str, str] | None = None
_RUNTIME_MANAGER: _MeterManager | None = None


def _runtime_manager() -> _MeterManager | None:
    global _RUNTIME_KEY, _RUNTIME_MANAGER
    path_text = str(os.environ.get(TRAFFIC_FILE_ENV, "") or "").strip()
    batch_id = str(os.environ.get(BATCH_ID_ENV, "") or "").strip()
    if not path_text or not batch_id:
        return None
    path = Path(path_text).resolve()
    key = (str(path), batch_id)
    with _RUNTIME_LOCK:
        if _RUNTIME_MANAGER is None or _RUNTIME_KEY != key:
            if _RUNTIME_MANAGER is not None:
                _RUNTIME_MANAGER.close()
            ensure_private_dir(path.parent)
            _RUNTIME_MANAGER = _MeterManager(_TrafficState(path, batch_id))
            _RUNTIME_KEY = key
        return _RUNTIME_MANAGER


def meter_proxy_url(upstream_url: str) -> str:
    manager = _runtime_manager()
    if manager is None or not str(upstream_url or "").strip():
        return upstream_url
    try:
        return manager.wrap(str(upstream_url).strip())
    except (OSError, ValueError):
        return upstream_url


def mark_successful_account(count: int = 1) -> None:
    manager = _runtime_manager()
    if manager is None:
        return
    manager.state.update(successful_accounts=max(0, int(count)))
    manager.state.flush()


def close_runtime(
    *,
    path: str | os.PathLike[str] | None = None,
    batch_id: str | None = None,
) -> None:
    global _RUNTIME_KEY, _RUNTIME_MANAGER
    with _RUNTIME_LOCK:
        if _RUNTIME_KEY is not None and path is not None:
            expected = (str(Path(path).resolve()), str(batch_id or ""))
            if _RUNTIME_KEY != expected:
                return
        manager = _RUNTIME_MANAGER
        _RUNTIME_MANAGER = None
        _RUNTIME_KEY = None
    if manager is not None:
        manager.close()


atexit.register(close_runtime)
