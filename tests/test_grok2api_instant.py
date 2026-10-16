# -*- coding: utf-8 -*-
"""Unit tests for grok2api instant upload (webui/grok2api_instant.py).

覆盖：入队开关/配置检查、单号一传完整调用链（导入→查id→转Build→转Console）、
单账号失败不抛异常且继续处理、并发入队只起一个 worker、日志脱敏。
"""
from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import grok2api_instant as instant


class FakeClient:
    def __init__(self):
        self.calls = []
        self._id = "42"

    def login(self):
        self.calls.append("login")

    def import_web_accounts(self, jsonl_content, filename="web_accounts.jsonl"):
        self.calls.append(("import", jsonl_content, filename))
        return {"created": 1, "updated": 0, "skipped": 0}

    def find_web_account_id(self, email, *, retries=3, delay=1.0):
        self.calls.append(("find", email))
        return self._id

    def convert_accounts_by_ids(self, ids):
        self.calls.append(("convert", list(ids)))
        return {"created": 1, "linked": 1}

    def sync_accounts_by_ids(self, ids):
        self.calls.append(("sync", list(ids)))
        return {"synced": 1}


def _fake_module_client(tmp_path, monkeypatch, client, config_overrides=None):
    """把 upload_one 里依赖的模块替换为假实现。

    - grok2api_api.Grok2apiClient → 返回 FakeClient
    - grok2api_upload.load_config/configured → 读临时 config.json
    - grok2api_instant.CONFIG_FILE → 临时路径
    """
    import types

    config = {
        "grok2api_instant_upload": True,
        "grok2api_admin_url": "http://127.0.0.1:8080",
        "grok2api_admin_user": "admin",
        "grok2api_admin_password": "test-admin-pw-123",
    }
    if config_overrides:
        config.update(config_overrides)
    config_file = tmp_path / "config.json"
    config_file.write_text(
        __import__("json").dumps(config, ensure_ascii=False),
        encoding="utf-8",
    )
    monkeypatch.setattr(instant, "CONFIG_FILE", config_file)
    monkeypatch.setattr(instant, "INSTANT_LOG", tmp_path / "grok2api_instant.log")

    fake_api = types.ModuleType("grok2api_api")
    fake_api.Grok2apiClient = lambda *a, **kw: client
    fake_upload = types.ModuleType("grok2api_upload")
    fake_upload.configured = lambda cfg: bool(
        cfg.get("grok2api_admin_url") and cfg.get("grok2api_admin_user")
        and cfg.get("grok2api_admin_password")
    )
    fake_upload.load_config = lambda path: config
    monkeypatch.setitem(sys.modules, "webui.grok2api_api", fake_api)
    monkeypatch.setitem(sys.modules, "webui.grok2api_upload", fake_upload)


def test_account_jsonl_fields():
    line = instant._account_jsonl("user@example.com", "ssotoken-abc")
    record = __import__("json").loads(line)
    assert record == {
        "provider": "grok_web",
        "name": "user@example.com",
        "email": "user@example.com",
        "sso_token": "ssotoken-abc",
        "tier": "auto",
    }


def test_enqueue_requires_switch_and_config(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text(
        __import__("json").dumps(
            {
                "grok2api_instant_upload": False,
                "grok2api_admin_url": "http://127.0.0.1:8080",
                "grok2api_admin_user": "admin",
                "grok2api_admin_password": "test-admin-pw-123",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(instant, "CONFIG_FILE", config_file)
    # 开关关闭 → 不入队
    assert instant.enqueue_instant_upload("a@example.com", "ssotoken-a", "pw") is False
    assert instant._UPLOADER._queue.qsize() == 0

    # 开关打开但未配置 → 不入队
    config_file.write_text(
        __import__("json").dumps({"grok2api_instant_upload": True}),
        encoding="utf-8",
    )
    assert instant.enqueue_instant_upload("a@example.com", "ssotoken-a", "pw") is False
    assert instant._UPLOADER._queue.qsize() == 0

    # 参数非法（空 sso）→ 不入队
    config_file.write_text(
        __import__("json").dumps(
            {
                "grok2api_instant_upload": True,
                "grok2api_admin_url": "http://127.0.0.1:8080",
                "grok2api_admin_user": "admin",
                "grok2api_admin_password": "test-admin-pw-123",
            }
        ),
        encoding="utf-8",
    )
    assert instant.enqueue_instant_upload("a@example.com", "", "pw") is False


def test_upload_one_full_chain(tmp_path, monkeypatch):
    client = FakeClient()
    _fake_module_client(tmp_path, monkeypatch, client)
    item = {
        "email": "user@example.com",
        "sso": "ssotoken-abc",
        "password": "pw",
        "task_subdir": "T1",
    }
    instant._UPLOADER._upload_one(item)
    assert client.calls[0] == "login"
    assert client.calls[1][0] == "import"
    assert client.calls[2][0] == "find"
    assert client.calls[2][1] == "user@example.com"
    assert client.calls[3] == ("convert", ["42"])
    assert client.calls[4] == ("sync", ["42"])
    # 成功计数
    assert instant._UPLOADER._stats["succeeded"] >= 1


def test_upload_one_failure_does_not_raise(tmp_path, monkeypatch):
    class ExplodingClient(FakeClient):
        def import_web_accounts(self, jsonl_content, filename="web_accounts.jsonl"):
            self.calls.append(("import", jsonl_content))
            raise RuntimeError("grok2api 导入失败 HTTP 500: boom")

    client = ExplodingClient()
    _fake_module_client(tmp_path, monkeypatch, client)
    item = {"email": "fail@example.com", "sso": "ssotoken-fail", "password": "pw"}
    # 必须不抛异常
    instant._UPLOADER._upload_one(item)
    assert instant._UPLOADER._stats["failed"] >= 1


def test_upload_one_skips_when_id_missing(tmp_path, monkeypatch):
    client = FakeClient()
    client._id = ""
    _fake_module_client(tmp_path, monkeypatch, client)
    instant._UPLOADER._upload_one(
        {"email": "noid@example.com", "sso": "ssotoken-noid", "password": "pw"}
    )
    # 查不到 id → 只到 find，不再 convert/sync
    kinds = [c[0] if isinstance(c, tuple) else c for c in client.calls]
    assert "convert" not in kinds
    assert "sync" not in kinds


def test_log_does_not_contain_password_or_sso(tmp_path, monkeypatch):
    client = FakeClient()
    _fake_module_client(tmp_path, monkeypatch, client)
    instant._UPLOADER._upload_one(
        {"email": "secret@example.com", "sso": "ssotoken-very-secret", "password": "test-admin-pw-123"}
    )
    log_text = (tmp_path / "grok2api_instant.log").read_text(encoding="utf-8")
    assert "test-admin-pw-123" not in log_text
    assert "ssotoken-very-secret" not in log_text
    assert "secret@example.com" in log_text


def test_enqueue_starts_single_worker(tmp_path, monkeypatch):
    import types

    config = {
        "grok2api_instant_upload": True,
        "grok2api_admin_url": "http://127.0.0.1:8080",
        "grok2api_admin_user": "admin",
        "grok2api_admin_password": "test-admin-pw-123",
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(__import__("json").dumps(config), encoding="utf-8")
    monkeypatch.setattr(instant, "CONFIG_FILE", config_file)
    monkeypatch.setattr(instant, "INSTANT_LOG", tmp_path / "grok2api_instant.log")
    fake_upload = types.ModuleType("grok2api_upload")
    fake_upload.configured = lambda cfg: True
    fake_upload.load_config = lambda path: config
    monkeypatch.setitem(sys.modules, "webui.grok2api_upload", fake_upload)
    # 让 worker 消费时不做真实网络调用
    fake_api = types.ModuleType("grok2api_api")
    fake_api.Grok2apiClient = lambda *a, **kw: FakeClient()
    monkeypatch.setitem(sys.modules, "webui.grok2api_api", fake_api)

    # 重置单例队列/线程/统计（避免污染其他测试）
    old_queue = instant._UPLOADER._queue
    instant._UPLOADER._queue = queue.Queue()
    instant._UPLOADER._thread = None
    instant._UPLOADER._stats = {"processed": 0, "succeeded": 0, "failed": 0}
    try:
        for _ in range(5):
            assert instant.enqueue_instant_upload("w@example.com", "ssotoken-w", "pw")
        thread = instant._UPLOADER._thread
        assert thread is not None
        assert thread.is_alive()
        # 并发入队只起一个 worker 线程（串行消费，不重复启动）
        workers = [t for t in threading.enumerate() if t.name == "grok2api-instant-uploader"]
        assert len(workers) == 1
        # 入队 5 个都被串行处理完成
        instant._UPLOADER._queue.join()
        assert instant._UPLOADER._stats["processed"] == 5
    finally:
        instant._UPLOADER._queue = old_queue


if __name__ == "__main__":
    import tempfile

    class _Monkey:
        def setattr(self, obj, name, value):
            setattr(obj, name, value)

        def setitem(self, mapping, key, value):
            mapping[key] = value

    import os

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        monkey = _Monkey()
        test_account_jsonl_fields()
        test_enqueue_requires_switch_and_config(tmp, monkey)
        test_upload_one_full_chain(tmp, monkey)
        test_upload_one_failure_does_not_raise(tmp, monkey)
        test_upload_one_skips_when_id_missing(tmp, monkey)
        test_log_does_not_contain_password_or_sso(tmp, monkey)
        test_enqueue_starts_single_worker(tmp, monkey)
    print("OK grok2api instant")
