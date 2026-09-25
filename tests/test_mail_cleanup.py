# -*- coding: utf-8 -*-
"""webui/mail_cleanup_ops：服务端邮件清理（批量端点 + 逐封兜底）。"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import mail_cleanup_ops

CREDS = {
    "api_base": "https://mail.example",
    "admin_auth": "test-admin-pw-123",
    "custom_auth": "",
}
NOW = 1700000000.0  # 固定时钟，保留 1 小时 → cutoff≈2023-11-14 21:13（UTC）


class FakeResponse:
    def __init__(self, status_code, *, body="", data=None, reason=""):
        self.status_code = status_code
        self.text = body
        self._data = data
        self.reason = reason or "test response"

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code} for test request")


def _count_get(counts, pages):
    """count 拉取走 counts 队列；分页扫描走 pages 队列。"""

    def fake_get(url, params=None, headers=None, timeout=None):
        assert (headers or {}).get("x-admin-auth") == "test-admin-pw-123"
        if int((params or {}).get("limit") or 0) == 1:
            return FakeResponse(200, data={"results": [{"id": 0}], "count": counts.pop(0)})
        if not pages:
            return FakeResponse(200, data={"results": [], "count": 0})
        return FakeResponse(200, data=pages.pop(0))

    return fake_get


def _reset_state():
    with mail_cleanup_ops._STATE_LOCK:
        mail_cleanup_ops._STATE.update(
            {
                "running": False,
                "started_at": None,
                "last_result": None,
                "last_error": None,
            }
        )


def test_resolve_creds_requires_base_and_key():
    try:
        mail_cleanup_ops.resolve_creds({})
        raise AssertionError("缺配置时应抛 MailCleanupError")
    except mail_cleanup_ops.MailCleanupError:
        pass
    creds = mail_cleanup_ops.resolve_creds(
        {
            "cloudflare_api_base": " https://mail.example/ ",
            "cloudflare_api_key": " test-admin-pw-123 ",
            "cloudflare_custom_auth": "custom-x",
        }
    )
    assert creds == {
        "api_base": "https://mail.example",
        "admin_auth": "test-admin-pw-123",
        "custom_auth": "custom-x",
    }


def test_server_batch_cleanup_reports_deleted_diff():
    posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append((url, json))
        return FakeResponse(200, data={"success": True})

    # before=50 → 批量后剩余 0（收敛）→ unknow 清理 → 最终 count=1
    result = mail_cleanup_ops.run_mail_cleanup(
        24,
        clean_unknow=True,
        creds=CREDS,
        http_get=_count_get([50, 0, 1], []),
        http_post=fake_post,
        now=NOW,
    )
    assert result["ok"] is True
    assert result["mode"] == "server_batch"
    assert result["deleted"] == 49
    assert posts == [
        (
            "https://mail.example/admin/cleanup",
            {"cleanType": "mails", "cleanDays": 1},
        ),
        (
            "https://mail.example/admin/cleanup",
            {"cleanType": "mails_unknow", "cleanDays": 1},
        ),
    ]


def test_server_batch_without_unknow_sends_single_type():
    posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append(json)
        return FakeResponse(200, data={"success": True})

    result = mail_cleanup_ops.run_mail_cleanup(
        48,
        clean_unknow=False,
        creds=CREDS,
        http_get=_count_get([9, 0, 9], []),
        http_post=fake_post,
        now=NOW,
    )
    assert result["mode"] == "server_batch"
    assert posts == [{"cleanType": "mails", "cleanDays": 2}]


def test_batch_capped_deployment_repeats_until_no_progress():
    """部分部署单批删除量受 CLEANUP_BATCH_SIZE 限制：有进展就继续调用。"""
    posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append(json)
        return FakeResponse(200, data={"success": True})

    # before=7000 → 第一批后 4000（有进展）→ 第二批后 0（收敛）→ after=0
    result = mail_cleanup_ops.run_mail_cleanup(
        24,
        clean_unknow=False,
        creds=CREDS,
        http_get=_count_get([7000, 4000, 0, 0], []),
        http_post=fake_post,
        now=NOW,
    )
    assert result["mode"] == "server_batch"
    assert posts == [
        {"cleanType": "mails", "cleanDays": 1},
        {"cleanType": "mails", "cleanDays": 1},
    ]
    assert result["deleted"] == 7000


def test_sub_day_retention_uses_local_paging_without_batch_post():
    """不足 24 小时的保留期不走批量端点（部署对小数天行为不可保证）。"""
    posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append((url, json))
        return FakeResponse(200, data={"success": True})

    pages = [
        {
            "results": [
                {"id": 1, "created_at": "2023-11-14 20:00:00"},
                {"id": 2, "created_at": "2023-11-14 21:00:00"},
                {"id": 3, "created_at": "2023-11-14 22:00:00"},
                {"id": 4},
                {"id": "5", "created_at": "not-a-date 99:99:99"},
            ],
            "count": 5,
        },
        {"results": [], "count": 5},
    ]
    deletes = []

    def fake_delete(url, headers=None, timeout=10):
        deletes.append(url)
        return FakeResponse(200, data={})

    result = mail_cleanup_ops.run_mail_cleanup(
        1,
        clean_unknow=True,
        creds=CREDS,
        http_get=_count_get([5, 3], pages),
        http_post=fake_post,
        http_delete=fake_delete,
        now=NOW,
    )
    # NOW cutoff ≈ 2023-11-14 21:13 → 仅 id 1、2 过期
    assert posts == []
    assert result["mode"] == "local_paging"
    assert result["ok"] is True
    assert result["deleted_by_api"] == 2
    assert result["deleted"] == 2
    assert deletes == [
        "https://mail.example/admin/mails/1",
        "https://mail.example/admin/mails/2",
    ]


def test_batch_endpoint_error_falls_back_to_paging():
    posts = []
    pages = [{"results": [{"id": 7, "created_at": "2023-01-01 00:00:00"}]}, {"results": [], "count": 0}]
    deletes = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append(url)
        return FakeResponse(500, body="d1 error")

    def fake_delete(url, headers=None, timeout=10):
        deletes.append(url)
        return FakeResponse(200, data={})

    result = mail_cleanup_ops.run_mail_cleanup(
        24,
        clean_unknow=True,
        creds=CREDS,
        http_get=_count_get([2, 1], pages),
        http_post=fake_post,
        http_delete=fake_delete,
        now=NOW,
    )
    assert result["mode"] == "local_paging"
    assert posts and result.get("server_batch_errors")
    assert deletes == ["https://mail.example/admin/mails/7"]


def test_fallback_single_delete_failure_does_not_abort():
    pages = [
        {
            "results": [
                {"id": 1, "created_at": "2023-01-01 00:00:00"},
                {"id": 2, "created_at": "2023-01-02 00:00:00"},
                {"id": 3, "created_at": "2023-01-03 00:00:00"},
            ]
        },
        {"results": [], "count": 0},
    ]
    deletes = []

    def fake_post(url, json=None, headers=None, timeout=None):
        return FakeResponse(404, body="not found")

    def fake_delete(url, headers=None, timeout=10):
        deletes.append(url)
        if "mails/2" in url:
            raise RuntimeError("boom")
        return FakeResponse(200, data={})

    result = mail_cleanup_ops.run_mail_cleanup(
        1,
        creds=CREDS,
        http_get=_count_get([3, 1], pages),
        http_post=fake_post,
        http_delete=fake_delete,
        now=NOW,
    )
    assert result["ok"] is True
    assert result["deleted_by_api"] == 2
    assert result["failed"] == 1
    assert len(deletes) == 3


def test_fallback_list_failure_stops_without_deleting():
    deletes = []

    def fake_get(url, params=None, headers=None, timeout=None):
        if int((params or {}).get("limit") or 0) == 1:
            return FakeResponse(200, data={"count": 7})
        return FakeResponse(500, body="d1 error")

    def fake_post(url, json=None, headers=None, timeout=None):
        return FakeResponse(404, body="not found")

    def fake_delete(url, headers=None, timeout=10):
        deletes.append(url)
        return FakeResponse(200, data={})

    result = mail_cleanup_ops.run_mail_cleanup(
        1,
        creds=CREDS,
        http_get=fake_get,
        http_post=fake_post,
        http_delete=fake_delete,
        now=NOW,
    )
    assert result["ok"] is False
    assert result["fatal"]
    assert deletes == []
    assert result["deleted_by_api"] == 0


def test_keep_hours_bounds_rejected():
    for bad in (0, -1, 721, "abc", None):
        try:
            mail_cleanup_ops.run_mail_cleanup(bad, creds=CREDS)
            raise AssertionError(f"keep_hours={bad!r} 应被拒绝")
        except mail_cleanup_ops.MailCleanupError:
            pass


def test_normalize_settings_roundtrip_and_bounds():
    out = mail_cleanup_ops.normalize_settings(
        {
            "mail_cleanup_keep_hours": "5",
            "mail_cleanup_interval_hours": 12,
            "mail_cleanup_enabled": True,
            "mail_cleanup_clean_unknow": False,
        }
    )
    assert out == {
        "mail_cleanup_keep_hours": 5,
        "mail_cleanup_interval_hours": 12,
        "mail_cleanup_enabled": True,
        "mail_cleanup_clean_unknow": False,
    }
    partial = mail_cleanup_ops.normalize_settings({"mail_cleanup_enabled": False})
    assert partial == {"mail_cleanup_enabled": False}
    for bad in (
        {"mail_cleanup_keep_hours": 0},
        {"mail_cleanup_keep_hours": 721},
        {"mail_cleanup_interval_hours": 0},
        {"mail_cleanup_interval_hours": 169},
        {"mail_cleanup_keep_hours": "soon"},
    ):
        try:
            mail_cleanup_ops.normalize_settings(bad)
            raise AssertionError(f"{bad} 应被拒绝")
        except ValueError:
            pass
    try:
        mail_cleanup_ops.normalize_settings({})
        raise AssertionError("空设置应被拒绝")
    except ValueError:
        pass


def test_start_cleanup_rejects_invalid_hours_and_double_run():
    _reset_state()
    try:
        outcome = mail_cleanup_ops.start_cleanup(0)
        assert outcome["started"] is False
        assert "保留时间" in outcome["error"]
        with mail_cleanup_ops._STATE_LOCK:
            mail_cleanup_ops._STATE["running"] = True
        outcome = mail_cleanup_ops.start_cleanup(1)
        assert outcome["started"] is False
        assert "已有清理任务在运行" in outcome["error"]
    finally:
        _reset_state()


def test_start_cleanup_records_result_in_background():
    _reset_state()
    captured = {}

    def fake_run(hours, *, clean_unknow, creds):
        captured["hours"] = hours
        captured["clean_unknow"] = clean_unknow
        return {
            "ok": True,
            "mode": "local_paging",
            "before": 10,
            "after": 2,
            "deleted": 8,
            "finished_at": "t",
        }

    original = mail_cleanup_ops.run_mail_cleanup
    mail_cleanup_ops.run_mail_cleanup = fake_run
    try:
        outcome = mail_cleanup_ops.start_cleanup(3, clean_unknow=False, creds=CREDS)
        assert outcome["started"] is True
        for _ in range(200):
            if not mail_cleanup_ops.cleanup_status()["running"]:
                break
            time.sleep(0.01)
        status = mail_cleanup_ops.cleanup_status()
        assert status["running"] is False
        assert status["last_result"]["deleted"] == 8
        assert captured == {"hours": 3, "clean_unknow": False}
    finally:
        mail_cleanup_ops.run_mail_cleanup = original
        _reset_state()


if __name__ == "__main__":
    test_resolve_creds_requires_base_and_key()
    test_server_batch_cleanup_reports_deleted_diff()
    test_server_batch_without_unknow_sends_single_type()
    test_batch_capped_deployment_repeats_until_no_progress()
    test_sub_day_retention_uses_local_paging_without_batch_post()
    test_batch_endpoint_error_falls_back_to_paging()
    test_fallback_single_delete_failure_does_not_abort()
    test_fallback_list_failure_stops_without_deleting()
    test_keep_hours_bounds_rejected()
    test_normalize_settings_roundtrip_and_bounds()
    test_start_cleanup_rejects_invalid_hours_and_double_run()
    test_start_cleanup_records_result_in_background()
    print("test_mail_cleanup: all tests passed")
