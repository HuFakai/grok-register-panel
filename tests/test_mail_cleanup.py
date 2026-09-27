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
    with mail_cleanup_ops._COUNT_LOCK:
        mail_cleanup_ops._LAST_COUNT.update({"value": None, "error": None})


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


def test_batch_uses_floor_days_for_over_day_retention():
    """≥24h 的保留期：批量 cleanDays 取整天数（floor），36h → 1 天。"""
    posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append(json)
        return FakeResponse(200, data={"success": True})

    result = mail_cleanup_ops.run_mail_cleanup(
        36,
        clean_unknow=False,
        creds=CREDS,
        http_get=_count_get([9, 0, 9], []),
        http_post=fake_post,
        now=NOW,
    )
    assert result["mode"] == "server_batch"
    assert posts == [{"cleanType": "mails", "cleanDays": 1}]


def test_sub_day_combo_batch_first_then_sweep_residual():
    """保留 <24h：先批量删 1 天前的大头，再逐封删 [保留期, 24h) 窗口剩余。"""
    posts = []
    deletes = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append(json)
        return FakeResponse(200, data={"success": True})

    def fake_delete(url, headers=None, timeout=10):
        deletes.append(url)
        return FakeResponse(200, data={})

    # NOW=2023-11-14 22:13:20 UTC；H=1 → cutoff 21:13。
    # 批量（cleanDays=1）后服务端剩 8 封：6 封在 [1h,24h) 窗口内（待逐封删）、
    # 2 封是 1 小时内的新邮件（保留）。
    window_mail = {"id": 1, "created_at": "2023-11-14 10:00:00"}
    pages = [
        {
            "results": [dict(window_mail, id=i) for i in range(1, 7)]
            + [
                {"id": 7, "created_at": "2023-11-14 22:00:00"},
                {"id": 8, "created_at": "2023-11-14 22:05:00"},
            ],
            "count": 8,
        },
        {"results": [], "count": 8},
    ]
    result = mail_cleanup_ops.run_mail_cleanup(
        1,
        clean_unknow=True,
        creds=CREDS,
        http_get=_count_get([10, 8, 8, 2], pages),
        http_post=fake_post,
        http_delete=fake_delete,
        now=NOW,
    )
    assert result["mode"] == "server_batch"
    assert result["ok"] is True
    # 批量先删 1 天前的（count 10→8）；收敛循环停在无进展；再清 unknow
    assert posts == [
        {"cleanType": "mails", "cleanDays": 1},
        {"cleanType": "mails", "cleanDays": 1},
        {"cleanType": "mails_unknow", "cleanDays": 1},
    ]
    # 扫尾只删窗口内的 6 封，1 小时内的新邮件保留
    assert result["deleted_by_api"] == 6
    assert result["deleted"] == 8
    assert sorted(deletes) == sorted(
        f"https://mail.example/admin/mails/{i}" for i in range(1, 7)
    )


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

    def fake_run(hours, *, clean_unknow, creds, progress_cb=None):
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



def test_last_known_count_snapshot_and_run_update():
    """邮件数缓存只在清理执行时写入：初始为空，跑完取 after，after 失败取 before。"""
    _reset_state()
    assert mail_cleanup_ops.last_known_count() == (None, None)

    def fake_post(url, json=None, headers=None, timeout=None):
        return FakeResponse(200, data={"success": True})

    mail_cleanup_ops.run_mail_cleanup(
        24,
        clean_unknow=False,
        creds=CREDS,
        http_get=_count_get([50, 0, 3], []),
        http_post=fake_post,
        now=NOW,
    )
    assert mail_cleanup_ops.last_known_count() == (3, None)
    _reset_state()

    # 清理后计数拉取失败：缓存回退为清理前读数并带错误说明。
    # 批量端点 404（不消耗 count 队列）→ 整体退回逐封删。
    pages = [{"results": [{"id": 9, "created_at": "2023-01-01 00:00:00"}]}, {"results": [], "count": 0}]

    def unsupported_post(url, json=None, headers=None, timeout=None):
        return FakeResponse(404, body="not found")

    def flaky_get(url, params=None, headers=None, timeout=None):
        if int((params or {}).get("limit") or 0) == 1:
            count = counts.pop(0)
            if count is None:
                return FakeResponse(500, body="d1 error")
            return FakeResponse(200, data={"results": [{"id": 0}], "count": count})
        return FakeResponse(200, data=pages.pop(0))

    counts = [2, None]
    mail_cleanup_ops.run_mail_cleanup(
        1,
        creds=CREDS,
        http_get=flaky_get,
        http_post=unsupported_post,
        http_delete=lambda url, headers=None, timeout=10: FakeResponse(200, data={}),
        now=NOW,
    )
    value, error = mail_cleanup_ops.last_known_count()
    assert value == 2
    assert "HTTP 500" in (error or "")
    _reset_state()


def test_progress_callback_reports_scan_and_delete():
    """逐封删路径要跑几分钟，进度必须实时上报（scan 分页 / delete 删除）。"""
    _reset_state()
    pages = [
        {
            "results": [
                {"id": i, "created_at": "2023-01-01 00:00:00"} for i in range(1, 51)
            ]
        },
        {"results": [], "count": 0},
    ]
    events = []

    def fake_post(url, json=None, headers=None, timeout=None):
        return FakeResponse(404, body="not found")

    def fake_delete(url, headers=None, timeout=10):
        return FakeResponse(200, data={})

    result = mail_cleanup_ops.run_mail_cleanup(
        1,
        creds=CREDS,
        http_get=_count_get([50, 0], pages),
        http_post=fake_post,
        http_delete=fake_delete,
        now=NOW,
        progress_cb=lambda fields: events.append(dict(fields)),
    )
    assert result["deleted_by_api"] == 50
    scan_events = [e for e in events if e.get("phase") == "scan"]
    delete_events = [e for e in events if e.get("phase") == "delete"]
    assert scan_events and scan_events[-1]["scanned"] == 50
    assert scan_events[-1]["stale"] == 50
    assert delete_events and delete_events[-1]["done"] == 50
    assert delete_events[-1]["total"] == 50
    assert delete_events[-1]["deleted"] == 50
    assert delete_events[-1]["failed"] == 0
    # 进度上报间隔不超过 REPORT_STEP，长时间任务不会长时间静默
    assert max(
        delete_events[i + 1]["done"] - delete_events[i]["done"]
        for i in range(len(delete_events) - 1)
    ) <= mail_cleanup_ops.PROGRESS_REPORT_STEP
    _reset_state()


if __name__ == "__main__":
    test_resolve_creds_requires_base_and_key()
    test_server_batch_cleanup_reports_deleted_diff()
    test_server_batch_without_unknow_sends_single_type()
    test_batch_capped_deployment_repeats_until_no_progress()
    test_batch_uses_floor_days_for_over_day_retention()
    test_sub_day_combo_batch_first_then_sweep_residual()
    test_batch_endpoint_error_falls_back_to_paging()
    test_fallback_single_delete_failure_does_not_abort()
    test_fallback_list_failure_stops_without_deleting()
    test_keep_hours_bounds_rejected()
    test_normalize_settings_roundtrip_and_bounds()
    test_start_cleanup_rejects_invalid_hours_and_double_run()
    test_start_cleanup_records_result_in_background()
    test_last_known_count_snapshot_and_run_update()
    test_progress_callback_reports_scan_and_delete()
    print("test_mail_cleanup: all tests passed")
