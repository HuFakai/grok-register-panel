# -*- coding: utf-8 -*-
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connectivity
from email_providers import inbucket


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self.payload


def test_normalize_base():
    assert inbucket.normalize_base("") == ""
    assert inbucket.normalize_base("127.0.0.1:9000/") == "http://127.0.0.1:9000"
    assert (
        inbucket.normalize_base("https://inbucket.example.com")
        == "https://inbucket.example.com"
    )
    # INBUCKET_WEB_BASEPATH 前缀必须保留，不能像 MoeMail 一样剥掉路径
    assert (
        inbucket.normalize_base("https://host.example/inbucket/")
        == "https://host.example/inbucket"
    )


def test_create_address_requires_domain():
    try:
        inbucket.create_address("")
    except Exception as exc:
        assert "inbucket_domain" in str(exc)
    else:
        raise AssertionError("expected domain error")

    address, mailbox = inbucket.create_address("Mail.Example.com", username="James.Smith9x")
    assert address == "james.smith9x@mail.example.com"
    assert mailbox == address


def test_parse_domains_and_levels():
    assert inbucket.parse_domains("mail.example.com, box.example.net") == [
        "mail.example.com",
        "box.example.net",
    ]
    assert inbucket.parse_domains("@Mail.Example.com，box.example.net extra.example") == [
        "mail.example.com",
        "box.example.net",
        "extra.example",
    ]
    assert inbucket.parse_domains("") == []

    assert inbucket.parse_levels("0") == (0, 0)
    assert inbucket.parse_levels("2") == (2, 2)
    assert inbucket.parse_levels("1-3") == (1, 3)
    assert inbucket.parse_levels("3-1") == (1, 3)
    assert inbucket.parse_levels("") == (0, 0)
    assert inbucket.parse_levels("not-a-number") == (0, 0)
    assert inbucket.parse_levels(99) == (4, 4)


def test_random_email_domain_rotation_and_levels():
    inbucket.reset_runtime_state()
    roots = "one.example, two.example"

    # 级数 0：根域名轮询均摊
    assert inbucket.random_email_domain(roots, "0") == "one.example"
    assert inbucket.random_email_domain(roots, "0") == "two.example"
    assert inbucket.random_email_domain(roots, "0") == "one.example"

    # 固定级数：根域名之上恰好多 N 级标签
    domain = inbucket.random_email_domain("one.example", "2")
    labels = domain.split(".")
    assert domain.endswith(".one.example")
    assert len(labels) == 2 + 2
    assert all(label for label in labels[:2])

    # 区间级数：每次都在 [low, high] 内
    for _ in range(30):
        domain = inbucket.random_email_domain("one.example", "1-3")
        extra = len(domain.split(".")) - 2
        assert 1 <= extra <= 3

    # 根域名带子域前缀（如 a.b.example）时级数叠加在其上
    domain = inbucket.random_email_domain("sub.one.example", "1")
    assert domain.endswith(".sub.one.example")


def test_create_address_uses_random_levels():
    inbucket.reset_runtime_state()
    random.seed(1234)
    try:
        address, mailbox = inbucket.create_address(
            "one.example, two.example", username="tester", random_levels="2"
        )
    finally:
        random.seed()
    local, _, domain = address.partition("@")
    assert local == "tester"
    assert domain.endswith(".one.example") or domain.endswith(".two.example")
    assert len(domain.split(".")) == 4
    assert mailbox == address


def test_wait_for_code_detail_body_and_cleanup():
    urls = []
    deleted = []

    def http_get(url, **kwargs):
        urls.append((url, kwargs))
        assert kwargs["headers"]["Accept"] == "application/json"
        assert kwargs["proxies"] == {}
        if url.endswith("/api/v1/mailbox/james.smith9x%40mail.example.com"):
            return FakeResponse([{"id": "0001", "subject": "xAI verification", "seen": False}])
        if url.endswith("/api/v1/mailbox/james.smith9x%40mail.example.com/0001"):
            return FakeResponse(
                {"subject": "xAI verification", "body": {"text": "", "html": "Use <b>QO7-TUD</b> to continue."}}
            )
        raise AssertionError(url)

    def http_delete(url, **kwargs):
        assert kwargs["proxies"] == {}
        deleted.append(url)
        return FakeResponse([])

    code = inbucket.wait_for_code(
        http_get,
        "https://inbucket.example.com/",
        "James.Smith9x@Mail.Example.com",
        http_delete=http_delete,
        raise_if_cancelled=lambda callback: None,
        sleep_with_cancel=lambda seconds, callback: None,
    )

    assert code == "QO7-TUD"
    assert urls[0][0] == "https://inbucket.example.com/api/v1/mailbox/james.smith9x%40mail.example.com"
    assert deleted == [
        "https://inbucket.example.com/api/v1/mailbox/james.smith9x%40mail.example.com"
    ]


def test_wait_for_code_subject_short_circuit():
    calls = []

    def http_get(url, **kwargs):
        calls.append(url)
        return FakeResponse(
            [{"id": "0002", "subject": "QO7-TUD is your xAI confirmation code"}]
        )

    def http_delete(url, **kwargs):
        raise AssertionError("cleanup should be best-effort and called last")

    code = inbucket.wait_for_code(
        http_get,
        "http://127.0.0.1:9000",
        "user@mail.example.com",
        http_delete=http_delete,
        cleanup=False,
        raise_if_cancelled=lambda callback: None,
        sleep_with_cancel=lambda seconds, callback: None,
    )

    assert code == "QO7-TUD"
    assert len(calls) == 1


def test_wait_for_code_timeout_purges():
    deleted = []

    code_error = None
    try:
        inbucket.wait_for_code(
            lambda url, **kwargs: FakeResponse([]),
            "http://127.0.0.1:9000",
            "user@mail.example.com",
            timeout=0,
            http_delete=lambda url, **kwargs: deleted.append(url) or FakeResponse([]),
            raise_if_cancelled=lambda callback: None,
            sleep_with_cancel=lambda seconds, callback: None,
        )
    except Exception as exc:
        code_error = exc
    assert code_error is not None and "未收到验证码" in str(code_error)
    assert deleted == [
        "http://127.0.0.1:9000/api/v1/mailbox/user%40mail.example.com"
    ]


def test_wait_for_code_requires_base():
    try:
        inbucket.wait_for_code(
            lambda url, **kwargs: FakeResponse([]),
            "",
            "user@mail.example.com",
            raise_if_cancelled=lambda callback: None,
            sleep_with_cancel=lambda seconds, callback: None,
        )
    except Exception as exc:
        assert "inbucket_api_base" in str(exc)
    else:
        raise AssertionError("expected base error")


def test_list_messages_raises_on_http_error():
    def http_get(url, **kwargs):
        return FakeResponse({"error": "nope"}, status_code=500)

    try:
        inbucket.list_messages(http_get, "http://127.0.0.1:9000", "user@mail.example.com")
    except Exception as exc:
        assert "HTTP 500" in str(exc)
    else:
        raise AssertionError("expected http error")


def test_connectivity_probe():
    seen = []

    def http_get(url, **kwargs):
        seen.append((url, kwargs))
        return FakeResponse([])

    result = connectivity.check_email_api(
        "inbucket",
        {"inbucket_api_base": "http://127.0.0.1:9000/", "inbucket_domain": "mail.example.com"},
        http_get,
        lambda *args, **kwargs: None,
    )
    assert result[1] is True
    assert "mail.example.com" in result[2]
    assert seen[0][0] == "http://127.0.0.1:9000/api/v1/mailbox/probe"
    assert seen[0][1]["proxies"] == {}
    assert seen[0][1]["headers"]["Accept"] == "application/json"

    missing_domain = connectivity.check_email_api(
        "inbucket",
        {"inbucket_api_base": "http://127.0.0.1:9000", "inbucket_domain": ""},
        http_get,
        lambda *args, **kwargs: None,
    )
    assert missing_domain[1] is False and "inbucket_domain" in missing_domain[2]

    not_found = connectivity.check_email_api(
        "inbucket",
        {"inbucket_api_base": "http://127.0.0.1:9000", "inbucket_domain": "mail.example.com"},
        lambda url, **kwargs: FakeResponse("no route", status_code=404),
        lambda *args, **kwargs: None,
    )
    assert not_found[1] is False and "404" in not_found[2]


if __name__ == "__main__":
    test_normalize_base()
    test_parse_domains_and_levels()
    test_random_email_domain_rotation_and_levels()
    test_create_address_requires_domain()
    test_create_address_uses_random_levels()
    test_wait_for_code_detail_body_and_cleanup()
    test_wait_for_code_subject_short_circuit()
    test_wait_for_code_timeout_purges()
    test_wait_for_code_requires_base()
    test_list_messages_raises_on_http_error()
    test_connectivity_probe()
    print("OK inbucket")
