# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ip_usage_store


def test_record_and_read_usage():
    with tempfile.TemporaryDirectory() as tmp:
        previous = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        try:
            assert ip_usage_store.get_ip_usage("1.2.3.4") == 0
            assert ip_usage_store.record_ip_usage("1.2.3.4") == 1
            assert ip_usage_store.record_ip_usage("1.2.3.4") == 2
            assert ip_usage_store.record_ip_usage("5.6.7.8") == 1
            assert ip_usage_store.get_ip_usage("1.2.3.4") == 2
            assert ip_usage_store.get_ip_usage("5.6.7.8") == 1
            assert ip_usage_store.get_all_ip_usage() == {"1.2.3.4": 2, "5.6.7.8": 1}
            assert ip_usage_store.get_total_usage() == 3
            # 空 IP 忽略
            assert ip_usage_store.record_ip_usage("") == 0
            assert ip_usage_store.record_ip_usage(None) == 0
        finally:
            ip_usage_store._USAGE_FILE = previous


def test_usage_persists_across_store_reloads():
    with tempfile.TemporaryDirectory() as tmp:
        previous = ip_usage_store._USAGE_FILE
        usage_file = Path(tmp) / "ip_usage.json"
        ip_usage_store._USAGE_FILE = usage_file
        try:
            ip_usage_store.record_ip_usage("9.9.9.9", times=3)
            # 模拟进程重启：重新加载文件
            ip_usage_store._USAGE_LOCK.acquire()
            try:
                reloaded = ip_usage_store._load_counts()
            finally:
                ip_usage_store._USAGE_LOCK.release()
            assert reloaded == {"9.9.9.9": 3}
            assert usage_file.is_file()
        finally:
            ip_usage_store._USAGE_FILE = previous


def test_record_usage_times_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        previous = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        try:
            assert ip_usage_store.record_ip_usage("1.1.1.1", times=5) == 5
            assert ip_usage_store.get_ip_usage("1.1.1.1") == 5
        finally:
            ip_usage_store._USAGE_FILE = previous


def test_per_ip_limit_override_and_fallback():
    with tempfile.TemporaryDirectory() as tmp:
        previous = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        try:
            # 未设置覆盖 → None（调用方回退全局）
            assert ip_usage_store.get_per_ip_limit("2.2.2.2") is None
            ip_usage_store.set_ip_usage_limit("2.2.2.2", 7)
            assert ip_usage_store.get_per_ip_limit("2.2.2.2") == 7
            # 覆盖不影响其他 IP
            assert ip_usage_store.get_per_ip_limit("3.3.3.3") is None
            # 清除覆盖 → None（回退全局）
            ip_usage_store.set_ip_usage_limit("2.2.2.2", 0)
            assert ip_usage_store.get_per_ip_limit("2.2.2.2") is None
        finally:
            ip_usage_store._USAGE_FILE = previous


def test_delete_ip_usage():
    with tempfile.TemporaryDirectory() as tmp:
        previous = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        try:
            ip_usage_store.record_ip_usage("4.4.4.4", times=3)
            ip_usage_store.set_ip_usage_limit("4.4.4.4", 5)
            ip_usage_store.set_ip_usage_meta("4.4.4.4", {"country": "US"})
            assert ip_usage_store.delete_ip_usage("4.4.4.4") is True
            assert ip_usage_store.get_ip_usage("4.4.4.4") == 0
            assert ip_usage_store.get_per_ip_limit("4.4.4.4") is None
            assert ip_usage_store.get_ip_usage_meta("4.4.4.4") == {}
            # 不存在的 IP 返回 False
            assert ip_usage_store.delete_ip_usage("4.4.4.4") is False
        finally:
            ip_usage_store._USAGE_FILE = previous


def test_meta_and_detail():
    with tempfile.TemporaryDirectory() as tmp:
        previous = ip_usage_store._USAGE_FILE
        ip_usage_store._USAGE_FILE = Path(tmp) / "ip_usage.json"
        try:
            ip_usage_store.record_ip_usage("8.8.8.8", times=2)
            ip_usage_store.set_ip_usage_meta(
                "8.8.8.8", {"country": "US", "isp": "ACME", "org": "ACME-NET", "latency_ms": 12}
            )
            meta = ip_usage_store.get_ip_usage_meta("8.8.8.8")
            assert meta["country"] == "US"
            assert meta["isp"] == "ACME"
            assert meta["latency_ms"] == 12
            # 合并写入保留旧字段
            ip_usage_store.set_ip_usage_meta("8.8.8.8", {"asn": "AS123"})
            meta = ip_usage_store.get_ip_usage_meta("8.8.8.8")
            assert meta["country"] == "US"
            assert meta["asn"] == "AS123"
            # 全量详情
            detail = ip_usage_store.get_all_ip_usage_detail()
            item = next(it for it in detail if it["ip"] == "8.8.8.8")
            assert item["count"] == 2
            assert item["limit"] is None
            assert item["meta"]["country"] == "US"
            # 只有覆盖、没有计数的 IP 也出现在详情里
            ip_usage_store.set_ip_usage_limit("5.5.5.5", 3)
            detail = ip_usage_store.get_all_ip_usage_detail()
            item = next(it for it in detail if it["ip"] == "5.5.5.5")
            assert item["count"] == 0
            assert item["limit"] == 3
            # 旧格式兼容：只写 counts 的 JSON 仍可读取
            usage_file = Path(tmp) / "legacy.json"
            usage_file.write_text('{"counts": {"7.7.7.7": 9}}', encoding="utf-8")
            old = ip_usage_store._USAGE_FILE
            ip_usage_store._USAGE_FILE = usage_file
            try:
                assert ip_usage_store.get_ip_usage("7.7.7.7") == 9
                assert ip_usage_store.get_per_ip_limit("7.7.7.7") is None
            finally:
                ip_usage_store._USAGE_FILE = old
        finally:
            ip_usage_store._USAGE_FILE = previous


if __name__ == "__main__":
    test_record_and_read_usage()
    test_usage_persists_across_store_reloads()
    test_record_usage_times_parameter()
    test_per_ip_limit_override_and_fallback()
    test_delete_ip_usage()
    test_meta_and_detail()
    print("OK ip usage store")
