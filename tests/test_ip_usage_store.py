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


if __name__ == "__main__":
    test_record_and_read_usage()
    test_usage_persists_across_store_reloads()
    test_record_usage_times_parameter()
    print("OK ip usage store")
