# -*- coding: utf-8 -*-
"""SharedSlotPool 共享槽位池单元测试。

回归背景：run_registration_cli / GUI 曾按 divmod 把 count 静态切块分给
各 worker，快 worker 跑完自己的份额就退出，慢 worker 掉队后并发只剩 1。
改为共享领取后，验证：所有槽位恰好被领完一次、池空后 claim 返回 None、
fail_unclaimed 原子清空未领取槽位且只生效一次。
"""
from pathlib import Path
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from grok_register_ttk import SharedSlotPool


def test_claim_exhausts_pool_exactly_once():
    pool = SharedSlotPool(10)
    claimed = []
    for _ in range(10):
        claimed.append(pool.claim())
    assert claimed == list(range(10))
    assert pool.claim() is None
    assert pool.remaining() == 0


def test_claim_is_thread_safe_no_duplicates_no_gaps():
    total = 500
    workers = 8
    pool = SharedSlotPool(total)
    results = []
    lock = threading.Lock()

    def run():
        got = []
        while True:
            slot = pool.claim()
            if slot is None:
                break
            got.append(slot)
        with lock:
            results.extend(got)

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == list(range(total))
    assert len(results) == total
    assert pool.remaining() == 0


def test_fail_unclaimed_marks_leftovers_once():
    pool = SharedSlotPool(10)
    for _ in range(4):
        pool.claim()
    assert pool.remaining() == 6
    assert pool.fail_unclaimed() == 6
    # 第二次调用不再重复计数
    assert pool.fail_unclaimed() == 0
    assert pool.remaining() == 0
    assert pool.claim() is None


def test_slow_worker_gets_help_after_fast_worker_drains_pool():
    """模拟快 worker 领完剩余槽位：慢 worker 只领了 2 个，
    快 worker 能领到其余全部，池最终恰好耗尽。"""
    total = 13
    pool = SharedSlotPool(total)
    # 慢 worker 领 2 个后开始"卡住"
    assert pool.claim() == 0
    assert pool.claim() == 1
    # 快 worker 接手，领完剩余 11 个
    fast = []
    for _ in range(11):
        slot = pool.claim()
        assert slot is not None
        fast.append(slot)
    assert fast == list(range(2, 13))
    assert pool.claim() is None


def test_zero_total_pool():
    pool = SharedSlotPool(0)
    assert pool.claim() is None
    assert pool.remaining() == 0
    assert pool.fail_unclaimed() == 0


if __name__ == "__main__":
    test_claim_exhausts_pool_exactly_once()
    test_claim_is_thread_safe_no_duplicates_no_gaps()
    test_fail_unclaimed_marks_leftovers_once()
    test_slow_worker_gets_help_after_fast_worker_drains_pool()
    test_zero_total_pool()
    print("OK shared slot pool")
