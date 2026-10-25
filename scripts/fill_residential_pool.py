#!/usr/bin/env python3
"""扫描树脂池 → ip-api 筛非机房出口 → 灌入 ip_ready_pool.json。

worker 换口优先消费就绪池，10 分钟 TTL 内用掉。用法:
  .venv/bin/python scripts/fill_residential_pool.py [身份数] [并发]
"""
import hashlib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from proxy_templates import expand_proxy_template, has_proxy_template  # noqa: E402

POOL_FILE = ROOT / "log" / "ip_ready_pool.json"
# 实测 resin sticky 会话可存活 ≥10 分钟（同身份 9 分钟间隔二次注册成功），
# 取 1 小时保守值；过期项由 worker 侧 refresh_pool 清理。
TTL = 3600.0

# ip-api hosting=False 但实测确认的机房 ASN（误报黑名单）
KNOWN_DC_ASNS = {
    "AS47172", "AS63023", "AS154177", "AS401434", "AS398823", "AS54600",
    "AS62240", "AS26666", "AS979", "AS152672", "AS219202", "AS16276",
    "AS31898", "AS30058", "AS14061", "AS16509", "AS212238", "AS216071",
    "AS152179", "AS20473", "AS56630", "AS57043", "AS61112", "AS25198",
    "AS26383", "AS201106", "AS204427", "AS213520", "AS26042", "AS13335",
    "AS14618", "AS18186", "AS51031", "AS215373", "AS402279", "AS17621",
}


def load_template() -> str:
    state = json.loads((ROOT / "log" / "proxy_pool.json").read_text())
    for item in state.get("items", []):
        if item.get("enabled") and has_proxy_template(item.get("url", "")):
            return item["url"]
    raise SystemExit("proxy_pool.json 无含 {session} 的启用代理")


def exit_ip_of(url: str) -> str:
    try:
        r = requests.get(
            "http://checkip.amazonaws.com/",
            proxies={"http": url, "https": url}, timeout=25)
        return r.text.strip()
    except Exception:
        return ""


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    template = load_template()
    identities = [
        expand_proxy_template(template, identity=f"resi-{int(time.time())}-{i}")
        for i in range(n)
    ]
    rows = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for url, fut in zip(identities, [ex.submit(exit_ip_of, u) for u in identities]):
            ip = fut.result()
            if ip:
                rows.append({"identity_url": url, "exit_ip": ip})
    print(f"[scan] 有效出口 {len(rows)}/{n}")

    info = {}
    ips = sorted({r["exit_ip"] for r in rows})
    for s in range(0, len(ips), 90):
        for attempt in range(3):
            try:
                resp = requests.post(
                    "http://ip-api.com/batch?fields=query,countryCode,as,asname,isp,org,proxy,hosting,mobile",
                    json=ips[s:s + 90], timeout=30)
                data = resp.json()
                if isinstance(data, list):
                    info.update({d["query"]: d for d in data
                                 if isinstance(d, dict) and d.get("query")})
                    break
            except Exception:
                pass
            time.sleep(65 if attempt < 2 else 0)

    now = time.time()
    pool = json.loads(POOL_FILE.read_text()) if POOL_FILE.exists() else {"items": []}
    items = [i for i in pool.get("items", []) if float(i.get("expires_at") or 0) > now]
    known = {i["id"] for i in items}
    added = 0
    for r in rows:
        d = info.get(r["exit_ip"], {})
        if d.get("hosting") is not False:
            continue
        asn = (d.get("as") or "").split(" ")[0]
        if asn in KNOWN_DC_ASNS:
            continue
        eid = hashlib.sha256(r["identity_url"].encode()).hexdigest()[:16]
        if eid in known:
            continue
        items.append({
            "id": eid,
            "template_url": template,
            "expanded_url": r["identity_url"],
            "exit_ip": r["exit_ip"],
            "used": 0,
            "limit": 0,
            "usable": True,
            "checked_at": now,
            "expires_at": now + TTL,
            "consumer": "",
            "consumed_at": 0.0,
        })
        added += 1
        print(f"[pool] + {r['exit_ip']:>16} {d.get('countryCode','?')} {d.get('as','?')}")
    pool["items"] = items
    pool["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    POOL_FILE.write_text(json.dumps(pool, ensure_ascii=False, indent=1))
    print(f"灌池完成: +{added} 个非机房身份（池内共 {len(items)} 项，TTL 10 分钟）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
