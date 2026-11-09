#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给界面证据脚本造「待接收」的真实传输（TTL 三态 + 一条**短 TTL**）。

供 `ui_v5_shots.mjs` 调用，不单独作为验收脚本。

为什么有一条短 TTL：v5/`#49` 之后 TTL 在**读写路径即时终结**，`/v1/inbox` 永不返回过期行，
所以「已过期」这一态**不能靠种一条过期记录来造**（那种做法在该语义下永远看不到）。
真实路径是：无过期的行已经在列表里 → 时间到点 → 该行自己翻成「已过期」。
因此这里种一条 `expires_at = now() + N 秒` 的行，由界面脚本在页面内**等它到点**。

四条：
  1. `23h`  —— `ttl_seconds=82800`，服务端自己算的到期时刻；
  2. `42m`  —— 契约把 TTL 夹在 1–24 h，只能把真实行的 `expires_at` 前移；
  3. `50h`  —— 同上，造「2 天后过期」；
  4. `short`—— `expires_at = now() + N 秒`（`--short-ttl`，默认 30），页面内等到点。

用法：
    python3 qa/evidence/v5/v5_ui_seed.py --base-url http://127.0.0.1:18099 \
        --dsn "$TEST_DATABASE_URL" --schema gate_v5_ui --recipient <4 位码> \
        [--short-ttl 30] [--json-out seeds.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402


def expires_at(args, tid: str) -> str:
    rc, out = Y.psql(args.dsn, f"select expires_at from transfers where transfer_id='{tid}'", args.schema)
    if rc != 0:
        raise SystemExit(f"查 expires_at 失败：{out}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True, help="服务端根（不带 /v1）")
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", required=True)
    ap.add_argument("--recipient", required=True)
    ap.add_argument("--short-ttl", type=int, default=30, help="短 TTL 那条还有多少秒到期")
    ap.add_argument("--json-out", default="")
    args = ap.parse_args(argv)

    c = Y.Client(args.base_url)
    snd, _ = c.register_pair("ui-sender", "发件人甲")
    out = []

    def push(name, tid):
        out.append({"name": name, "transfer_id": tid, "expires_at": expires_at(args, tid)})

    # 1) 23 小时后过期
    t1 = Y.make_transfer(c, snd, args.recipient, size=3 * 1024 * 1024,
                         chunk_size=1024 * 1024, chunks=3, ttl_seconds=82800)
    push("23h", t1["transfer_id"])

    # 2) 42 分钟后过期
    t2 = Y.make_transfer(c, snd, args.recipient, size=2 * 1024 * 1024,
                         chunk_size=1024 * 1024, chunks=2, ttl_seconds=3600)
    Y.psql(args.dsn, "update transfers set expires_at = now() + interval '42 minutes' "
                     f"where transfer_id = '{t2['transfer_id']}'", args.schema)
    push("42m", t2["transfer_id"])

    # 3) 2 天后过期
    t3 = Y.make_transfer(c, snd, args.recipient, size=1024 * 1024,
                         chunk_size=1024 * 1024, chunks=1, ttl_seconds=86400)
    Y.psql(args.dsn, "update transfers set expires_at = now() + interval '50 hours' "
                     f"where transfer_id = '{t3['transfer_id']}'", args.schema)
    push("50h", t3["transfer_id"])

    # 4) 短 TTL：页面内等它到点，看这一行自己翻成「已过期」
    t4 = Y.make_transfer(c, snd, args.recipient, size=1024 * 1024,
                         chunk_size=1024 * 1024, chunks=1, ttl_seconds=3600)
    Y.psql(args.dsn, "update transfers set expires_at = now() + "
                     f"interval '{int(args.short_ttl)} seconds' "
                     f"where transfer_id = '{t4['transfer_id']}'", args.schema)
    push("short", t4["transfer_id"])

    payload = {"recipient": args.recipient, "shortTtlSec": args.short_ttl, "seeds": out}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
