#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给 `ui_ttl_flip.mjs` 造一条**到期时刻精确可控**的真实传输。

只做一件事：注册发送方 → 建一条传输（READY）→ 把 `expires_at` 改成 `now() + N 秒`，
并把**库里的精确值**（带微秒）与**接口返回的值**（秒级）一并打出来，供翻转探针判定
"界面是不是比服务端更早判过期"。

用法：
    python3 qa/evidence/v5/v5_flip_seed.py --base-url http://127.0.0.1:18099 \
        --dsn "$TEST_DATABASE_URL" --schema gate_v5_flip --recipient <4 位码> --seconds 20
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", required=True)
    ap.add_argument("--recipient", required=True)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--size", type=int, default=7654321, help="故意用不常见大小，便于在列表里认出这一行")
    args = ap.parse_args(argv)

    c = Y.Client(args.base_url)
    snd, _ = c.register_pair("flip-sender", "翻转探针")
    chunk = 1024 * 1024
    chunks = max(1, round(args.size / chunk))
    t = Y.make_transfer(c, snd, args.recipient, size=chunks * chunk, chunk_size=chunk, chunks=chunks)

    rc, out = Y.psql(args.dsn, "update transfers set expires_at = now() + "
                               f"interval '{args.seconds} seconds' where transfer_id='{t['transfer_id']}' "
                               "returning to_char(expires_at at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), "
                               "to_char(expires_at at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
                     args.schema)
    if rc != 0:
        raise SystemExit(f"改 expires_at 失败：{out}")
    db_exact, api_form = out.split("|")

    st, meta = c.transfer(t["transfer_id"])
    print(json.dumps({
        "transfer_id": t["transfer_id"],
        "plaintext_size": chunks * chunk,
        "db_expires_at": db_exact,          # 库里的精确值（含微秒）
        "api_expires_at": meta.get("expires_at"),  # 接口返回（秒级）
        "expect_seconds": args.seconds,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
