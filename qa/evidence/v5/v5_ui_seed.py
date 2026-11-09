#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给界面证据脚本造三条「待接收」的真实传输（TTL 三态）。

供 `ui_v5_shots.mjs` 调用，不单独作为验收脚本：
它只负责在**真服务**上造数据，然后由 Chromium 打开真界面截图取证。

三条：
  ① 23 小时后过期（`ttl_seconds=82800`，服务端自己算的到期时刻）；
  ② 42 分钟后过期（契约把 TTL 夹在 1–24h，只能把真实行的 `expires_at` 前移）；
  ③ 已过期但还没被清道夫收走（`expires_at=now-1s`，服务端 sweep 间隔拉长到 60s，
     这正是用户在 TTL 刚过、清理还没跑到时看到的那一屏）。

用法：
    python3 qa/evidence/v5/v5_ui_seed.py --base-url http://127.0.0.1:4173/v1? \
        --dsn "$TEST_DATABASE_URL" --schema gate_v5_ui --recipient <4 位码> --json-out seeds.json
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
    ap.add_argument("--base-url", required=True, help="服务端根（不带 /v1）")
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", required=True)
    ap.add_argument("--recipient", required=True)
    ap.add_argument("--json-out", default="")
    args = ap.parse_args(argv)

    c = Y.Client(args.base_url)
    snd, _ = c.register_pair("ui-sender", "发件人甲")

    out = []
    # ① 23 小时后过期
    t1 = Y.make_transfer(c, snd, args.recipient, size=3 * 1024 * 1024,
                         chunk_size=1024 * 1024, chunks=3, ttl_seconds=82800)
    out.append({"name": "23h", "transfer_id": t1["transfer_id"],
                "expires_at": t1["created"]["expires_at"]})

    # ② 42 分钟后过期
    t2 = Y.make_transfer(c, snd, args.recipient, size=2 * 1024 * 1024,
                         chunk_size=1024 * 1024, chunks=2, ttl_seconds=3600)
    Y.psql(args.dsn, "update transfers set expires_at = now() + interval '42 minutes' "
                     f"where transfer_id = '{t2['transfer_id']}'", args.schema)
    out.append({"name": "42m", "transfer_id": t2["transfer_id"],
                "expires_at": Y.psql(args.dsn, "select expires_at from transfers where transfer_id="
                                              f"'{t2['transfer_id']}'", args.schema)[1]})

    # ③ 已过期（还没被清走）
    t3 = Y.make_transfer(c, snd, args.recipient, size=1024 * 1024,
                         chunk_size=1024 * 1024, chunks=1, ttl_seconds=3600)
    Y.psql(args.dsn, "update transfers set expires_at = now() - interval '1 second' "
                     f"where transfer_id = '{t3['transfer_id']}'", args.schema)
    out.append({"name": "expired", "transfer_id": t3["transfer_id"],
                "expires_at": Y.psql(args.dsn, "select expires_at from transfers where transfer_id="
                                              f"'{t3['transfer_id']}'", args.schema)[1]})

    payload = {"recipient": args.recipient, "seeds": out}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
