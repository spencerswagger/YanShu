#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布自测（沙箱无 docker，用 tag `v0.2.0` 的代码构建的本地二进制跑）：

1. `/healthz` 200；
2. `/v1/config`：`server_time` 存在、与 Date 同秒；`Cache-Control` / `CDN-Cache-Control: no-store`；
3. `/v1/stats`：三个 `no-store`、字段集精确、UTC 日界（服务端会话时区 UTC）；
4. 到期件 `GET /prelude` = `410 TRANSFER_EXPIRED`，且密文当场删净；
5. 一次完整真实收发（建包 → 传 prelude/块 → complete → 取 prelude/块 → ack → CONSUMED）；
6. 清理日志里 `purgeRemaining` 归 0、无 `sweep failed`。

用法：python3 qa/evidence/v5/release_selftest.py --binary <v0.2.0 构建的二进制> --dsn "$TEST_DATABASE_URL"
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import time
import urllib.request
from email.utils import parsedate_to_datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402


def http_headers(url: str) -> dict[str, str]:
    with urllib.request.urlopen(url, timeout=5) as r:
        return {k.lower(): v for k, v in r.headers.items()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_release_selftest")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v0.2.0 发布自测（本地二进制；沙箱无 docker，容器部署未验）",
                   f"schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    with Y.Server(args.binary, args.dsn, args.schema,
                  Path(tempfile.gettempdir()) / "ys-release-selftest", sweep="1s") as srv:
        # 1) healthz
        try:
            st = urllib.request.urlopen(f"{srv.base}/healthz", timeout=5).status
        except Exception as e:  # noqa: BLE001
            st = f"err:{e}"
        rep.add("/healthz 200", st == 200, f"status={st}")

        # 2) config
        c = Y.Client(srv.base)
        st, cfg = c.config()
        hdr = {k: (v or "").lower() for k, v in c.headers.items()}
        same_sec = False
        if cfg.get("server_time") and hdr.get("date"):
            try:
                same_sec = abs(parsedate_to_datetime(hdr["date"]).timestamp()
                               - time.mktime(time.strptime(cfg["server_time"], "%Y-%m-%dT%H:%M:%SZ"))) <= 2
            except Exception:  # noqa: BLE001
                same_sec = False
        rep.add("/v1/config 有 server_time 且与 Date 一致",
                st == 200 and bool(cfg.get("server_time")) and same_sec,
                f"server_time={cfg.get('server_time')} date={hdr.get('date')}")
        rep.add("/v1/config 两个 no-store 头",
                hdr.get("cache-control") == "no-store" and hdr.get("cdn-cache-control") == "no-store",
                f"cache-control={hdr.get('cache-control')!r} cdn={hdr.get('cdn-cache-control')!r}")

        # 3) stats
        st, stats = c.stats()
        h2 = {k: (v or "").lower() for k, v in c.headers.items()}
        hdrs_ok = all(h2.get(k) == "no-store"
                      for k in ("cache-control", "cdn-cache-control", "surrogate-control"))
        shape_ok = (set(stats) == {"today", "total", "generated_at"}
                    and set(stats.get("today", {})) == {"consumed", "consumed_bytes", "created"}
                    and set(stats.get("total", {})) == {"consumed", "consumed_bytes", "created"})
        rep.add("/v1/stats 三个 no-store + 字段集精确", st == 200 and hdrs_ok and shape_ok,
                f"{st} {json_short(stats)}")

        # 4)+5) 一次完整收发 + 到期 410
        snd, _ = c.register_pair("release-sender", "发送方")
        rcv, _ = c.register_pair("release-recipient", "接收方")
        chunk = 256 * 1024
        t = Y.make_transfer(c, snd, rcv, size=chunk * 3, chunk_size=chunk, chunks=3)
        tid = t["transfer_id"]
        stp, prelude = c.get_prelude(tid)
        dl = c.headers.get("x-ys-download-id", "")
        got = []
        for i in range(3):
            stc, data = c.get_chunk(tid, i, dl)
            got.append(stc == 200 and data == t["chunks"][i])
        sta, ack = c.ack(tid, rcv, dl)
        rep.add("一次完整真实收发（3 块逐字节一致 + ack → CONSUMED）",
                stp == 200 and all(got) and sta == 200 and ack.get("state") == "CONSUMED",
                f"prelude={stp} 块一致={got} ack={sta} state={ack.get('state')}")
        tdir = srv.blob_dir() / tid[:2] / tid
        rep.add("ack 后密文物理删除", not tdir.is_dir(), f"目录残留={tdir.is_dir()}")

        t2 = Y.make_transfer(c, snd, rcv, size=chunk, chunk_size=chunk, chunks=1)
        tid2 = t2["transfer_id"]
        Y.psql(args.dsn, "update transfers set expires_at = now() - interval '2 seconds' "
                         f"where transfer_id='{tid2}'", args.schema)
        stq, meta = c.transfer(tid2)
        ste, body = c.get_prelude(tid2)
        code = (body.get("error") or {}).get("code") if isinstance(body, dict) else ""
        rep.add("到期件 GET /prelude = 410 TRANSFER_EXPIRED（且密文当场删）",
                stq == 200 and meta.get("state") == "EXPIRED" and ste == 410
                and code == "TRANSFER_EXPIRED" and not (srv.blob_dir() / tid2[:2] / tid2).is_dir(),
                f"GET state={meta.get('state')} prelude={ste} {code}")

        # 6) 清理日志：造一条"终结但密文还在"的行，逼清道夫干活，日志才会打 purgeRemaining
        fake = "f" * 31 + "1"
        Y.psql(args.dsn, "insert into transfers (transfer_id,sender_code,recipient_code,plaintext_size,"
                         "chunk_size,chunk_count,prelude_len,state,max_downloads,created_at,updated_at,"
                         "expires_at,upload_token_kid,terminal_reason,terminal_at) values "
                         f"('{fake}','AWQW','X2EH',1024,1024,1,96,'CONSUMED',1,now(),now(),now(),'1',"
                         "\'CONSUMED\', now() - interval '1 hour')", args.schema)
        d = srv.blob_dir() / fake[:2] / fake
        (d / "chunks").mkdir(parents=True, exist_ok=True)
        (d / "prelude").write_bytes(b"release-selftest")
        time.sleep(3.5)
        log = "\n".join(srv.sweep_log_lines())
        rem = [int(m) for m in re.findall(r'"?purgeRemaining"?=(\d+)', log)]
        rep.add("清理日志 purgeRemaining 最终为 0", bool(rem) and rem[-1] == 0, f"序列={rem[-6:]}")
        rep.add("清理日志无 sweep failed", "sweep failed" not in log,
                f"出现次数={log.count('sweep failed')}")

    return rep.emit(args.json_out)


def json_short(o, n: int = 120) -> str:
    import json
    return json.dumps(o, ensure_ascii=False)[:n]


if __name__ == "__main__":
    sys.exit(main())
