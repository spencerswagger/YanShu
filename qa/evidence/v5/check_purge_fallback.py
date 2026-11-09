#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ③b·兜底删密文（永久保留之后的回归）：终结行超过一批时，密文必须**全部**删掉。

背景（Ark 预审 P0）：元数据改成永久保留后，若兜底清理仍是
`ORDER BY terminal_at ASC LIMIT 200`，那每 tick 都取回同一批最老的 200 行 →
**第 201 行之后永远轮不到**，密文永久残留在盘上；更糟的是日志每轮照样打 `purged=200`，
把"没删掉"伪装成"一直在删"。

本脚本造 N（>200）条**未删密文**的终结行（直接在库里插 + 在 blob 目录种 prelude 文件），
只靠清道夫兜底，看它能不能把 N 条全删掉：

1. N=210 条终结行、密文都在盘上；
2. 清道夫跑若干轮后，**盘上残留必须是 0**；
3. 日志里 `purged` 不能恒等于批次大小（说明水位在推进），且出现多轮累加；
4. 若实现暴露 `purgeRemaining`，最终必须是 0。

用法：
    python3 qa/evidence/v5/check_purge_fallback.py --binary <yanshu-server> \
        --dsn "$TEST_DATABASE_URL" [--schema gate_v5_purge] [--count 210] [--wait 25]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import shutil
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

BATCH = 200  # cleanup.New 里的批次大小


def q(args, sql: str) -> str:
    rc, out = Y.psql(args.dsn, sql, args.schema)
    if rc != 0 or out.startswith(("ERROR", "psql:", "FATAL")):
        raise RuntimeError(f"SQL 失败（不允许当成通过）：{out[:200]}")
    return out


def insert_terminal(args, count: int) -> list[str]:
    """插 count 条 CONSUMED 行（terminal_at 一小时前，密文未删记录保持 NULL）。"""
    sql = f"""
    INSERT INTO transfers
      (transfer_id, sender_code, recipient_code, plaintext_size, chunk_size, chunk_count,
       prelude_len, prelude_sm3, state, max_downloads, created_at, updated_at, expires_at,
       upload_token_sm3, upload_token_kid, uploader_ip, terminal_reason, terminal_at)
    SELECT lpad(to_hex(g), 32, '0'), 'AWQW', 'X2EH', 1048576, 1048576, 1, 96,
           decode(repeat('00', 32), 'hex'), 'CONSUMED', 1,
           now() - interval '2 hours', now() - interval '2 hours', now() - interval '1 hour',
           decode(repeat('11', 32), 'hex'), '1', '203.0.113.9', 'CONSUMED',
           now() - interval '1 hour' - (g || ' seconds')::interval
    FROM generate_series(1, {count}) AS g
    ON CONFLICT (transfer_id) DO NOTHING
    """
    q(args, sql)
    ids = q(args, "select transfer_id from transfers where state='CONSUMED' "
                  "order by transfer_id limit " + str(count)).split()
    return ids


def plant_blobs(blob_root: Path, ids: list[str]) -> None:
    for tid in ids:
        d = blob_root / tid[:2] / tid
        d.mkdir(parents=True, exist_ok=True)
        (d / "prelude").write_bytes(b"YSPK-gate-purge-probe")
        (d / "chunks").mkdir(exist_ok=True)
        (d / "chunks" / "00000000").write_bytes(b"\x00" * 32)


def residue(blob_root: Path, ids: list[str]) -> int:
    return sum(1 for tid in ids if (blob_root / tid[:2] / tid).is_dir())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_purge")
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-purge"))
    ap.add_argument("--count", type=int, default=210)
    ap.add_argument("--wait", type=float, default=25.0)
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ③b 兜底删密文 · 永久保留后超过一批的终结行必须也被删干净",
                   f"count={args.count}（批次 {BATCH}）　schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    work = Path(args.work) / args.schema   # 每次跑独立目录：别把上一轮的日志读进来
    shutil.rmtree(work, ignore_errors=True)

    with Y.Server(args.binary, args.dsn, args.schema, work, sweep="1s") as srv:
        ids = insert_terminal(args, args.count)
        plant_blobs(srv.blob_dir(), ids)
        planted = residue(srv.blob_dir(), ids)
        rep.add(f"已种 {args.count} 条终结行且密文都在盘上", planted == args.count,
                f"残留文件目录={planted}")

        deadline = time.time() + args.wait
        last = planted
        while time.time() < deadline:
            last = residue(srv.blob_dir(), ids)
            if last == 0:
                break
            time.sleep(0.5)

        rep.add("清道夫跑完后盘上残留必须为 0", last == 0,
                f"残留={last}/{args.count}" + ("" if last == 0 else "（超过一批的行没被删 → 水位没推进）"))

        # 日志：purged 是否恒等于批次大小
        log = srv.sweep_log_lines()
        purged_vals = [int(m) for m in re.findall(r'"?purged"?=(\d+)', "\n".join(log))]
        nz = [v for v in purged_vals if v > 0]
        # 水位推进的证据：累计删够 N 条，且最后一轮必须是「不足一批」（210 → 200 + 10）
        rep.add("日志的 purged 累计覆盖全部行，且末批不足一批",
                bool(nz) and sum(nz) >= args.count and (args.count % BATCH == 0 or nz[-1] < BATCH),
                f"非零 purged 序列={nz[:8]}{'…' if len(nz) > 8 else ''} 累计={sum(nz)} 期望≥{args.count}")

        remaining = q(args, "select count(*) from transfers where state in ('CONSUMED','REVOKED','EXPIRED') "
                            "and ciphertext_purged_at is null") if "ciphertext_purged_at" in q(
            args, "select string_agg(column_name, ',') from information_schema.columns "
                  "where table_schema=current_schema() and table_name='transfers'") else ""
        if remaining != "":
            rep.add("库内「未确认删密文」的终结行归零", remaining.strip() == "0", f"未确认={remaining.strip()}")
        else:
            rep.add("库内「未确认删密文」计数", None, "该分支没有 ciphertext_purged_at 列（水位实现之前）")

    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
