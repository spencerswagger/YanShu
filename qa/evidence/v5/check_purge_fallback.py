#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ③b·兜底删密文（永久保留后的 P0 回归）：超过一批的终结行也必须被删干净，且**每轮推进到不同行**。

背景（Ark 预审 P0）：元数据永久保留后，若兜底清理仍是
`ORDER BY terminal_at ASC LIMIT 200`，每 tick 都取回同一批最老的 200 行 →
第 201 行之后**永远轮不到**，密文永久残留；更糟的是日志每轮照样打 `purged=200`，把"没删掉"伪装成"一直在删"。

验 4 件事：
1. 种 N（> 批次）条**未删密文**的终结行 + 盘上真实 prelude/块文件，只靠清道夫兜底 →
   **盘上残留必须是 0**；
2. **逐轮推进**：把文件消失的时刻按轮快照，第 1 轮与第 2 轮删掉的**必须是不同批行**（交集为空），
   且各轮之和 = N（旧实现第 2 轮会重复删同一批或干脆不动）；
3. 日志 `purged` / `purgeRemaining` **不是常量**：末批不足一批、剩余数归零；
4. 事务内终结（`newly=false`）那条路径：把清道夫拉到 600s，走一次「到期后取件」与一次 `ack`，
   密文必须**在这一次请求里**就没（不能等 sweeper 兜底）。

用法：
    python3 qa/evidence/v5/check_purge_fallback.py --binary <yanshu-server> \
        --dsn "$TEST_DATABASE_URL" [--schema gate_v5_purge] [--count 250] [--wait 30]
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
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
    return q(args, "select transfer_id from transfers where terminal_reason='CONSUMED' "
                   "order by terminal_at limit " + str(count)).split()


def plant(blob_root: Path, ids: list[str]) -> None:
    for tid in ids:
        d = blob_root / tid[:2] / tid
        (d / "chunks").mkdir(parents=True, exist_ok=True)
        (d / "prelude").write_bytes(b"YSPK-gate-purge-probe")
        (d / "chunks" / "00000000").write_bytes(b"\x00" * 32)


def present(blob_root: Path, ids: list[str]) -> set[str]:
    return {tid for tid in ids if (blob_root / tid[:2] / tid).is_dir()}


def batches_over_time(blob_root: Path, ids: list[str], wait: float) -> list[set[str]]:
    """按时间顺序记录"每一轮被删掉的那批行"。"""
    prev = present(blob_root, ids)
    removed: list[set[str]] = []
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.4)
        cur = present(blob_root, ids)
        gone = prev - cur
        if gone:
            removed.append(gone)
        prev = cur
        if not cur:
            break
    return removed


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_purge")
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-purge"))
    ap.add_argument("--count", type=int, default=250)
    ap.add_argument("--wait", type=float, default=30.0)
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ③b 兜底删密文 · 超过一批的终结行必须被删、且每轮推进到不同行",
                   f"count={args.count}（批次 {BATCH}）　schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    work = Path(args.work) / args.schema
    shutil.rmtree(work, ignore_errors=True)

    with Y.Server(args.binary, args.dsn, args.schema, work, sweep="1s") as srv:
        ids = insert_terminal(args, args.count)
        plant(srv.blob_dir(), ids)
        rep.add(f"已种 {args.count} 条终结行，且密文真实落盘", len(present(srv.blob_dir(), ids)) == args.count,
                f"盘上={len(present(srv.blob_dir(), ids))}/{args.count}")

        batches = batches_over_time(srv.blob_dir(), ids, args.wait)
        left = present(srv.blob_dir(), ids)
        rep.add("清道夫跑完：盘上残留必须为 0", not left,
                f"残留={len(left)}/{args.count}" + ("" if not left else "（超过一批的行没被删 → 水位没推进）"))

        # 逐轮推进：至少两批，且两批交集为空
        if len(batches) >= 2:
            b1, b2 = batches[0], batches[1]
            rep.add("第 1 轮与第 2 轮删的是**不同批**行（交集为空）",
                    not (b1 & b2), f"|第1轮|={len(b1)} |第2轮|={len(b2)} 交集={len(b1 & b2)}")
            rep.add("各轮覆盖并集 = 全部行（无重复删、无漏删）",
                    len(set().union(*batches)) == args.count,
                    f"并集={len(set().union(*batches))} / {args.count}，轮次数={len(batches)}")
        else:
            rep.add("第 1 轮与第 2 轮删的是**不同批**行（交集为空）", False,
                    f"只观察到 {len(batches)} 批（旧实现会一直删同一批）")

        log = "\n".join(srv.sweep_log_lines())
        purged_vals = [int(m) for m in re.findall(r'"?purged"?=(\d+)', log)]
        nz = [v for v in purged_vals if v > 0]
        rep.add("日志 purged 不是常量（累计覆盖全部行、末批不足一批）",
                bool(nz) and sum(nz) >= args.count and (args.count % BATCH == 0 or nz[-1] < BATCH),
                f"非零序列={nz[:6]}{'…' if len(nz) > 6 else ''} 累计={sum(nz)}")
        rem = [int(m) for m in re.findall(r'"?purgeRemaining"?=(\d+)', log)]
        rep.add("日志 purgeRemaining 有非零值且最终归零（真实剩余，不是批次大小）",
                bool(rem) and max(rem) > 0 and rem[-1] == 0,
                f"序列={rem[:8]}{'…' if len(rem) > 8 else ''}")

    # ── 事务内终结（newly=false）那条路径：清道夫拉到 600s，密文必须在请求内就没
    work2 = Path(args.work) / (args.schema + "-intx")
    shutil.rmtree(work2, ignore_errors=True)
    with Y.Server(args.binary, args.dsn, args.schema + "_intx", work2, sweep="600s") as srv2:
        c = Y.Client(srv2.base)
        snd, _ = c.register_pair("intx-sender", "发送方")
        rcv, _ = c.register_pair("intx-recipient", "接收方")

        # (a) 到期后取件：StartLease 事务内终结 → 该请求必须顺手把密文删了
        t = Y.make_transfer(c, snd, rcv, size=1024 * 1024, chunk_size=1024 * 1024, chunks=1)
        tid = t["transfer_id"]
        Y.psql(args.dsn, "update transfers set expires_at = now() - interval '1 second' "
                         f"where transfer_id='{tid}'", args.schema + "_intx")
        st, body = c.get_prelude(tid)
        code = (body.get("error") or {}).get("code") if isinstance(body, dict) else ""
        gone = not (srv2.blob_dir() / tid[:2] / tid).is_dir()
        rep.add("到期后取件（事务内终结、newly=false）：410 且密文当场删净",
                st == 410 and code == "TRANSFER_EXPIRED" and gone,
                f"{st} {code} 目录已消失={gone}（sweep=600s，不可能靠兜底）")

        # (b) ack 终结：同样在请求内删密文
        t2 = Y.make_transfer(c, snd, rcv, size=1024 * 1024, chunk_size=1024 * 1024, chunks=1)
        tid2 = t2["transfer_id"]
        stp, _ = c.get_prelude(tid2)
        dl = c.headers.get("x-ys-download-id", "")
        sta, bodya = c.ack(tid2, rcv, dl)
        gone2 = not (srv2.blob_dir() / tid2[:2] / tid2).is_dir()
        rep.add("ack 终结（事务内终结）：CONSUMED 且密文当场删净",
                sta == 200 and bodya.get("state") == "CONSUMED" and gone2,
                f"{sta} state={bodya.get('state')} 目录已消失={gone2}（sweep=600s）")

    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
