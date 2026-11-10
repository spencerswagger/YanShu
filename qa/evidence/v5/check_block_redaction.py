#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ③d·块级指纹脱敏：`transfer_chunks.ciphertext_sm3` 30 天后必须为 NULL，别的都不许变。

背景（#48 7ed85bc）：脱敏清单从三列扩到**四列**——`transfers.uploader_ip` / `prelude_sm3` /
`upload_token_sm3` + `transfer_chunks.ciphertext_sm3`（块级密文指纹）。最容易漏的是最后这列：
它是新加的、在另一张表上、而且是**按块**而不是按行。

验 4 件事：
1. 真上传的多块传输，块行里 `ciphertext_sm3` 有值（不是空的"假数据"）；
2. 终结满 30 天后，该传输**所有块**的 `ciphertext_sm3` 均为 NULL；
3. `transfers` 除那三列外、**其余每一列逐值不变**（用 information_schema 拼出来比，不手抄列名）；
   `transfer_chunks` 除 `ciphertext_sm3` 外也不变；
4. 块侧候选集（`ciphertext_sm3 IS NOT NULL` 且属于已终结超期传输）**只减不增**。

用法：
    python3 qa/evidence/v5/check_block_redaction.py --binary <yanshu-server> --dsn "$TEST_DATABASE_URL" \
        [--schema gate_v5_block] [--json-out out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

SENSITIVE_TRANSFER = {"uploader_ip", "prelude_sm3", "upload_token_sm3"}


def q(args, sql: str) -> str:
    rc, out = Y.psql(args.dsn, sql, args.schema)
    if rc != 0 or out.startswith(("ERROR", "psql:", "FATAL")):
        raise RuntimeError(f"SQL 失败（不允许当成通过）：{out[:300]}")
    return out


def cols(args, table: str) -> list[str]:
    out = q(args, "select column_name from information_schema.columns "
                  f"where table_schema = current_schema() and table_name = '{table}' order by ordinal_position")
    return [c for c in out.split() if c]


def snapshot(args, tid: str) -> dict:
    tcols = [c for c in cols(args, "transfers") if c not in SENSITIVE_TRANSFER]
    ccols = [c for c in cols(args, "transfer_chunks") if c != "ciphertext_sm3"]
    tvals = q(args, "select " + ",".join(f"coalesce({c}::text,'<null>')" for c in tcols)
              + f" from transfers where transfer_id='{tid}'")
    cvals = q(args, "select chunk_index, " + ",".join(f"coalesce({c}::text,'<null>')" for c in ccols if c != "chunk_index")
              + f" from transfer_chunks where transfer_id='{tid}' order by chunk_index")
    return {"transfers": dict(zip(tcols, tvals.split("|"))), "chunks": cvals}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_block")
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-block"))
    ap.add_argument("--chunks", type=int, default=4)
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ③d 块级指纹脱敏 · ciphertext_sm3 30 天后为 NULL，其余逐值不变",
                   f"schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    with Y.Server(args.binary, args.dsn, args.schema, Path(args.work), sweep="5s") as srv:
        c = Y.Client(srv.base)
        snd, _ = c.register_pair("block-sender", "发送方")
        rcv, _ = c.register_pair("block-recipient", "接收方")
        chunk = 1024 * 1024
        t = Y.make_transfer(c, snd, rcv, size=chunk * args.chunks, chunk_size=chunk, chunks=args.chunks)
        tid = t["transfer_id"]
        st, prelude = c.get_prelude(tid)
        dl = c.headers.get("x-ys-download-id", "")
        st, ack = c.ack(tid, rcv, dl)
        rep.add("取件完成 → CONSUMED", st == 200 and ack.get("state") == "CONSUMED",
                f"{st} state={ack.get('state')}")

        # 1) 块上的指纹真的有值（真上传路径写的，不是空）
        nonnull = q(args, "select count(*) from transfer_chunks where transfer_id="
                          f"'{tid}' and ciphertext_sm3 is not null").strip()
        total = q(args, f"select count(*) from transfer_chunks where transfer_id='{tid}'").strip()
        rep.add("块行里 ciphertext_sm3 有值（真上传写入）", nonnull == total and int(total) == args.chunks,
                f"{nonnull}/{total} 块有指纹（期望 {args.chunks}）")

        # 造 260 条"已终结 40 天"的合成传输（各 2 块带指纹）：让块侧候选集明显大于一批，
        # 才能验"候选集只减不增"，而不是 0→0 的空转。
        q(args, """
        INSERT INTO transfers (transfer_id, sender_code, recipient_code, plaintext_size, chunk_size,
          chunk_count, prelude_len, prelude_sm3, state, max_downloads, created_at, updated_at,
          expires_at, upload_token_sm3, upload_token_kid, uploader_ip, terminal_reason, terminal_at)
        SELECT lpad(to_hex(900000 + g), 32, '0'), 'AWQW', 'X2EH', 2097152, 1048576, 2, 96,
          decode(repeat('00', 32), 'hex'), 'CONSUMED', 1, now() - interval '45 days',
          now() - interval '45 days', now() - interval '40 days', decode(repeat('11', 32), 'hex'),
          '1', '203.0.113.9', 'CONSUMED', now() - interval '40 days'
        FROM generate_series(1, 260) AS g""")
        q(args, """
        INSERT INTO transfer_chunks (transfer_id, chunk_index, length, stored_at, ciphertext_sm3)
        SELECT lpad(to_hex(900000 + g), 32, '0'), i, 1048576, now() - interval '45 days',
               decode(repeat('22', 32), 'hex')
        FROM generate_series(1, 260) AS g, generate_series(0, 1) AS i""")

        # 2) 把终结时间推到 40 天前（先改再看：terminal_at 本来就要变），随后立刻快照，
        #    之后红脱敏不许再动任何其它列。
        Y.psql(args.dsn, "update transfers set terminal_at = now() - interval '40 days' "
                         f"where transfer_id='{tid}'", args.schema)
        before = snapshot(args, tid)

        candidates = []
        deadline = time.time() + 25
        while time.time() < deadline:
            n = q(args, "select count(*) from transfer_chunks ch join transfers t "
                        "on t.transfer_id = ch.transfer_id where ch.ciphertext_sm3 is not null "
                        "and t.state in ('CONSUMED','REVOKED','EXPIRED') and t.terminal_at < now() - interval '30 days'")
            candidates.append(int(n.strip()))
            if candidates[-1] == 0 and len(candidates) > 1:
                break
            time.sleep(0.2)

        left = q(args, "select count(*) from transfer_chunks where transfer_id="
                       f"'{tid}' and ciphertext_sm3 is not null").strip()
        rep.add("终结 40 天 → 该传输所有块 ciphertext_sm3 为 NULL", left == "0", f"仍有指纹的块={left}")
        rep.add("块侧候选集只减不增（不会越扫越多）",
                bool(candidates) and candidates == sorted(candidates, reverse=True)
                and (max(candidates) > 0) and candidates[-1] == 0,
                f"候选序列首/末={candidates[:6]}…{candidates[-3:]}（峰值 {max(candidates) if candidates else 0}）")

        after = snapshot(args, tid)
        diff_t = {k: (before["transfers"][k], after["transfers"][k])
                  for k in before["transfers"] if before["transfers"][k] != after["transfers"][k]}
        rep.add("transfers 其余列逐值不变（除三列）", not diff_t,
                f"变化的列={diff_t or '无'}（比较了 {len(before['transfers'])} 列）")
        rep.add("transfer_chunks 除 ciphertext_sm3 外逐值不变", before["chunks"] == after["chunks"],
                f"块行 {len(before['chunks'].splitlines())} 行一致={before['chunks'] == after['chunks']}")

        empty = q(args, "select count(*) from transfer_chunks where transfer_id="
                        f"'{tid}'").strip()
        rep.add("块行本身仍在（永久保留的是行与计数）", empty == str(args.chunks), f"块行数={empty}")

    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
