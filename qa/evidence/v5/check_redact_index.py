#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ③c·脱敏扫描的索引与代价：20 万行稳态上必须是索引扫描，不是全表扫。

背景（预审 P1）：`RedactOldTerminal` 每 30 秒跑一次，没有索引时是
「终结 ∧ 未脱敏」条件的**全表扫**（20 万行 74.7 ms / 5,732 buffers）。
`0009` 加了部分索引 `transfers_terminal_unredacted_idx`，谓词必须与查询 WHERE 逐字对齐才会被用。

本脚本：真建 20 万行 → ANALYZE → 用真实 SQL 跑 `EXPLAIN (ANALYZE, BUFFERS)`，
1. 报计划节点（Index Scan / Bitmap / Seq Scan）+ buffers + 执行时间；
2. **紧接着**把大批行一次脱敏（模拟"清理刚跑完那阵"，表里一堆死元组、部分索引刚缩水），
   再跑同一条 EXPLAIN，看是否退化成几十毫秒级 / 换成 Seq Scan；
3. 结论给"稳态快不快要看索引，跑完那阵的退化是不是真的存在"。

用法：
    python3 qa/evidence/v5/check_redact_index.py --binary <yanshu-server> \
        --dsn "$TEST_DATABASE_URL" [--schema gate_v5_redact] [--rows 200000]
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

REDACT_SQL = """
UPDATE transfers
SET uploader_ip = NULL, prelude_sm3 = NULL, upload_token_sm3 = NULL
WHERE transfer_id IN (
    SELECT transfer_id FROM transfers
    WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED')
      AND terminal_at IS NOT NULL AND terminal_at < now() - interval '30 days'
      AND (uploader_ip IS NOT NULL OR prelude_sm3 IS NOT NULL OR upload_token_sm3 IS NOT NULL)
    ORDER BY terminal_at
    LIMIT 200
)"""


def q(args, sql: str) -> str:
    rc, out = Y.psql(args.dsn, sql, args.schema)
    if rc != 0 or out.startswith(("ERROR", "psql:", "FATAL")):
        raise RuntimeError(f"SQL 失败（不允许当成通过）：{out[:300]}")
    return out


def explain(args) -> tuple[str, int | None, int | None]:
    """跑 EXPLAIN (ANALYZE, BUFFERS)，返回 (原文, 执行时间ms, buffers 总量)。"""
    rc, out = Y.psql(args.dsn, "EXPLAIN (ANALYZE, BUFFERS) " + REDACT_SQL, args.schema)
    if rc != 0 or out.startswith(("ERROR", "psql:")):
        raise RuntimeError(f"EXPLAIN 失败：{out[:300]}")
    ms = None
    m = re.search(r"Execution Time: ([\d.]+) ms", out)
    if m:
        ms = float(m.group(1))
    # EXPLAIN 文本里每个节点都有 Buffers 行，**最后一条**才是整条语句的合计
    buf = None
    hits = re.findall(r"Buffers: shared hit=(\d+)(?: read=(\d+))?", out)
    if hits:
        buf = sum(int(h) + int(r or 0) for h, r in [hits[-1]])
    return out, ms, buf


def explain_select(args) -> tuple[float | None, int | None]:
    """只量「找 200 个待脱敏行」这一步（UPDATE 里的 SELECT 子查询）。"""
    sql = """EXPLAIN (ANALYZE, BUFFERS)
    SELECT transfer_id FROM transfers
    WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED')
      AND terminal_at IS NOT NULL AND terminal_at < now() - interval '30 days'
      AND (uploader_ip IS NOT NULL OR prelude_sm3 IS NOT NULL OR upload_token_sm3 IS NOT NULL)
    ORDER BY terminal_at
    LIMIT 200"""
    rc, out = Y.psql(args.dsn, sql, args.schema)
    if rc != 0:
        raise RuntimeError(out[:300])
    m = re.search(r"Execution Time: ([\d.]+) ms", out)
    hits = re.findall(r"Buffers: shared hit=(\d+)(?: read=(\d+))?", out)
    return (float(m.group(1)) if m else None,
            (int(hits[-1][0]) + int(hits[-1][1] or 0)) if hits else None)


def summarize(plan: str) -> str:
    if "Index Scan" in plan or "Index Only Scan" in plan:
        head = "Index Scan"
        if "Bitmap Index Scan" in plan:
            head = "Bitmap Index Scan"
    elif "Bitmap Index Scan" in plan:
        head = "Bitmap Index Scan"
    elif "Seq Scan" in plan:
        head = "Seq Scan"
    else:
        head = "（未识别）"
    return head


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_redact")
    ap.add_argument("--rows", type=int, default=200000)
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-redact"))
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ③c 脱敏扫描 · 20 万行稳态必须走部分索引",
                   f"rows={args.rows}　schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    schema = args.schema.lower()
    work = Path(args.work) / schema
    shutil.rmtree(work, ignore_errors=True)
    Y.psql(args.dsn, f'drop schema if exists "{schema}" cascade')
    rc, out = Y.psql(args.dsn, f'create schema "{schema}"')
    if rc != 0:
        raise SystemExit(out)
    env = dict(os.environ, YANSHU_DATABASE_URL=f"{args.dsn}&search_path={schema}")
    mig = subprocess.run([args.binary, "-migrate-only"], env=env, capture_output=True, text=True, timeout=180)
    rep.add("迁移建表（含 0009 脱敏索引）", mig.returncode == 0,
            (mig.stderr or mig.stdout).strip().splitlines()[-1][:80] if (mig.stderr or mig.stdout).strip() else "ok")

    # 20 万行：90% 终结（30 天前终结、三列有值＝待脱敏），10% 活跃
    n_term = int(args.rows * 0.9)
    n_live = args.rows - n_term
    q(args, f"""
    INSERT INTO transfers
      (transfer_id, sender_code, recipient_code, plaintext_size, chunk_size, chunk_count, prelude_len,
       prelude_sm3, state, max_downloads, created_at, updated_at, expires_at,
       upload_token_sm3, upload_token_kid, uploader_ip, terminal_reason, terminal_at)
    SELECT lpad(to_hex(g), 32, '0'), 'AWQW', 'X2EH', 1048576, 1048576, 1, 96,
           decode(repeat('00', 32), 'hex'), 'CONSUMED', 1,
           now() - interval '40 days', now() - interval '40 days', now() - interval '30 days',
           decode(repeat('11', 32), 'hex'), '1', '203.0.113.' || (g % 250),
           'CONSUMED', now() - interval '35 days' - (g || ' seconds')::interval
    FROM generate_series(1, {n_term}) AS g""")
    if n_live:
        q(args, f"""
        INSERT INTO transfers
          (transfer_id, sender_code, recipient_code, plaintext_size, chunk_size, chunk_count, prelude_len,
           prelude_sm3, state, max_downloads, created_at, updated_at, expires_at,
           upload_token_sm3, upload_token_kid, uploader_ip)
        SELECT lpad(to_hex(g), 32, '0'), 'AWQW', 'X2EH', 1048576, 1048576, 1, 96,
               decode(repeat('00', 32), 'hex'), 'READY', 1,
               now(), now(), now() + interval '1 day',
               decode(repeat('11', 32), 'hex'), '1', '198.51.100.1'
        FROM generate_series({n_term + 1}, {args.rows}) AS g""")
    q(args, "ANALYZE transfers")
    total = q(args, "select count(*) from transfers").strip()
    candidates = q(args, "select count(*) from transfers where state in ('CONSUMED','REVOKED','EXPIRED') "
                         "and terminal_at < now() - interval '30 days'").strip()
    rep.add(f"造 {args.rows} 行并 ANALYZE", total == str(args.rows),
            f"表内={total} 待脱敏候选={candidates}")

    sel_ms, sel_buf = explain_select(args)
    rep.add("稳态：取 200 行的子查询走索引、且很便宜", (sel_ms or 10**9) <= 5 and (sel_buf or 10**9) <= 500,
            f"子查询 {sel_ms}ms / {sel_buf} buffers（Core 报 0.039ms 指的就是这一步）")

    plan, ms, buf = explain(args)
    node = summarize(plan)
    rep.add("稳态：整条 UPDATE 的计划走索引（不是 Seq Scan）", node != "Seq Scan",
            f"节点={node} 时间={ms}ms buffers={buf}（UPDATE 含 200 行写 + 索引维护）")
    rep.add("稳态：整条 UPDATE ≤ 30 ms", (ms or 10**9) <= 30, f"时间={ms}ms buffers={buf}")

    # 模拟"清理刚跑完那阵"：一次把剩余候选全脱敏（表里 18 万行被改、部分索引缩水）
    rc, out = Y.psql(args.dsn, "UPDATE transfers SET uploader_ip=NULL, prelude_sm3=NULL, upload_token_sm3=NULL "
                               "WHERE state IN ('CONSUMED','REVOKED','EXPIRED') "
                               "AND (uploader_ip IS NOT NULL OR prelude_sm3 IS NOT NULL OR upload_token_sm3 IS NOT NULL)",
                     schema)
    rep.add("模拟「清理刚跑完」：一次性脱敏全部候选行", rc == 0, out[:60])

    plan2, ms2, buf2 = explain(args)
    node2 = summarize(plan2)
    rep.add("紧接着再跑：仍不应退化成 Seq Scan", node2 != "Seq Scan",
            f"节点={node2} 时间={ms2}ms buffers={buf2}（死元组未回收时的高水位）")

    # VACUUM 后再量：证明这是「死元组/索引惰性清理」的瞬时现象，不是长期退化
    rc, vout = Y.psql(args.dsn, "VACUUM (ANALYZE) transfers", schema)
    plan3, ms3, buf3 = explain(args)
    node3 = summarize(plan3)
    rep.add("VACUUM 后回落到 ≤ 30 ms（瞬时退化不是长期问题）", (ms3 or 10**9) <= 30,
            f"VACUUM rc={rc} → {node3} {ms3}ms / {buf3} buffers")
    if ms2 and ms and ms2 > ms * 3:
        rep.note(f"退化观察：稳态 {ms}ms → 刚跑完 {ms2}ms（{ms2 / ms:.1f}×）→ VACUUM 后 {ms3}ms。"
                 "成因是部分索引里的死项与堆页可见性未更新（180k 行刚被改），属瞬时；"
                 "生产上自动 vacuum 会回收，若要避免这段抖动可把大批量脱敏分批摊到多 tick。")
    rep.note("稳态计划尾部：" + " / ".join(l.strip() for l in plan.splitlines()[-3:]))

    Y.psql(args.dsn, f'drop schema if exists "{schema}" cascade')
    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
