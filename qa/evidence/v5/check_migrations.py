#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 迁移专项：`0010` 的非事务 / CONCURRENTLY / 迁移器行为（发版最大风险点）。

验 6 件事（每条都真跑）：
1. **干净库 0 → 0010**：一次跑完，9 个迁移全记录、5 个索引全 valid；
2. **0009 库补跑 0010**：手动铺 0001–0009 后只跑 0010，成功且不重复建索引；
3. **建索引期间不阻塞写**：CIC 期间另开会话持续 INSERT，逐条量耗时；并抓 `pg_locks` 证明
   它拿的是 `ShareUpdateExclusiveLock`（这是 CIC 的锁模式，`CREATE INDEX` 会是 `ShareLock`）；
4. **中断自愈**：CIC 跑到一半 SIGKILL → 留下 INVALID 索引；重跑必须靠
   `DROP INDEX CONCURRENTLY IF EXISTS` 自愈成 valid；
5. **幂等**：已到 0010 的库再跑一次 → 0 报错、索引不变；
6. **两个实例并发迁移不死锁**：两个 `-migrate-only` 同时上，一个持锁跑 CIC、另一个用
   `pg_try_advisory_lock` 轮询；两者都必须成功、输出里不得出现 `deadlock`，结束后不得残留 advisory 锁。

另外跑一遍迁移器的单测（切句 / 指令识别），命令与结果一起打出来。

用法：
    python3 qa/evidence/v5/check_migrations.py --binary <yanshu-server> \
        --migrations <server/internal/store/migrations 目录> --dsn "$TEST_DATABASE_URL" \
        [--seed 400000] [--json-out out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

INDEXES = [
    "transfers_terminal_at_idx",
    "transfers_created_at_idx",
    "transfers_unpurged_terminal_idx",
    "transfers_terminal_unredacted_idx",
    "transfer_chunks_unredacted_idx",
]
LOCK_KEY = 0x59616E536875  # "YanShu"


def q(dsn: str, sql: str, schema: str | None = None) -> str:
    rc, out = Y.psql(dsn, sql, schema)
    if rc != 0 or out.startswith(("ERROR", "psql:", "FATAL")):
        raise RuntimeError(f"SQL 失败（不允许当成通过）：{out[:300]}")
    return out


def migrate(binary: str, dsn: str, schema: str, timeout: float = 300) -> tuple[int, str, float]:
    env = dict(os.environ, YANSHU_DATABASE_URL=f"{dsn}&search_path={schema}")
    t0 = time.time()
    p = subprocess.run([binary, "-migrate-only"], env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0


def migrate_bg(binary: str, dsn: str, schema: str) -> subprocess.Popen:
    env = dict(os.environ, YANSHU_DATABASE_URL=f"{dsn}&search_path={schema}")
    return subprocess.Popen([binary, "-migrate-only"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def fresh_schema(dsn: str, schema: str) -> None:
    Y.psql(dsn, f'drop schema if exists "{schema}" cascade')
    rc, out = Y.psql(dsn, f'create schema "{schema}"')
    if rc != 0:
        raise RuntimeError(out)


def build_0009(args, schema: str) -> None:
    """手动铺 0001–0009（模拟"已经上线的 0009 库"），并记账。"""
    fresh_schema(args.dsn, schema)
    # schema_migrations 由迁移器自己建，手动铺迁移时也要先建出来（记账用）
    q(args.dsn, "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version text PRIMARY KEY, applied_at timestamptz NOT NULL)", schema)
    files = sorted(p for p in Path(args.migrations).glob("0*.sql"))
    for f in files:
        if f.name >= "0010":
            continue
        r = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                            f"{args.dsn}&options=-c%20search_path%3D{schema}", "-f", str(f)],
                           capture_output=True, text=True, env=dict(os.environ, PGPASSFILE=os.environ.get("PGPASSFILE", "")))
        if r.returncode != 0:
            raise RuntimeError(f"铺 {f.name} 失败：{(r.stderr or r.stdout)[:300]}")
        q(args.dsn, f"insert into schema_migrations(version, applied_at) values ('{f.name}', now()) "
                    "on conflict (version) do nothing", schema)


def index_states(args, schema: str) -> dict[str, str]:
    out = q(args.dsn, "select i.relname || '=' || (x.indisvalid and x.indisready)::text "
                      "from pg_index x join pg_class i on i.oid = x.indexrelid "
                      f"join pg_namespace n on n.oid = i.relnamespace where n.nspname = '{schema}' "
                      "and i.relname in (" + ",".join(f"'{n}'" for n in INDEXES) + ")", schema)
    return dict(row.split("=") for row in out.splitlines() if row)


def wait_ready(args, schema: str, timeout: float = 300) -> None:
    """等所有索引既不是 invalid 也不在 build 中（CIC 结束时 indisready/indisvalid 都 true）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = index_states(args, schema)
        if len(st) == len(INDEXES) and all(v == "true" for v in st.values()):
            return
        time.sleep(0.2)


def seed_rows(args, schema: str, n: int) -> None:
    q(args.dsn, f"""
    INSERT INTO transfers
      (transfer_id, sender_code, recipient_code, plaintext_size, chunk_size, chunk_count, prelude_len,
       prelude_sm3, state, max_downloads, created_at, updated_at, expires_at, upload_token_sm3,
       upload_token_kid, uploader_ip, terminal_reason, terminal_at)
    SELECT lpad(to_hex(g), 32, '0'), 'AWQW', 'X2EH', 1048576, 1048576, 1, 96,
           decode(repeat('00', 32), 'hex'), 'CONSUMED', 1,
           now() - interval '40 days', now() - interval '40 days', now() - interval '30 days',
           decode(repeat('11', 32), 'hex'), '1', '203.0.113.' || (g % 250),
           'CONSUMED', now() - interval '35 days' - (g || ' seconds')::interval
    FROM generate_series(1, {n}) AS g""", schema)
    q(args.dsn, f"""
    INSERT INTO transfer_chunks (transfer_id, chunk_index, length, stored_at, ciphertext_sm3)
    SELECT lpad(to_hex(g), 32, '0'), 0, 1048576, now() - interval '40 days',
           decode(repeat('22', 32), 'hex')
    FROM generate_series(1, {n}) AS g""", schema)
    q(args.dsn, "ANALYZE transfers", schema)
    q(args.dsn, "ANALYZE transfer_chunks", schema)


def insert_latency(args, schema: str, n: int) -> list[float]:
    """用一条语句插 n 行，量单次往返耗时（含 psql 启动固定开销，所以看的是"有没有量级突变"）。"""
    out = []
    for i in range(n):
        t0 = time.time()
        q(args.dsn, "insert into transfers (transfer_id, sender_code, recipient_code, plaintext_size, "
                    "chunk_size, chunk_count, prelude_len, state, max_downloads, created_at, updated_at, "
                    "expires_at, upload_token_kid) values "
                    f"(md5(random()::text || '{time.time()}'), 'AWQW', 'X2EH', 1024, 1024, 1, 96, 'READY', 1, "
                    "now(), now(), now() + interval '1 hour', '1')", schema)
        out.append((time.time() - t0) * 1000)
    return out


def lock_modes(args, schema: str) -> set[str]:
    out = q(args.dsn, "select distinct l.mode from pg_locks l join pg_class c on c.oid = l.relation "
                      f"join pg_namespace n on n.oid = c.relnamespace where n.nspname='{schema}' "
                      "and c.relname in ('transfers','transfer_chunks') and l.granted", schema)
    return set(out.splitlines())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--migrations", required=True, help="server/internal/store/migrations 目录")
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--seed", type=int, default=400000, help="建索引要够久才测得出阻塞；默认 40 万行")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 迁移专项 · 0010 非事务 CIC + 迁移器（单连接 / try-lock / 切句）",
                   f"seed={args.seed} 行　binary={Path(args.binary).name}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    # ── 1) 干净库 0 → 0010
    sch = "gate_mig_clean"
    fresh_schema(args.dsn, sch)
    rc, out, dur = migrate(args.binary, args.dsn, sch)
    applied = q(args.dsn, "select count(*) from schema_migrations", sch).strip()
    st = index_states(args, sch)
    rep.add("干净库 0→0010 一次跑成功", rc == 0, f"rc={rc} {dur:.1f}s 记录迁移={applied}")
    rep.add("5 个 v5 索引全部建成且 valid", len(st) == len(INDEXES) and all(v == "true" for v in st.values()),
            f"{json.dumps(st, ensure_ascii=False)}")

    # ── 2) 0009 库补跑 0010
    sch2 = "gate_mig_0009"
    build_0009(args, sch2)
    before = index_states(args, sch2)
    seed_rows(args, sch2, args.seed)
    base_latency = insert_latency(args, sch2, 3)
    proc = migrate_bg(args.binary, args.dsn, sch2)
    time.sleep(0.4)
    during_latency = insert_latency(args, sch2, 8)
    modes = lock_modes(args, sch2)
    out_bg = proc.communicate(timeout=300)[0] or ""
    wait_ready(args, sch2)
    after = index_states(args, sch2)
    rep.add("0009 库补跑 0010 成功（不重复建索引报错）", proc.returncode == 0 and "already exists" not in out_bg,
            f"rc={proc.returncode} 补跑前索引={len(before)} 补跑后={len(after)} out={(out_bg.strip().splitlines() or [''])[-1][:60]}")
    rep.add("补跑后 5 个索引 valid", len(after) == len(INDEXES) and all(v == "true" for v in after.values()),
            json.dumps(after, ensure_ascii=False))

    # ── 3) 建索引期间写入不阻塞
    base_max = max(base_latency)
    during_max = max(during_latency)
    rep.add("CIC 期间 INSERT 未被阻塞（耗时无数量级突变）",
            during_max < max(1000.0, base_max * 20),
            f"基线 max={base_max:.0f}ms　CIC 期间 max={during_max:.0f}ms（{len(during_latency)} 次）")
    rep.add("CIC 的锁模式是 ShareUpdateExclusiveLock（不是 ShareLock）",
            "ShareUpdateExclusiveLock" in modes and "ShareLock" not in modes,
            f"观测到的锁={sorted(modes)}")

    # ── 4) 中断自愈
    sch3 = "gate_mig_interrupt"
    build_0009(args, sch3)
    seed_rows(args, sch3, args.seed)
    p2 = migrate_bg(args.binary, args.dsn, sch3)
    # 精确等"CIC 正在建某个索引"：pg_index 里出现 indisvalid=false 的索引就立刻杀，
    # 不靠猜时间（第一轮就是杀在两条 CIC 之间，才没留下 INVALID）。
    deadline = time.time() + 60
    caught = False
    while time.time() < deadline:
        bad = q(args.dsn, "select count(*) from pg_index x join pg_class i on i.oid = x.indexrelid "
                          f"join pg_namespace n on n.oid = i.relnamespace where n.nspname='{sch3}' "
                          "and not x.indisvalid", sch3).strip()
        if bad != "0":
            caught = True
            break
        time.sleep(0.05)
    # 注意：SIGKILL 客户端**不会**中断正在跑的 CIC（PostgreSQL 会把这一条语句跑完，
    # 我第一版就是这么"杀"的，结果索引是 valid）。要复现真实故障（服务端重启/连接被掐），
    # 必须杀**后端会话**。
    q(args.dsn, "select count(*) from (select pg_terminate_backend(pid) from pg_stat_activity "
                "where query ilike 'CREATE INDEX CONCURRENTLY%' and pid <> pg_backend_pid()) s", sch3)
    try:
        p2.wait(timeout=30)
    except subprocess.TimeoutExpired:
        p2.kill()
    time.sleep(1.2)
    broken = index_states(args, sch3)
    invalid = [k for k, v in broken.items() if v != "true"]
    rec_rc, rec_out, rec_dur = migrate(args.binary, args.dsn, sch3)
    wait_ready(args, sch3)
    healed = index_states(args, sch3)
    rep.add("中断（后端被杀）后留下 INVALID 索引（可复现的坏状态）", bool(invalid),
            f"CIC 进行中={caught} invalid={invalid or '无'}")
    rep.add("重跑靠 DROP INDEX CONCURRENTLY IF EXISTS 自愈成 valid",
            rec_rc == 0 and len(healed) == len(INDEXES) and all(v == "true" for v in healed.values()),
            f"重跑 rc={rec_rc} {rec_dur:.1f}s 结果={json.dumps(healed, ensure_ascii=False)}")

    # ── 5) 幂等
    rc5, out5, dur5 = migrate(args.binary, args.dsn, sch)
    rep.add("已到 0010 的库再跑一次幂等", rc5 == 0, f"rc={rc5} {dur5:.2f}s")

    # ── 6) 两实例并发迁移不死锁
    sch4 = "gate_mig_concurrent"
    build_0009(args, sch4)
    seed_rows(args, sch4, args.seed)
    a = migrate_bg(args.binary, args.dsn, sch4)
    time.sleep(0.05)
    b = migrate_bg(args.binary, args.dsn, sch4)
    out_a = a.communicate(timeout=300)[0] or ""
    out_b = b.communicate(timeout=300)[0] or ""
    wait_ready(args, sch4)
    leftover = q(args.dsn, "select count(*) from pg_locks where locktype='advisory' "
                           "and pid <> pg_backend_pid()", sch4).strip()
    deadlocked = "deadlock" in (out_a + out_b).lower()
    rep.add("两个实例并发迁移都成功且不死锁",
            a.returncode == 0 and b.returncode == 0 and not deadlocked,
            f"rc={a.returncode}/{b.returncode} deadlock={deadlocked}")
    rep.add("迁移结束后不残留 advisory 锁（单连接加锁/解锁）", leftover == "0", f"advisory 锁={leftover}")
    st4 = index_states(args, sch4)
    rep.add("并发迁移后 5 个索引 valid", len(st4) == len(INDEXES) and all(v == "true" for v in st4.values()),
            json.dumps(st4, ensure_ascii=False))

    # ── 7) 迁移器单测（切句/指令）
    pkg = str(Path(args.migrations).resolve().parent.parent.parent)  # server/
    t = subprocess.run(["go", "test", "./internal/store", "-run", "TestSplitSQLStatements|TestIsNoTxMigration",
                        "-v", "-count=1"], cwd=pkg, capture_output=True, text=True,
                       env=dict(os.environ, TEST_DATABASE_URL=args.dsn))
    passed = len([l for l in t.stdout.splitlines() if l.strip().startswith("--- PASS")])
    rep.add("迁移器单测（切句 11 例 + 指令识别）通过", t.returncode == 0 and passed >= 2,
            f"rc={t.returncode} PASS 行={passed}")

    for s in ("gate_mig_clean", "gate_mig_0009", "gate_mig_interrupt", "gate_mig_concurrent"):
        Y.psql(args.dsn, f'drop schema if exists "{s}" cascade')
    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
