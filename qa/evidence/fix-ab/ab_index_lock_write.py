#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A/B：建索引期间写入会不会被挡住（普通 CREATE INDEX vs CREATE INDEX CONCURRENTLY）。

背景：v5 的迁移器把整份 .sql 包在一个事务里；`CREATE INDEX` 取 `SHARE` 锁，锁一直持到
提交 —— 建索引期间该表的**所有写入被整体挡住**（线上就是一段写不可用窗口，且随表变大
线性变长）。修法是迁移改用 `-- yanshu:no-transaction` + `CREATE INDEX CONCURRENTLY`。

这条脚本不看代码、不看提交人的自证，只在真 PG 上测两种写法对**并发写入**的实际影响：
  1. 造一张有数据的表（默认 60 万行）
  2. 起一路 writer：每条 INSERT 一次，记录单条写延迟
  3. 同时在另一条连接上执行 phaseA = `BEGIN; CREATE INDEX ...; COMMIT;`（迁移的真实写法）
  4. phaseB = `CREATE INDEX CONCURRENTLY ...`（0010 的写法）
  5. 采样 `pg_locks`，看建索引期间表上到底挂了什么锁
判定：A 出现秒级写阻塞且能看到 `ShareLock`；B 写入持续、最长阻塞在百毫秒内、只有
`ShareUpdateExclusiveLock`。

用法：
    python3 ab_index_lock_write.py --dsn "$TEST_DATABASE_URL" [--rows 600000] [--json-out out.json]
退出码：0 = 结论符合预期（A 阻塞 / B 不阻塞）；1 = 不符；2 = 环境失败。
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ab_common as C  # noqa: E402

SCHEMA = "gate_ab_index"
TABLE = "t_idx"


def run_sql(dsn: str, sql: str, timeout: float = 600) -> tuple[int, str, float]:
    t0 = time.monotonic()
    rc, out = C.psql(dsn, sql, schema=SCHEMA, timeout=timeout)
    return rc, out, time.monotonic() - t0


class Writer(threading.Thread):
    """每条 INSERT 一次（独立 psql 连接），记录单条延迟。"""

    def __init__(self, dsn: str, gap: float = 0.02):
        super().__init__(daemon=True)
        self.dsn, self.gap = dsn, gap
        self.samples: list[tuple[float, float, float]] = []  # (start, end, ms)
        self.stop_flag = threading.Event()
        self.errors: list[str] = []

    def run(self) -> None:
        i = 0
        while not self.stop_flag.is_set():
            i += 1
            t0 = time.monotonic()
            rc, out = C.psql(self.dsn, f"INSERT INTO {TABLE} (k, pad) VALUES (md5('w{i}'), 'w')",
                             schema=SCHEMA, timeout=180)
            t1 = time.monotonic()
            if rc != 0:
                self.errors.append(out[:200])
            self.samples.append((t0, t1, (t1 - t0) * 1000.0))
            self.stop_flag.wait(self.gap)


class LockSampler(threading.Thread):
    """每 50ms 采样一次表上的锁模式。"""

    def __init__(self, dsn: str):
        super().__init__(daemon=True)
        self.dsn = dsn
        self.samples: list[tuple[float, set[str]]] = []
        self.stop_flag = threading.Event()

    def run(self) -> None:
        sql = ("SELECT DISTINCT mode FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
               f"WHERE c.relname = '{TABLE}' AND c.relkind = 'r' AND l.granted")
        while not self.stop_flag.is_set():
            rc, out = C.psql(self.dsn, sql)
            modes = {m.strip() for m in out.splitlines() if m.strip()} if rc == 0 else set()
            self.samples.append((time.monotonic(), modes))
            self.stop_flag.wait(0.05)

    def modes_between(self, t0: float, t1: float) -> set[str]:
        s: set[str] = set()
        for t, modes in self.samples:
            if t0 <= t <= t1:
                s |= modes
        return s


def window_stats(samples, t0: float, t1: float) -> dict:
    """取与 [t0,t1] 有交集的写延迟。"""
    vals = [ms for (s, e, ms) in samples if e >= t0 and s <= t1]
    if not vals:
        return {"n": 0}
    vals_sorted = sorted(vals)
    return {
        "n": len(vals),
        "max_ms": round(max(vals), 1),
        "p50_ms": round(statistics.median(vals), 1),
        "p95_ms": round(vals_sorted[max(0, int(len(vals_sorted) * 0.95) - 1)], 1),
        "over_200ms": sum(1 for v in vals if v > 200),
        "over_1000ms": sum(1 for v in vals if v > 1000),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="建索引锁写 A/B（普通 vs CONCURRENTLY）")
    ap.add_argument("--dsn", default=None)
    ap.add_argument("--rows", type=int, default=600000)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    dsn = C.require_dsn(args.dsn)

    rc, out = C.psql(dsn, f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE')
    if rc != 0:
        print(f"[BLOCKED] 清 schema 失败：{out}", file=sys.stderr)
        return C.EXIT_BLOCKED
    rc, out = C.psql(dsn, f'CREATE SCHEMA "{SCHEMA}"')
    if rc != 0:
        print(f"[BLOCKED] 建 schema 失败：{out}", file=sys.stderr)
        return C.EXIT_BLOCKED

    print(f"== 建索引锁写 A/B @ {C.now_iso()}")
    t_fill = time.monotonic()
    rc, out, dur = run_sql(dsn, f"""
CREATE TABLE {TABLE} (id bigserial PRIMARY KEY, k text NOT NULL, pad text NOT NULL);
INSERT INTO {TABLE} (k, pad)
SELECT md5(i::text), repeat('x', 100) FROM generate_series(1, {args.rows}) i;
ANALYZE {TABLE};
""")
    if rc != 0:
        print(f"[BLOCKED] 造数失败：{out}", file=sys.stderr)
        return C.EXIT_BLOCKED
    rc, rows_txt = C.psql(dsn, f"SELECT count(*) FROM {TABLE}", schema=SCHEMA)
    rc2, size_txt = C.psql(dsn, f"SELECT pg_size_pretty(pg_total_relation_size('{TABLE}'))", schema=SCHEMA)
    print(f"造数：{rows_txt} 行 / {size_txt}，耗时 {dur:.1f}s")

    writer = Writer(dsn)
    sampler = LockSampler(dsn)
    writer.start()
    sampler.start()
    time.sleep(2.0)  # 基线：索引还不存在，先量一段"没被挡"的写延迟

    result = {}
    try:
        # ---- phase A：迁移的真实写法（事务 + 普通 CREATE INDEX）
        a_start = time.monotonic()
        rc, out, a_dur = run_sql(dsn, f"BEGIN; CREATE INDEX idx_plain ON {TABLE} (k); COMMIT;")
        a_end = time.monotonic()
        if rc != 0:
            print(f"[BLOCKED] phase A 失败：{out}", file=sys.stderr)
            return C.EXIT_BLOCKED
        time.sleep(1.5)

        # ---- phase B：0010 的写法（CONCURRENTLY）
        C.psql(dsn, f"DROP INDEX idx_plain", schema=SCHEMA)
        time.sleep(0.5)
        b_start = time.monotonic()
        rc, out, b_dur = run_sql(dsn, f"CREATE INDEX CONCURRENTLY idx_conc ON {TABLE} (k)")
        b_end = time.monotonic()
        if rc != 0:
            print(f"[BLOCKED] phase B 失败（残留 INVALID 索引？）：{out}", file=sys.stderr)
            return C.EXIT_BLOCKED
        time.sleep(1.0)
    finally:
        writer.stop_flag.set()
        sampler.stop_flag.set()
        writer.join(timeout=200)
        sampler.join(timeout=10)

    base = window_stats(writer.samples, 0, a_start)
    a = window_stats(writer.samples, a_start, a_end)
    b = window_stats(writer.samples, b_start, b_end)
    a_locks = sorted(sampler.modes_between(a_start, a_end))
    b_locks = sorted(sampler.modes_between(b_start, b_end))
    base_locks = sorted(sampler.modes_between(0, a_start))

    def show(name: str, st: dict, locks: list[str], dur: float) -> None:
        if st.get("n", 0) == 0:
            print(f"  {name}: 无写入样本（建索引太快或 writer 挂了）")
            return
        print(f"  {name}: 建索引 {dur * 1000:.0f} ms｜写入 n={st['n']} "
              f"max={st['max_ms']}ms p95={st['p95_ms']}ms p50={st['p50_ms']}ms "
              f">200ms:{st['over_200ms']} >1s:{st['over_1000ms']}")
        print(f"       采样到的表锁：{', '.join(locks) if locks else '(无)'}")

    print("\n[写入延迟]（同一条 writer 连接贯穿三个阶段）")
    show("基线(无索引)", base, base_locks, 0.0)
    show("A 普通CREATE INDEX", a, a_locks, a_dur)
    show("B CONCURRENTLY", b, b_locks, b_dur)

    if writer.errors:
        print(f"  writer 报错 {len(writer.errors)} 次，首条：{writer.errors[0]}")

    a_blocked = a.get("max_ms", 0) >= 300 and "ShareLock" in a_locks
    b_ok = b.get("max_ms", 99999) < 300 and "ShareLock" not in b_locks
    print(f"\n结论：A（事务+普通 CREATE INDEX）"
          f"{'写入被挡住（最长 ' + str(a.get('max_ms')) + ' ms，锁 ' + ','.join(a_locks) + '）' if a_blocked else '未复现写阻塞'}"
          f"；B（CONCURRENTLY）"
          f"{'写入持续（最长 ' + str(b.get('max_ms')) + ' ms，锁 ' + ','.join(b_locks) + '）' if b_ok else '仍被挡/异常'}"
          f" → {'A 阻塞 / B 不阻塞，结论成立' if (a_blocked and b_ok) else '结论不成立'}")

    C.dump(args.json_out, {
        "kind": "index-lock-write-ab",
        "at": C.now_iso(),
        "rows": int(rows_txt or 0),
        "table_size": size_txt,
        "phase_a": {"sql": "BEGIN; CREATE INDEX ...; COMMIT;", "duration_ms": round(a_dur * 1000, 1),
                    "locks": a_locks, **a},
        "phase_b": {"sql": "CREATE INDEX CONCURRENTLY ...", "duration_ms": round(b_dur * 1000, 1),
                    "locks": b_locks, **b},
        "baseline": {**base, "locks": base_locks},
        "writer_errors": writer.errors[:5],
        "verdict": {"a_blocked": a_blocked, "b_not_blocked": b_ok,
                    "pass": a_blocked and b_ok},
    })
    return C.EXIT_PASS if (a_blocked and b_ok) else C.EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
