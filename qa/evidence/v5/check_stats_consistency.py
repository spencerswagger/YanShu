#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ④·全平台统计口径验收：计数器 / HTTP / 前端展示 三处必须同一个数。

`GET /v1/stats` 的坑不在"能不能返回数字"，而在**口径**：`consumed` 只算 CONSUMED、
`consumed_bytes` 是明文大小、`created` 单独一列不与之相加、`today` 按 **UTC 日界**、
响应禁止缓存、只能给聚合数字。所以本脚本用三条独立来源对齐：

  A. `stats_counters` 计数器表（写路径累加）；
  B. `transfers` 表直接聚合（独立口径，能抓出漏加/双加/回填错）；
  C. HTTP JSON + 前端 `formatCount` / `formatBytesTotal`（展示端不改数）。

断言（每行带真数字）：
1. 空库基线全 0（不是缺字段、不是 404）；
2. 三个 `no-store` 头齐备；
3. 响应字段集精确（只有 today/total/generated_at，各 3 个键，无个例信息）；
4. 建 3 条、取走 2 条 → `created +3`、`consumed +2`、`consumed_bytes` 等于这两条的明文和；
5. 计数 ≤60s 内可见（契约允许服务端内部缓存 ≤60s），实测多久；
6. A 与 B 逐数字相等（计数器表 vs transfers 直算）；
7. `today` 按 UTC 日界（会话时区非 UTC 时这里必须红）；
8. `generated_at` 与响应头 `Date` 差 ≤5s；
9. 前端格式化能吃真数字、输出非空且量级正确；
10. 换一个客户端读同一份数字（全平台共享、无鉴权、无 cookie 差异）。

用法：
    python3 qa/evidence/v5/check_stats_consistency.py \
        --binary <yanshu-server> --dsn "$TEST_DATABASE_URL" \
        [--schema gate_v5_stats] [--web-dir <web 分支目录>] [--json-out out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

HERE = Path(__file__).resolve().parent
BUCKET_KEYS = {"consumed", "consumed_bytes", "created"}


def q(args, sql: str) -> str:
    rc, out = Y.psql(args.dsn, sql, args.schema)
    if rc != 0 or out.startswith(("ERROR", "psql:", "FATAL")):
        raise RuntimeError(f"SQL 失败（不允许当成通过）：{out[:200]}")
    return out


def triple(row: str) -> tuple[int, int, int]:
    parts = row.split("|")
    if len(parts) != 3:
        raise RuntimeError(f"期望三列，拿到 {row!r}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def render_stats(web_dir: str, payload: dict) -> dict:
    p = subprocess.run(["node", str(HERE / "render_web.mjs"), "stats",
                        f"--web-dir={web_dir}", "--json", json.dumps(payload)],
                       capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError(f"render_web stats 失败：{p.stderr.strip()[:300]}")
    return json.loads(p.stdout)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_stats")
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-work"))
    ap.add_argument("--web-dir", default="")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ④ 全平台统计 · 计数器 / HTTP / 前端展示三处同数",
                   f"schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    with Y.Server(args.binary, args.dsn, args.schema, Path(args.work), sweep="5s") as srv:
        c = Y.Client(srv.base)
        snd, _ = c.register_pair("stats-sender", "发送方")
        rcv, _ = c.register_pair("stats-receiver", "接收方")

        # 1) 空库基线
        st, base = c.stats()
        zeros = all(v == 0 for b in ("today", "total") for v in (base.get(b) or {}).values())
        rep.add("空库基线全 0", st == 200 and zeros, f"{st} {json.dumps(base, ensure_ascii=False)}")

        # 2) 三个 no-store
        h = c.headers
        hdr = {k: h.get(k) for k in ("cache-control", "cdn-cache-control", "surrogate-control")}
        rep.add("响应带三个 no-store 头",
                all((v or "").lower() == "no-store" for v in hdr.values()), json.dumps(hdr))

        # 3) 字段集精确
        keys = set(base.keys())
        bucket_ok = set((base.get("today") or {}).keys()) == BUCKET_KEYS and \
            set((base.get("total") or {}).keys()) == BUCKET_KEYS
        flat = json.dumps(base, ensure_ascii=False)
        leak = [w for w in ("transfer_id", "sender_code", "recipient_code", "nickname", "ip")
                if w in flat]
        rep.add("字段集精确（aggregate only，无个例信息）",
                keys == {"today", "total", "generated_at"} and bucket_ok and not leak,
                f"top={sorted(keys)} leak={leak or '无'}")

        # 4) 建 3 条、取走 2 条
        made, acked = [], []
        for i in range(3):
            size = (i + 1) * 1024 * 1024
            t = Y.make_transfer(c, snd, rcv, size=size, chunk_size=1024 * 1024, chunks=i + 1)
            t["size"] = size
            made.append(t)
            if i < 2:  # 前两条取走
                stp, _ = c.get_prelude(t["transfer_id"])
                dl = c.headers.get("x-ys-download-id", "")
                sta, _ = c.ack(t["transfer_id"], rcv, dl)
                if sta == 200:
                    acked.append(t)
        expect_bytes = sum(t["size"] for t in acked)
        rep.add("建 3 条 + 取走 2 条（ok 前置）", len(made) == 3 and len(acked) == 2,
                f"made={len(made)} acked={len(acked)} 明文合计={expect_bytes}B")

        # 5) ≤60s 内可见（服务端内部缓存）
        t0 = time.time()
        got = base
        while time.time() - t0 <= 70:
            st, got = c.stats()
            if (got.get("today") or {}).get("created") == 3:
                break
            time.sleep(2)
        lag = time.time() - t0
        today, total = got.get("today") or {}, got.get("total") or {}
        rep.add("建/取 计数在 ≤60s 内可见（实测延迟）",
                today.get("created") == 3 and today.get("consumed") == 2
                and today.get("consumed_bytes") == expect_bytes,
                f"延迟={lag:.1f}s today={json.dumps(today, ensure_ascii=False)} 期望 consumed_bytes={expect_bytes}")

        # 6) 计数器表 vs transfers 直算
        ctr_today = triple(q(args, "select coalesce(sum(consumed),0),coalesce(sum(consumed_bytes),0),"
                                 "coalesce(sum(created),0) from stats_counters where day = "
                                 "(now() at time zone 'utc')::date"))
        ctr_total = triple(q(args, "select coalesce(sum(consumed),0),coalesce(sum(consumed_bytes),0),"
                                 "coalesce(sum(created),0) from stats_counters"))
        src_all = triple(q(args, "select count(*) filter (where state='CONSUMED'),"
                              " coalesce(sum(plaintext_size) filter (where state='CONSUMED'),0),"
                              " count(*) from transfers"))
        src_today = triple(q(args, "select count(*) filter (where state='CONSUMED'),"
                                " coalesce(sum(plaintext_size) filter (where state='CONSUMED'),0),"
                                " count(*) from transfers where created_at >= "
                                "(now() at time zone 'utc')::date"))
        rep.add("计数器表 == transfers 直算（今日）", ctr_today == src_today,
                f"counters={ctr_today} transfers={src_today}")
        rep.add("计数器表 == transfers 直算（累计）", ctr_total == src_all,
                f"counters={ctr_total} transfers={src_all}")
        rep.add("HTTP JSON == 计数器表（今日/累计）",
                (today.get("consumed"), today.get("consumed_bytes"), today.get("created")) == ctr_today
                and (total.get("consumed"), total.get("consumed_bytes"), total.get("created")) == ctr_total,
                f"http_today=({today.get('consumed')},{today.get('consumed_bytes')},{today.get('created')}) "
                f"ctr_today={ctr_today}")

        # 7) UTC 日界：会话时区必须是 UTC，否则 `$1::date` 的日界不是 UTC 日
        tz = q(args, "select current_setting('TimeZone')").strip()
        utc_same = q(args, "select (now()::date = (now() at time zone 'utc')::date)").strip() == "t"
        rep.add("today 按 UTC 日界（服务端会话时区必须 UTC）", utc_same,
                f"TimeZone={tz} 本地日=UTC日={utc_same}")
        if not utc_same:
            rep.note("风险：实现用 `$1::date` 取日桶，会话时区非 UTC 时「今日」会错一天")

        # 8) generated_at 与 Date 头
        gen = datetime.strptime(got["generated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        date_ms = parsedate_to_datetime(c.headers.get("date", "")).timestamp()
        skew = abs(gen.timestamp() - date_ms)
        rep.add("generated_at 与 Date 头一致（≤5s）", skew <= 5,
                f"generated_at={got['generated_at']} Δ={skew:.1f}s")

        # 9) 前端格式化吃真数字
        if args.web_dir:
            shown = render_stats(args.web_dir, got)
            ok = (shown["today"]["consumed"] and shown["total"]["consumed"]
                  and shown["total"]["consumed_bytes"])
            rep.add("前端格式化真数字（非空、不塌成 0）", bool(ok),
                    json.dumps(shown, ensure_ascii=False))
        else:
            rep.add("前端格式化真数字", None, "缺 --web-dir")

        # 10) 换客户端读同一份数字（无鉴权、无 cookie 差异）
        c2 = Y.Client(srv.base)
        st2, other = c2.stats()
        rep.add("另一客户端读到同一份数字（全平台共享）", st2 == 200 and other == got,
                f"{st2} 相同={other == got}")

        # 11) 撤回（REVOKED）不计入 consumed：撤一条，计数器 consumed 必须不动
        t_rev = Y.make_transfer(c, snd, rcv, size=1024 * 1024, chunk_size=1024 * 1024, chunks=1)
        ch = c.challenge("TRANSFER_REVOKE")
        stv, bv = c.json("POST", f"/v1/transfers/{t_rev['transfer_id']}/revoke", {},
                         c.auth(snd, ch))
        ctr_after_revoke = triple(q(args, "select coalesce(sum(consumed),0),"
                                        "coalesce(sum(consumed_bytes),0),"
                                        "coalesce(sum(created),0) from stats_counters"))
        rep.add("撤回不计入 consumed（created +1、consumed 不动）",
                stv == 200 and ctr_after_revoke == (ctr_total[0], ctr_total[1], ctr_total[2] + 1),
                f"revoke={stv} {bv.get('state')} counters {ctr_total}→{ctr_after_revoke}")

    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
