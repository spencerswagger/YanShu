#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ①·TTL 可见性验收：服务端给的是**权威到期时刻**，前端能把它变成准确文案。

验什么（每行一条，PASS/FAIL 都带真数字）：

1. `/v1/config` 暴露 `max_ttl_seconds`（前端要知道上限）；
2. 建传输 `ttl_seconds=82800` → `expires_at − created_at == 82800s`（服务端算的，不是客户端猜的）；
3. 用**响应头 `Date`**（前端同步服务端时间的依据）算剩余 → `formatTtl` 得 `23 小时后过期`；
4. `GET /v1/inbox` 的每一行都带 `expires_at`（TTL 胶囊的数据源）；
5. TTL 下限夹取：`ttl_seconds=60` → 3600；
6. TTL 上限夹取：`ttl_seconds=999999` → 86400；
7. 「42 分钟」中间态：把真实行的 `expires_at` 前移（契约 TTL 只能 1–24 h，构造不出 42 min；
   但"服务端给 42 分钟后到期"这件事本身必须被正确显示）→ 文案 `42 分钟后过期` + 警示态；
8. TTL 到期 → 清道夫把状态打到 `EXPIRED`（`terminal_reason=EXPIRED`）；
9. 到期后取件 → `410 TRANSFER_EXPIRED`（看得见 + 拿不走）；
10. 到期后密文物理删除（blob 目录里 prelude 不在了）；
11. 同一时刻的过期文案 → `已过期，无法取回`。

用法：
    python3 qa/evidence/v5/check_ttl_visible.py \
        --binary <yanshu-server> --dsn "$TEST_DATABASE_URL" [--schema gate_v5_ttl] \
        [--web-dir <web 分支目录>] [--json-out out.json]

退出码：0 PASS / 1 FAIL / 3 INCONCLUSIVE（有项没跑）/ 4 PENDING（缺参数）。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

HERE = Path(__file__).resolve().parent


def http_date_ms(headers: dict[str, str]) -> int | None:
    raw = headers.get("date")
    if not raw:
        return None
    try:
        return int(parsedate_to_datetime(raw).timestamp() * 1000)
    except Exception:  # noqa: BLE001
        return None


def iso_ms(s: str) -> int:
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


def render_ttl(web_dir: str, items: list[dict]) -> list[dict]:
    out = subprocess.run(["node", str(HERE / "render_web.mjs"), "ttl",
                          f"--web-dir={web_dir}", "--json", json.dumps(items)],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"render_web ttl 失败：{out.stderr.strip()[:300]}")
    return json.loads(out.stdout)["items"]


def wait_state(c: Y.Client, tid: str, want: str, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        st, last = c.transfer(tid)
        if st == 200 and last.get("state") == want:
            return last
        time.sleep(0.25)
    return last


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_ttl")
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-work"))
    ap.add_argument("--web-dir", default="")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ① TTL 可见性 · TTL 到期与可见（真服务 + 真库 + 前端格式化模块）",
                   f"schema={args.schema}　binary={Path(args.binary).name}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)
    if not args.web_dir:
        rep.note("未给 --web-dir：文案相关的项记为 SKIP（不计入通过）")

    with Y.Server(args.binary, args.dsn, args.schema, Path(args.work), sweep="1s") as srv:
        c = Y.Client(srv.base)
        snd, _ = c.register_pair("ttl-sender", "发送方")
        rcv, _ = c.register_pair("ttl-recipient", "接收方")

        # 1) 配置上限
        st, cfg = c.config()
        rep.add("/v1/config 给出 max_ttl_seconds",
                bool(st == 200 and cfg.get("max_ttl_seconds")),
                f"max_ttl_seconds={cfg.get('max_ttl_seconds')}")

        # 2) 23 小时传输：expires_at − created_at 必须 = TTL
        t23 = Y.make_transfer(c, snd, rcv, size=64 * 1024, ttl_seconds=82800)
        created = t23["created"]
        delta = iso_ms(created["expires_at"]) - iso_ms(created["created_at"])
        rep.add("建传输 ttl=82800 → expires_at−created_at=82800s",
                abs(delta - 82800_000) <= 1000,
                f"created_at={created['created_at']} expires_at={created['expires_at']} Δ={delta/1000:.0f}s")

        # 3) 用响应头 Date 当"现在"（前端时钟基准），跑真前端格式化
        st, meta23 = c.transfer(t23["transfer_id"])
        now_ms = http_date_ms(c.headers)
        if args.web_dir and now_ms:
            got = render_ttl(args.web_dir, [{"expiresAt": meta23["expires_at"], "now": now_ms,
                                             "label": "23h"}])[0]
            rep.add("前端 formatTtl(真实 expires_at, 服务端 Date) → 23 小时后过期",
                    got["text"] == "23 小时后过期",
                    f"text={got['text']!r} remaining={got['remainingMs']/3600000:.2f}h soon={got['soon']}")
        else:
            rep.add("前端 formatTtl → 23 小时后过期", None, "缺 --web-dir 或响应无 Date 头")

        # 4) 收件列表带 expires_at（TTL 胶囊的数据源）
        st, ib = c.inbox(rcv)
        rows = ib.get("transfers") or ib.get("items") or []
        hit = next((r for r in rows if r.get("transfer_id") == t23["transfer_id"]), None)
        rep.add("GET /v1/inbox 每行带 expires_at", st == 200 and hit is not None
                and bool(hit.get("expires_at")),
                f"rows={len(rows)} 该行 expires_at={hit.get('expires_at') if hit else None}")

        # 5/6) TTL 上下限夹取
        tmin = Y.make_transfer(c, snd, rcv, size=64 * 1024, ttl_seconds=60, upload=False)
        dmin = iso_ms(tmin["created"]["expires_at"]) - iso_ms(tmin["created"]["created_at"])
        rep.add("ttl=60 被夹到下限 3600s", abs(dmin - 3600_000) <= 1000, f"Δ={dmin/1000:.0f}s")

        tmax = Y.make_transfer(c, snd, rcv, size=64 * 1024, ttl_seconds=999999, upload=False)
        dmax = iso_ms(tmax["created"]["expires_at"]) - iso_ms(tmax["created"]["created_at"])
        rep.add("ttl=999999 被夹到上限 86400s", abs(dmax - 86400_000) <= 1000, f"Δ={dmax/1000:.0f}s")

        # 7) 42 分钟中间态：契约夹取后只能 1–24h，用真行改 expires_at 造"服务端说还有 42 分钟"
        rc, _ = Y.psql(args.dsn, "update transfers set expires_at = now() + interval '42 minutes' "
                                 f"where transfer_id = '{t23['transfer_id']}'", args.schema)
        st, meta42 = c.transfer(t23["transfer_id"])
        now_ms = http_date_ms(c.headers)
        if args.web_dir and now_ms:
            got42 = render_ttl(args.web_dir, [{"expiresAt": meta42["expires_at"], "now": now_ms,
                                               "label": "42m"}])[0]
            rep.add("42 分钟态 → 文案「42 分钟后过期」+ 警示态",
                    got42["text"] == "42 分钟后过期" and got42["soon"] is True,
                    f"text={got42['text']!r} remaining={got42['remainingMs']/60000:.1f}min soon={got42['soon']}")
        else:
            rep.add("42 分钟态文案", None, "缺 --web-dir")

        # 8) 到期：把真实行推到过去，等清道夫（sweep=1s）
        Y.psql(args.dsn, "update transfers set expires_at = now() - interval '2 seconds' "
                         f"where transfer_id = '{tmin['transfer_id']}'", args.schema)
        expired = wait_state(c, tmin["transfer_id"], "EXPIRED")
        rep.add("TTL 到期 → state=EXPIRED / terminal_reason=EXPIRED",
                expired.get("state") == "EXPIRED" and expired.get("terminal_reason") == "EXPIRED",
                f"state={expired.get('state')} reason={expired.get('terminal_reason')}")

        # 9) 到期后取件必须 410
        st, body = c.get_prelude(tmin["transfer_id"])
        code = (body.get("error") or {}).get("code") if isinstance(body, dict) else ""
        if st == 410 and not code:
            st, body = c.call("GET", f"/v1/transfers/{tmin['transfer_id']}/chunks/0")
            code = (body.get("error") or {}).get("code") if isinstance(body, dict) else ""
        rep.add("到期后 GET prelude → 410 TRANSFER_EXPIRED",
                st == 410 and code == "TRANSFER_EXPIRED", f"{st} {code}")

        # 10) 密文物理删除
        tid = tmin["transfer_id"]
        prelude_path = srv.blob_dir() / tid[:2] / tid / "prelude"
        left = list((srv.blob_dir() / tid[:2] / tid).rglob("*")) if prelude_path.parent.is_dir() else []
        rep.add("到期后密文物理删除（blob 无残留）", not prelude_path.exists(),
                f"prelude_exists={prelude_path.exists()} 残留文件={len(left)}")

        # 11) 过期文案
        st, meta_exp = c.transfer(tid)
        now_ms = http_date_ms(c.headers)
        if args.web_dir and now_ms:
            gotexp = render_ttl(args.web_dir, [{"expiresAt": meta_exp["expires_at"], "now": now_ms,
                                                "label": "expired"}])[0]
            rep.add("过期态 → 文案「已过期，无法取回」",
                    gotexp["text"] == "已过期，无法取回" and gotexp["expired"] is True,
                    f"text={gotexp['text']!r} expired={gotexp['expired']}")
        else:
            rep.add("过期态文案", None, "缺 --web-dir")

        # 12) 前端时钟基准：/v1/config 的 server_time（#49 起）
        stc, cfg2 = c.config()
        if "server_time" in cfg2:
            now2 = http_date_ms(c.headers)
            delta_cfg = abs(iso_ms(cfg2["server_time"]) - now2) / 1000 if now2 else 999
            rep.add("/v1/config 带 server_time（前端时钟基准）", delta_cfg <= 2,
                    f"server_time={cfg2['server_time']} 与 Date 差={delta_cfg:.0f}s")
        else:
            rep.add("/v1/config 带 server_time（前端时钟基准）", None,
                    "该分支的 config 无 server_time（#49 才有）")

        # 13) 上传中也能看到剩余有效期：/status 带 expires_at（#49 起）
        ts = Y.make_transfer(c, snd, rcv, size=64 * 1024, ttl_seconds=3600, upload=False)
        sts, st_body = c.json("GET", f"/v1/transfers/{ts['transfer_id']}/status", None,
                              {"X-YS-Upload-Token": ts["upload_token"]})
        if sts == 200 and "expires_at" in st_body:
            rep.add("/status 带 expires_at（发送方上传中可见）",
                    iso_ms(st_body["expires_at"]) == iso_ms(ts["created"]["expires_at"]),
                    f"status.expires_at={st_body['expires_at']}")
        else:
            rep.add("/status 带 expires_at（发送方上传中可见）", None,
                    f"/status 无该字段（{sts}；#49 才有）")

    # 14) TTL 到点在读写路径即时生效：清道夫拉到 600s，仍然必须立刻 410
    sch2 = args.schema + "_nosweep"
    with Y.Server(args.binary, args.dsn, sch2, Path(args.work + "-nosweep"), sweep="600s") as srv2:
        c2 = Y.Client(srv2.base)
        s2, _ = c2.register_pair("ttl-nosweep-sender", "发送方")
        r2, _ = c2.register_pair("ttl-nosweep-recipient", "接收方")
        t = Y.make_transfer(c2, s2, r2, size=64 * 1024, ttl_seconds=3600)
        Y.psql(args.dsn, "update transfers set expires_at = now() - interval '1 second' "
                         f"where transfer_id = '{t['transfer_id']}'", sch2)
        stq, meta2 = c2.transfer(t["transfer_id"])
        stp, body2 = c2.get_prelude(t["transfer_id"])
        code2 = (body2.get("error") or {}).get("code") if isinstance(body2, dict) else ""
        rep.add("TTL 到点即时生效（清道夫 600s 也不等它）",
                stq == 200 and meta2.get("state") == "EXPIRED" and stp == 410
                and code2 == "TRANSFER_EXPIRED",
                f"GET={stq} state={meta2.get('state')} 取件={stp} {code2}（sweep=600s）")

    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
