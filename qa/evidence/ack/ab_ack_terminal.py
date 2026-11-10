#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""独立验收：`POST /v1/transfers/{id}/ack` 的终态判定（§1.7.4 / §5.2，PR #71）。

不采信提交人的自证：只按契约发真 HTTP、连真 PG 查 `download_count`。

断言（--expect fixed）：
  A. REVOKED  → ack 必须 `410 TRANSFER_REVOKED`，且 `download_count` 不变（不计数）
  B. EXPIRED  → ack 必须 `410 TRANSFER_EXPIRED`，且 `download_count` 不变（不计数）
  C. 阴性对照：正常（未终结）但没带 `X-YS-Download-Id` / 带了别人的租约
     → 必须仍是 `409 DOWNLOAD_NOT_STARTED`（不能把 409 全拍成 410）
  D. 幂等例外（ADR-0005）：`CONSUMED` + 同一 `download_id` 重复 ack → 200，且只计一次

判据用**状态码 + error.code + 库里计数**三件一起看；退出码 0=全过，1=有红，2=环境失败。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "qa" / "evidence" / "v5"))
import ysv5 as Y  # noqa: E402


SCHEMA = "ack_ab"


def psql(dsn: str, sql: str) -> tuple[int, str]:
    """查询必须落在服务端用的那个 schema（Y.Server 建的是 ack_ab，不是 public）。"""
    return Y.psql(dsn, sql, SCHEMA)


def ack(c, tid: str, code: str, dl: str) -> tuple[int, dict]:
    ch = c.challenge("TRANSFER_ACK")
    hdr = c.auth(code, ch)
    if dl:
        hdr["X-YS-Download-Id"] = dl
    return c.json("POST", f"/v1/transfers/{tid}/ack", {}, hdr)


def err_code(body) -> str:
    return ((body or {}).get("error") or {}).get("code", "") if isinstance(body, dict) else ""


def revoke(c, sender: str, tid: str) -> int:
    ch = c.challenge("TRANSFER_REVOKE")
    st, _ = c.json("POST", f"/v1/transfers/{tid}/revoke", None, c.auth(sender, ch))
    return st


def lease(c, tid: str) -> str:
    st, _ = c.get_prelude(tid)
    return c.headers.get("x-ys-download-id", "") if st == 200 else ""


def count(dsn: str, tid: str) -> str:
    rc, out = psql(dsn, f"select download_count from transfers where transfer_id='{tid}'")
    return out if rc == 0 else f"err:{out[:40]}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ack 终态 410 独立验收")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--work", default="/tmp/ys-ack-ab")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    if not args.dsn:
        print("[BLOCKED] 需要 --dsn 或 TEST_DATABASE_URL", file=sys.stderr)
        return 2

    work = Path(args.work)
    rows: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, ev: str) -> None:
        rows.append((name, ok, ev))
        print(f"{'PASS' if ok else 'FAIL'}  {name:<44} {ev}", flush=True)

    with Y.Server(args.binary, args.dsn, "ack_ab", work, sweep="1s") as srv:
        c = Y.Client(srv.base)
        sender, _ = c.register_pair("ack-sender", "发送方")
        recipient, _ = c.register_pair("ack-recipient", "接收方")

        cs = 262144
        # A) REVOKED：先拿租约 → 撤回 → ack
        t = Y.make_transfer(c, sender, recipient, size=cs, chunk_size=cs, chunks=1)
        dl = lease(c, t["transfer_id"])
        before = count(args.dsn, t["transfer_id"])
        rv = revoke(c, sender, t["transfer_id"])
        # 三种凭据都必须 410：有效租约 / 不带 / 伪造（§1.7.4「即使凭据不存在或已被轮换」）
        probes = []
        for label, token in (("有效", dl), ("无", ""), ("伪造", "0" * 32)):
            st, body = ack(c, t["transfer_id"], recipient, token)
            probes.append((label, st, err_code(body)))
        after = count(args.dsn, t["transfer_id"])
        add("A. REVOKED → 410 TRANSFER_REVOKED（3 种凭据）且不计数",
            rv in (200, 201)
            and all(st == 410 and code == "TRANSFER_REVOKED" for _, st, code in probes)
            and before == after,
            f"revoke={rv} " + " ".join(f"{l}={st}:{c}" for l, st, c in probes)
            + f" count={before}->{after}")

        # B) EXPIRED：拿租约 → 回拨过期 → ack
        t2 = Y.make_transfer(c, sender, recipient, size=cs, chunk_size=cs, chunks=1)
        dl2 = lease(c, t2["transfer_id"])
        before2 = count(args.dsn, t2["transfer_id"])
        rc, out = psql(args.dsn, f"update transfers set expires_at = now() - interval '2 seconds' "
                                 f"where transfer_id='{t2['transfer_id']}'")
        probes2 = []
        for label, token in (("有效", dl2), ("无", ""), ("伪造", "0" * 32)):
            st, body = ack(c, t2["transfer_id"], recipient, token)
            probes2.append((label, st, err_code(body)))
        after2 = count(args.dsn, t2["transfer_id"])
        add("B. EXPIRED → 410 TRANSFER_EXPIRED（3 种凭据）且不计数",
            rc == 0 and all(st == 410 and code == "TRANSFER_EXPIRED" for _, st, code in probes2)
            and before2 == after2,
            " ".join(f"{l}={st}:{c}" for l, st, c in probes2) + f" count={before2}->{after2}")

        # C) 阴性对照：未终结 + 无租约 / 伪租约 → 409 DOWNLOAD_NOT_STARTED
        t3 = Y.make_transfer(c, sender, recipient, size=cs, chunk_size=cs, chunks=1)
        st3a, body3a = ack(c, t3["transfer_id"], recipient, "")
        st3b, body3b = ack(c, t3["transfer_id"], recipient, "0" * 32)
        add("C. 未终结缺/伪租约 → 409 DOWNLOAD_NOT_STARTED",
            st3a == 409 and err_code(body3a) == "DOWNLOAD_NOT_STARTED"
            and st3b == 409 and err_code(body3b) == "DOWNLOAD_NOT_STARTED",
            f"无={st3a} {err_code(body3a)} 伪={st3b} {err_code(body3b)}")

        # D) 幂等例外：正常 ack → 200（CONSUMED）；同一租约再 ack → 200 且只计一次
        t4 = Y.make_transfer(c, sender, recipient, size=cs, chunk_size=cs, chunks=1)
        dl4 = lease(c, t4["transfer_id"])
        c0 = count(args.dsn, t4["transfer_id"])
        st4, _ = ack(c, t4["transfer_id"], recipient, dl4)
        c1 = count(args.dsn, t4["transfer_id"])
        st5, body5 = ack(c, t4["transfer_id"], recipient, dl4)
        c2 = count(args.dsn, t4["transfer_id"])
        add("D. CONSUMED + 同一租约重复 ack → 200 且只计一次",
            st4 == 200 and st5 == 200 and c0 == "0" and c1 == "1" and c2 == "1",
            f"first={st4} replay={st5} count={c0}->{c1}->{c2}")

    bad = [r for r in rows if not r[1]]
    print("-" * 86)
    print(f"{len(rows) - len(bad)}/{len(rows)} 通过　结论：{'PASS' if not bad else 'FAIL'}")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps({
            "at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
            "binary": args.binary,
            "rows": [{"name": n, "pass": ok, "evidence": e} for n, ok, e in rows],
            "verdict": "PASS" if not bad else "FAIL",
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
