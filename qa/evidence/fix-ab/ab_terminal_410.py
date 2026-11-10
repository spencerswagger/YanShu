#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A/B：契约 §1.7.4「终结态 410 先于凭据 401」在运行时是否真的执行。

契约原文（docs/API.md §1.7.4，写死）：
  判定顺序 = 先判资源终结态（REVOKED/EXPIRED/CONSUMED → 410），资源未终结才走凭据校验；
  终结态下**不返回任何 401**（"即使凭据同时不存在 / 已被轮换 / 已超期"）。

实测矩阵（2 终态 × 4 条上传路径 × 3 种凭据 = 24 例）：
  终态   CONSUMED（complete 之后）、REVOKED（撤回之后）
  路径   GET status / PUT prelude / PUT chunks/0 / POST complete
  凭据   不带 / 伪造（形状合法但值不对）/ 真实 upload_token

修前（main）：终结态判断只落了 TTL 一条，于是
  不带凭据 → 401 AUTH_MISSING；伪造 → 401 AUTH_TOKEN_INVALID；真实 → 409 TRANSFER_STATE_CONFLICT
—— 客户端会按 §1.7.5 去"重签凭据"，重签完还是 410，白跑一轮。
修后：24/24 全是 410 + 对应终态码。

阴性对照（修前修后都必须成立，防止「一律 410」把真该 401 的场景吞掉）：
  未终结传输 + 不带凭据 → 401 AUTH_MISSING；+ 伪造凭据 → 401 AUTH_TOKEN_INVALID。

用法：
    python3 ab_terminal_410.py --binary <yanshu-server> --expect before|after [--dsn ...] [--json-out ...]
退出码：0 = 与 --expect 相符；1 = 不符；2 = 环境/前置失败。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ab_common as C  # noqa: E402

PRELUDE = bytes(range(256)) * 2  # 512 B，内容不重要（服务端不解析）
CHUNK = b"\xa5" * (1024 + 16)  # 块切片 = 明文块 + 16 B GCM tag
PATHS = ["status", "prelude", "chunk", "complete"]
CREDS = ["none", "bogus", "valid"]
TERMINAL_CODE = {"CONSUMED": "TRANSFER_CONSUMED", "REVOKED": "TRANSFER_REVOKED"}


def do_probe(c: C.Client, tid: str, token: str, path: str, cred: str) -> dict:
    hdr = {}
    if cred == "bogus":
        hdr["X-YS-Upload-Token"] = C.b64u(os.urandom(32))  # 形状合法、值不对
    elif cred == "valid":
        hdr["X-YS-Upload-Token"] = token

    if path == "status":
        st, _, body = c.json("GET", f"/v1/transfers/{tid}/status", None, hdr)
    elif path == "prelude":
        hdr["Content-Type"] = "application/octet-stream"
        st, _, raw = c.call("PUT", f"/v1/transfers/{tid}/prelude", PRELUDE, hdr)
        body = _maybe_json(raw)
    elif path == "chunk":
        hdr["Content-Type"] = "application/octet-stream"
        st, _, raw = c.call("PUT", f"/v1/transfers/{tid}/chunks/0", CHUNK, hdr)
        body = _maybe_json(raw)
    else:
        st, _, body = c.json("POST", f"/v1/transfers/{tid}/complete", {}, hdr)
    return {"path": path, "cred": cred, "status": st, "code": C.err_code(body)}


def _maybe_json(raw: bytes):
    import json
    try:
        return json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001
        return {"_raw": raw[:120].decode("utf-8", "replace")}


def make_consumed(c: C.Client, sender: str, recipient: str) -> tuple[str, str]:
    rep = c.create(sender, recipient, len(PRELUDE), 2048, 1024, 2, C.b64u(C.sm3(PRELUDE)))
    tid, token = rep["transfer_id"], rep["upload_token"]
    for name, st, body in [
        ("prelude", *c.put_prelude(tid, token, PRELUDE)),
        ("chunk0", *c.put_chunk(tid, token, 0, CHUNK)),
        ("chunk1", *c.put_chunk(tid, token, 1, CHUNK)),
        ("complete", *c.complete(tid, token)),
    ]:
        if not (200 <= st < 300):
            raise RuntimeError(f"造 READY 失败于 {name}: {st} {body}")

    # complete 只到 READY；CONSUMED 要真的取一次（租约）+ ack。
    st, hd, raw = c.call("GET", f"/v1/transfers/{tid}/prelude")
    dl = hd.get("x-ys-download-id", "")
    if st != 200 or not dl:
        raise RuntimeError(f"取 prelude 失败: {st} dl={dl!r} {raw[:120]}")
    for i in (0, 1):
        st, _, raw = c.call("GET", f"/v1/transfers/{tid}/chunks/{i}",
                            headers={"X-YS-Download-Id": dl})
        if st != 200:
            raise RuntimeError(f"取块 {i} 失败: {st} {raw[:120]}")
    ch = c.challenge("TRANSFER_ACK")
    hdr = c.auth(recipient, ch)
    hdr["X-YS-Download-Id"] = dl
    st, _, body = c.json("POST", f"/v1/transfers/{tid}/ack", {}, hdr)
    if not (200 <= st < 300):
        raise RuntimeError(f"ack 失败: {st} {body}")
    return tid, token


def make_revoked(c: C.Client, sender: str, recipient: str) -> tuple[str, str]:
    rep = c.create(sender, recipient, len(PRELUDE), 2048, 1024, 2, C.b64u(C.sm3(PRELUDE)))
    tid, token = rep["transfer_id"], rep["upload_token"]
    st, body = c.revoke(sender, tid)
    if not (200 <= st < 300):
        raise RuntimeError(f"撤回失败: {st} {body}")
    return tid, token


def make_fresh(c: C.Client, sender: str, recipient: str) -> tuple[str, str]:
    rep = c.create(sender, recipient, len(PRELUDE), 2048, 1024, 2, C.b64u(C.sm3(PRELUDE)))
    return rep["transfer_id"], rep["upload_token"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="契约 §1.7.4 终结态 410 先于凭据 401 · A/B")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=None)
    ap.add_argument("--expect", choices=["before", "after"], required=True)
    ap.add_argument("--schema", default="gate_ab_terminal")
    ap.add_argument("--work", default="/tmp/ab-terminal")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    dsn = C.require_dsn(args.dsn)
    work = Path(args.work)
    terminal, negative, failures = [], [], []

    with C.Server(args.binary, dsn, args.schema, work) as srv:
        c = C.Client(srv.base)
        sender, _ = c.register("sender-410", "sender")
        recipient, _ = c.register("recipient-410", "recipient")

        cases = {
            "CONSUMED": make_consumed(c, sender, recipient),
            "REVOKED": make_revoked(c, sender, recipient),
        }
        for state, (tid, token) in cases.items():
            for path in PATHS:
                for cred in CREDS:
                    r = do_probe(c, tid, token, path, cred)
                    r["state"] = state
                    terminal.append(r)

        fresh_tid, fresh_token = make_fresh(c, sender, recipient)
        for cred in ("none", "bogus"):
            r = do_probe(c, fresh_tid, fresh_token, "prelude", cred)
            r["want"] = "AUTH_MISSING" if cred == "none" else "AUTH_TOKEN_INVALID"
            negative.append(r)

    print(f"== 契约 §1.7.4 终结态 410 先于凭据 401（expect={args.expect}）@ {C.now_iso()}")
    print(f"binary = {args.binary}  sha256 = {C.sha256_file(args.binary)}")
    print("\n[矩阵] 终态 × 路径 × 凭据")
    for r in terminal:
        ok = r["status"] == 410 and r["code"] == TERMINAL_CODE[r["state"]]
        mark = "410✓" if ok else "----"
        print(f"  {mark}  {r['state']:8s} {r['path']:8s} cred={r['cred']:5s}"
              f" → {r['status']} {r['code'] or '(无)'}")

    print("\n[阴性对照] 未终结传输必须仍是 401（不能被 410 吞掉）")
    for r in negative:
        ok = r["status"] == 401 and r["code"] == r["want"]
        print(f"  {'PASS' if ok else 'FAIL'}  {r['path']:8s} cred={r['cred']:5s}"
              f" → {r['status']} {r['code'] or '(无)'}（期望 401 {r['want']}）")
        if not ok:
            failures.append(f"阴性对照失效：cred={r['cred']} → {r['status']} {r['code']}")

    got_410 = [r for r in terminal if r["status"] == 410 and r["code"] == TERMINAL_CODE[r["state"]]]
    if args.expect == "before":
        verdict_ok = len(got_410) < len(terminal)
        print(f"\n结论：24 例中 {len(got_410)} 例回了 410 —— 终结态判定"
              f"{'存在缺口（修前问题复现）' if verdict_ok else '已全覆盖（树选错了？）'}")
        if not verdict_ok:
            failures.append("期望修前「有缺口」，实测 24/24 已合规 —— 树选错了")
    else:
        for r in terminal:
            if r["status"] != 410:
                failures.append(f"{r['state']} {r['path']} cred={r['cred']} → {r['status']} {r['code']}，期望 410")
            elif r["code"] != TERMINAL_CODE[r["state"]]:
                failures.append(f"{r['state']} {r['path']} → 410 {r['code']}，期望 {TERMINAL_CODE[r['state']]}")
        verdict_ok = len(got_410) == len(terminal)
        print(f"\n结论：24 例中 {len(got_410)} 例为 410 + 对应终态码 → 修后{'达标' if verdict_ok else '未达标'}")

    for f in failures:
        print(f"  [FAIL] {f}")

    C.dump(args.json_out, {
        "kind": "contract-1.7.4-terminal-before-credential",
        "expect": args.expect,
        "at": C.now_iso(),
        "binary": args.binary,
        "binary_sha256": C.sha256_file(args.binary),
        "terminal_matrix": terminal,
        "negative_control": negative,
        "failures": failures,
        "pass": not failures,
    })
    return C.EXIT_PASS if not failures else C.EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
