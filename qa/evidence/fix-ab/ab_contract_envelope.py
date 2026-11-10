#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A/B：契约 §0.2「所有非 2xx 响应统一错误信封」在运行时是否真的执行。

被测的是**路由层没接住**的两种响应（ADR-0003）：
  - 路径不存在（`GET /v1/definitely-not-an-endpoint`）
  - 路径存在但方法不对（`GET /v1/transfers`、`DELETE /healthz`）

修前（main）：Go 的 `http.ServeMux` 自己抢答 —— `404 page not found` / `Method Not Allowed`，
**text/plain、没有 error.code、没有 request_id**。客户端按 §10 要求「按 code 分支」时拿不到
任何可分支的信号（等于 §0.2 在运行时没执行）。
修后（契约封套兜底）：同样的请求回 `404 ROUTE_NOT_FOUND` / `405 METHOD_NOT_ALLOWED` 的 JSON 信封。

对照组（修前修后都必须成立，防止「一律包信封」把真 handler 的判定吞掉）：
  - `GET /v1/transfers/not-a-transfer-id` → `404 TRANSFER_NOT_FOUND`（路径成立、对象不成立）
  - `POST /v1/challenges` 带坏 JSON → `400 BAD_REQUEST`

用法：
    python3 ab_contract_envelope.py --binary <yanshu-server> --dsn "$TEST_DATABASE_URL" \
        --expect before|after [--json-out out.json]

退出码：0 = 实测与 --expect 相符；1 = 不符；2 = 环境/前置失败（BLOCKED）。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ab_common as C  # noqa: E402

# (名字, method, path, body)
UNROUTED = [
    ("未知路径", "GET", "/v1/definitely-not-an-endpoint", None),
    ("未知路径(深层)", "GET", "/v1/transfers/abc/nope", None),
    ("方法不对(POST→GET)", "GET", "/v1/transfers", None),
    ("方法不对(GET→DELETE)", "DELETE", "/healthz", None),
]

CONTROLS = [
    ("路径成立·对象不成立", "GET", "/v1/transfers/not-a-transfer-id", None, 404, "TRANSFER_NOT_FOUND"),
    ("坏 JSON", "POST", "/v1/challenges", b"{not json", 400, "BAD_REQUEST"),
]


def probe(client: C.Client, method: str, path: str, body):
    st, hd, raw = client.call(method, path, body, {"Content-Type": "application/json"} if body else None)
    ctype = hd.get("content-type", "")
    obj = None
    try:
        import json
        obj = json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        obj = None
    return {
        "status": st,
        "content_type": ctype,
        "code": C.err_code(obj) if obj is not None else "",
        "request_id": ((obj or {}).get("error") or {}).get("request_id", "") if isinstance(obj, dict) else "",
        "allow": hd.get("allow", ""),
        "body_head": raw.decode("utf-8", "replace")[:120].replace("\n", "\\n"),
        "envelope": bool(isinstance(obj, dict) and isinstance(obj.get("error"), dict)
                         and obj["error"].get("code")),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="契约 §0.2 错误信封 · 运行时执行情况 A/B")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=None, help="默认取 TEST_DATABASE_URL")
    ap.add_argument("--expect", choices=["before", "after"], required=True)
    ap.add_argument("--schema", default="gate_ab_envelope")
    ap.add_argument("--work", default="/tmp/ab-envelope")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    dsn = C.require_dsn(args.dsn)
    work = Path(args.work)

    rows, controls, failures = [], [], []
    with C.Server(args.binary, dsn, args.schema, work) as srv:
        client = C.Client(srv.base)
        for name, method, path, body in UNROUTED:
            r = probe(client, method, path, body)
            r.update({"case": name, "method": method, "path": path})
            rows.append(r)
        for name, method, path, body, want_st, want_code in CONTROLS:
            r = probe(client, method, path, body)
            r.update({"case": name, "method": method, "path": path,
                      "want_status": want_st, "want_code": want_code})
            controls.append(r)

    print(f"== 契约 §0.2 错误信封 A/B（expect={args.expect}）@ {C.now_iso()}")
    print(f"binary = {args.binary}  sha256 = {C.sha256_file(args.binary)}")
    print("\n-- 未被路由接住的请求 --")
    for r in rows:
        print(f"  {r['status']}  {r['method']:6s} {r['path']:42s} {r['case']}")
        print(f"        content-type={r['content_type'] or '(空)'}  envelope={r['envelope']}"
              f"  code={r['code'] or '(无)'}  request_id={r['request_id'] or '(无)'}"
              + (f"  allow={r['allow']}" if r["allow"] else ""))
        print(f"        body={r['body_head']}")

    print("\n-- 对照组（必须一直是真 handler 的判定）--")
    for r in controls:
        ok = r["status"] == r["want_status"] and r["code"] == r["want_code"] and r["envelope"]
        print(f"  {'PASS' if ok else 'FAIL'}  {r['status']} {r['method']} {r['path']}"
              f" → {r['code'] or '(无 code)'}（期望 {r['want_status']} {r['want_code']}）")
        if not ok:
            failures.append(f"对照组失效：{r['case']} → {r['status']} {r['code'] or r['body_head']}")

    bad = [r for r in rows if not r["envelope"]]
    good = [r for r in rows if r["envelope"]]

    if args.expect == "before":
        verdict_ok = len(bad) > 0
        print(f"\n结论：{len(bad)}/{len(rows)} 条未被路由接住的请求**没有**错误信封"
              f"（text/plain）→ 修前问题复现{'成功' if verdict_ok else '失败'}")
        if not verdict_ok:
            failures.append("期望修前「无信封」，实测全部有信封 —— 树选错了，或修复已在基线里")
    else:
        # 只要求「状态码与 code 自洽、且是信封」：404→ROUTE_NOT_FOUND、405→METHOD_NOT_ALLOWED。
        # 具体哪条走 404 哪条走 405 由 ADR-0003 的实现决定（Go 的 ServeMux 对
        # 「路径存在但方法不符」并不总是给 405），这里不越位替实现选边。
        want_codes = {404: "ROUTE_NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
        for r in rows:
            if not r["envelope"]:
                failures.append(f"{r['method']} {r['path']} 仍无信封（{r['content_type']}）")
                continue
            want = want_codes.get(r["status"])
            if want is None:
                failures.append(f"{r['method']} {r['path']} 状态码 {r['status']} 不在预期（404/405）")
            elif r["code"] != want:
                failures.append(f"{r['method']} {r['path']} status={r['status']} 但 code={r['code']}，期望 {want}")
            elif not r["request_id"]:
                failures.append(f"{r['method']} {r['path']} 信封缺 request_id")
        verdict_ok = not failures
        print(f"\n结论：{len(good)}/{len(rows)} 条未被路由接住的请求回了错误信封"
              f"（ROUTE_NOT_FOUND / METHOD_NOT_ALLOWED）→ 修后{'达标' if verdict_ok else '未达标'}")

    for f in failures:
        print(f"  [FAIL] {f}")

    C.dump(args.json_out, {
        "kind": "contract-envelope-0.2",
        "expect": args.expect,
        "at": C.now_iso(),
        "binary": args.binary,
        "binary_sha256": C.sha256_file(args.binary),
        "unrouted": rows,
        "controls": controls,
        "failures": failures,
        "pass": verdict_ok and not failures,
    })
    return C.EXIT_PASS if (verdict_ok and not failures) else C.EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
