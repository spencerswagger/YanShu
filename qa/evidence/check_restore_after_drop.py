#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""「回滚后向前修复」检查：库曾跑过"删 epoch"版本（列/状态表被删）→ 新版本能否恢复。

背景：曾有 `0004_drop_token_epoch.sql` 把 `transfers.upload_token_kid` 与 `token_kid_state`
一起删掉。现在的仓库不含该迁移（`0004` 改作建状态表、`0005` 做幂等恢复）。
但**已经跑过删除版的库**必须能被新版本修回来，否则回滚会把线上库搞坏。

本脚本模拟那种损坏状态，然后断言：

1. 删列 + 删状态表 + 抹掉对应迁移记账（制造"跑过删除版"的库）；
2. 插入一条历史传输行（带一个旧凭据的 SM3）；
3. 跑新版 `-migrate-only` → **列与状态表恢复**、历史行回填 `pre-kid`、`NOT NULL` 生效；
4. 再跑一次 → **幂等**（退出 0、行数不变）；
5. 起服务 → `/healthz` **200**、日志无 `sweep failed` / `does not exist`；
6. 用**旧凭据**（kid = `pre-kid`）打 `GET /v1/transfers/{id}/status` →
   期望 **401 `AUTH_TOKEN_STALE`**（不是 500，也不是 INVALID）。

用法：
    python3 qa/evidence/check_restore_after_drop.py --binary <新版 yanshu-server> \
        --dsn "<基础 DSN>" [--schema gate_restore] [--json-out out.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SECRET = "restore-probe-secret-0001"
TID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def psql(dsn: str, sql: str, schema: str | None = None) -> tuple[int, str]:
    env = dict(os.environ)
    if schema:
        env["PGOPTIONS"] = f"-c search_path={schema}"
    p = subprocess.run(["psql", "-X", "-A", "-t", dsn, "-c", sql],
                       capture_output=True, text=True, env=env)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


def sm3_hex(data: bytes) -> str:
    """用内核算 SM3（与旧凭据的哈希同源），失败时退回 sha256 仅用于造数据。"""
    drv = Path(__file__).resolve().parent / "adapters" / "wasm_pack_probe.mjs"
    wasm = Path(os.environ.get("YS_KERNEL_WASM", ""))
    if drv.is_file() and wasm.is_file():
        r = subprocess.run(["node", str(drv), "--wasm", str(wasm), "sm3", data.hex()],
                           capture_output=True, text=True)
        if r.returncode == 0 and len(r.stdout.strip()) == 64:
            return r.stdout.strip()
    return hashlib.sha256(data).hexdigest()


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--schema", default="gate_restore")
    ap.add_argument("--work", default="/tmp/ys-restore")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    sch, base = args.schema, args.dsn
    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    rows = []

    # 0) 干净 schema + 正常迁移（造出"跑过删除版"之前的基线）
    psql(base, f'drop schema if exists "{sch}" cascade')
    psql(base, f'create schema "{sch}"')
    env = dict(os.environ, YANSHU_DATABASE_URL=f"{base}&search_path={sch}")
    r = subprocess.run([args.binary, "-migrate-only"], env=env, capture_output=True, text=True, timeout=120)
    rows.append(("基线迁移", r.returncode == 0, (r.stderr or r.stdout).strip().splitlines()[-1] if (r.stderr or r.stdout).strip() else ""))

    # 1) 制造"跑过删除版"的损坏状态
    psql(base, "alter table transfers drop column if exists upload_token_kid", sch)
    psql(base, "drop table if exists token_kid_state", sch)
    psql(base, f"delete from schema_migrations where version like '%upload_token_kid%' or version like '%token_kid_state%'", sch)
    psql(base, f"delete from schema_migrations where version like '%restore%'", sch)
    rc_c, out_c = psql(base, "select count(*) from information_schema.columns "
                             f"where table_schema='{sch}' and table_name='transfers' and column_name='upload_token_kid'", sch)
    rows.append(("损坏状态：列已删", out_c.strip() == "0", f"count={out_c.strip()}"))

    # 2) 历史行（旧凭据的 SM3）
    old_token = "old-credential-from-before-rollback"
    digest = sm3_hex(old_token.encode())
    ins = (
        "insert into transfers (transfer_id, sender_code, recipient_code, plaintext_size, chunk_size,"
        " chunk_count, prelude_len, prelude_sm3, max_downloads, state, created_at, updated_at,"
        " expires_at, upload_token_sm3)"
        " values ('" + TID + "','AWQW','AWQW',1024,1024,1,112, decode(repeat('00',32),'hex'),1,'LEASED',"
        " now(), now(), now() + interval '1 day', decode('" + digest + "','hex'))"
    )
    rc, out = psql(base, ins, sch)
    rows.append(("插入历史行（旧凭据哈希）", rc == 0, out))

    # 3) 新版恢复迁移
    r = subprocess.run([args.binary, "-migrate-only"], env=env, capture_output=True, text=True, timeout=120)
    rows.append(("新版 -migrate-only（恢复）", r.returncode == 0,
                 (r.stderr or r.stdout).strip().splitlines()[-1] if (r.stderr or r.stdout).strip() else ""))
    rc, out = psql(base, "select count(*) from information_schema.columns "
                         f"where table_schema='{sch}' and table_name='transfers' and column_name='upload_token_kid'", sch)
    rows.append(("列已恢复", out.strip() == "1", f"count={out.strip()}"))
    rc, out = psql(base, "select count(*) from information_schema.tables "
                         f"where table_schema='{sch}' and table_name='token_kid_state'", sch)
    rows.append(("状态表已恢复", out.strip() == "1", f"count={out.strip()}"))
    rc, out = psql(base, f"select coalesce(upload_token_kid,'<null>') from transfers where transfer_id='{TID}'", sch)
    rows.append(("历史行回填 pre-kid", out.strip() == "pre-kid", f"value={out.strip()}"))

    # 4) 幂等：再跑一次
    before = psql(base, "select count(*) from transfers", sch)[1]
    r2 = subprocess.run([args.binary, "-migrate-only"], env=env, capture_output=True, text=True, timeout=120)
    after = psql(base, "select count(*) from transfers", sch)[1]
    rows.append(("再跑一次幂等", r2.returncode == 0 and before == after, f"rc={r2.returncode} rows {before}→{after}"))

    # 5) 起服务 + healthz
    port = free_port()
    (work / "blobs").mkdir(exist_ok=True)
    senv = dict(os.environ, YANSHU_DATABASE_URL=f"{base}&search_path={sch}",
                YANSHU_BLOB_DIR=str(work / "blobs"), YANSHU_ADDR=f"127.0.0.1:{port}",
                YANSHU_VERIFIER="stub-allow", YANSHU_TOKEN_SECRET=SECRET, YANSHU_TOKEN_EPOCH="1")
    proc = subprocess.Popen([args.binary], env=senv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    health = None
    for _ in range(80):
        if proc.poll() is not None:
            break
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as x:
                health = x.status; break
        except Exception:
            time.sleep(0.2)
    rows.append(("服务能起 + /healthz 200", health == 200, f"healthz={health}"))

    # 6) 旧凭据 → AUTH_TOKEN_STALE
    if health == 200:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/transfers/{TID}/status")
        req.add_header("X-YS-Upload-Token", old_token)
        try:
            with urllib.request.urlopen(req, timeout=10) as x:
                st, body = x.status, x.read().decode()
        except urllib.error.HTTPError as e:
            st, body = e.code, e.read().decode()
        try:
            code = (json.loads(body).get("error") or {}).get("code", "")
        except Exception:
            code = ""
        rows.append(("旧凭据 → 401 AUTH_TOKEN_STALE", st == 401 and code == "AUTH_TOKEN_STALE", f"{st} {code}"))
    proc.terminate()
    try:
        out = proc.communicate(timeout=10)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill(); out = ""
    rows.append(("启动日志无缺列报错", "does not exist" not in out and "sweep failed" not in out,
                 (out[-120:] if out else "")))

    print("=" * 88)
    print("回滚后向前修复：跑过「删 epoch」的库 → 新版本恢复")
    print("=" * 88)
    bad = 0
    for name, ok, detail in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<34} {detail[:100]}")
        if not ok:
            bad += 1
    print("-" * 88)
    print(f"{len(rows)-bad}/{len(rows)} 通过")
    print("结论：" + ("PASS —— 已删列/删表的库能被修回来，旧凭据按 STALE 被拒"
                    if bad == 0 else "FAIL —— 回滚修复路径不成立"))
    psql(base, f'drop schema if exists "{sch}" cascade')
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"ok": bad == 0, "rows": [{"name": n, "ok": o, "detail": d} for n, o, d in rows]},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
