#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真实回滚场景：**用跑过 `0004_drop_token_epoch` 的旧二进制建库**，再用新版本恢复。

与 `check_restore_after_drop.py` 的区别：那个是"手工把列删掉"模拟；这个走**真实迁移路径**——
旧二进制（`5605907` 线，含 `0004_drop_token_epoch.sql`）会把 `upload_token_kid` 列与
`token_kid_state` 删掉，然后新版本必须把它们修回来。

断言：

1. 旧二进制迁移后**列确实不存在**（证明真的跑过删除版）；
2. 插一条历史传输行（带旧凭据 SM3）；
3. 新版本 `-migrate-only` → **列与状态表恢复**、历史行仍在、新列回填 `pre-kid`；
4. **连跑第二次**迁移 → 幂等（退出 0、行数不变）；
5. 起服务 → `/healthz` 200；
6. 旧凭据 → **401 `AUTH_TOKEN_STALE`**（恢复不能复活旧凭据）。

用法：
    python3 qa/evidence/check_restore_from_real_drop.py \
        --old-binary <5605907 编的> --new-binary <回滚后新版> --dsn "<基础 DSN>"
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

TID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
SECRET = "restore-real-probe-secret-01"
OLD_TOKEN = "credential-issued-before-rollback"


def psql(dsn: str, sql: str, schema: str | None = None) -> tuple[int, str]:
    env = dict(os.environ)
    if schema:
        env["PGOPTIONS"] = f"-c search_path={schema}"
    p = subprocess.run(["psql", "-X", "-A", "-t", dsn, "-c", sql], capture_output=True, text=True, env=env)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


def sm3_hex(data: bytes) -> str:
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


def migrate(binary: str, dsn: str) -> tuple[int, str]:
    env = dict(os.environ, YANSHU_DATABASE_URL=dsn)
    r = subprocess.run([binary, "-migrate-only"], env=env, capture_output=True, text=True, timeout=120)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    return r.returncode, out.splitlines()[-1] if out else ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-binary", required=True, help="含 0004_drop_token_epoch 的旧版（如 5605907）")
    ap.add_argument("--new-binary", required=True, help="回滚后版本（应含 0005 恢复）")
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--schema", default="gate_real_restore")
    ap.add_argument("--work", default="/tmp/ys-real-restore")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    sch, base = args.schema, args.dsn
    dsn = f"{base}&search_path={sch}"
    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    (work / "blobs").mkdir(exist_ok=True)
    rows = []

    psql(base, f'drop schema if exists "{sch}" cascade')
    psql(base, f'create schema "{sch}"')

    # 1) 旧二进制建库（会执行 0004 drop）
    rc, out = migrate(args.old_binary, dsn)
    rows.append(("旧版迁移（含 drop 迁移）", rc == 0, out))
    _, cnt = psql(base, "select count(*) from information_schema.columns "
                        f"where table_schema='{sch}' and table_name='transfers' and column_name='upload_token_kid'", sch)
    rows.append(("列确实被删（前提成立）", cnt.strip() == "0", f"count={cnt.strip()}"))
    _, orphan = psql(base, "select count(*) from information_schema.tables "
                           f"where table_schema='{sch}' and table_name='token_kid_state'", sch)
    rows.append(("状态表确实不存在（前提成立）", orphan.strip() == "0", f"count={orphan.strip()}"))

    # 2) 历史行
    digest = sm3_hex(OLD_TOKEN.encode())
    ins = ("insert into transfers (transfer_id, sender_code, recipient_code, plaintext_size, chunk_size,"
           " chunk_count, prelude_len, prelude_sm3, max_downloads, state, created_at, updated_at,"
           " expires_at, upload_token_sm3) values "
           f"('{TID}','AWQW','AWQW',1024,1024,1,112, decode(repeat('00',32),'hex'),1,'LEASED',"
           f" now(), now(), now() + interval '1 day', decode('{digest}','hex'))")
    rc, out = psql(base, ins, sch)
    rows.append(("插入历史传输行（旧凭据哈希）", rc == 0, out))

    # 3) 新版恢复
    rc, out = migrate(args.new_binary, dsn)
    rows.append(("新版 -migrate-only（恢复）", rc == 0, out))
    _, cnt = psql(base, "select count(*) from information_schema.columns "
                        f"where table_schema='{sch}' and table_name='transfers' and column_name='upload_token_kid'", sch)
    rows.append(("epoch 列已恢复", cnt.strip() == "1", f"count={cnt.strip()}"))
    _, cnt = psql(base, "select count(*) from information_schema.tables "
                        f"where table_schema='{sch}' and table_name='token_kid_state'", sch)
    rows.append(("状态表已恢复", cnt.strip() == "1", f"count={cnt.strip()}"))
    _, val = psql(base, f"select coalesce(upload_token_kid,'<null>') from transfers where transfer_id='{TID}'", sch)
    rows.append(("历史行仍在且有默认值", val.strip() not in ("", "<null>"), f"value={val.strip()}"))

    # 4) 连跑第二次
    before = psql(base, "select count(*) from transfers", sch)[1]
    rc, out = migrate(args.new_binary, dsn)
    after = psql(base, "select count(*) from transfers", sch)[1]
    rows.append(("连跑第二次幂等", rc == 0 and before == after, f"rc={rc} rows {before}→{after}"))

    # 5) 起服务 + 6) 旧凭据
    port = free_port()
    senv = dict(os.environ, YANSHU_DATABASE_URL=dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
                YANSHU_ADDR=f"127.0.0.1:{port}", YANSHU_VERIFIER="stub-allow",
                YANSHU_TOKEN_SECRET=SECRET, YANSHU_TOKEN_EPOCH="1")
    proc = subprocess.Popen([args.new_binary], env=senv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
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

    if health == 200:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/transfers/{TID}/status")
        req.add_header("X-YS-Upload-Token", OLD_TOKEN)
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
        log = proc.communicate(timeout=10)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill(); log = ""
    rows.append(("启动日志无缺列报错", "does not exist" not in log and "sweep failed" not in log, (log[-100:] if log else "")))

    print("=" * 90)
    print("真实回滚场景：旧二进制（含 0004 drop）建库 → 新版本恢复")
    print("=" * 90)
    bad = 0
    for name, ok, detail in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<32} {detail[:96]}")
        if not ok:
            bad += 1
    print("-" * 90)
    print(f"{len(rows)-bad}/{len(rows)} 通过")
    print("结论：" + ("PASS —— 跑过 drop 迁移的库能被恢复，旧凭据按 STALE 被拒"
                    if bad == 0 else "FAIL —— 真实回滚恢复路径不成立"))
    psql(base, f'drop schema if exists "{sch}" cascade')
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"ok": bad == 0, "rows": [{"name": n, "ok": o, "detail": d} for n, o, d in rows]},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
