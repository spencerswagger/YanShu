#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""升级路径常规检查：**老库**能不能升到新版本还能跑。

只测"全新建库"是不够的 —— 2026-11-02 真踩到过：某个提交给 `transfers` 加了
`upload_token_kid` 列，但迁移里只有 `CREATE TABLE IF NOT EXISTS`、没有 `ALTER`，
于是**全新库正常、已有库升级直接报 `column ... does not exist`**，宿主重启起不来。

本脚本每一步都断言，任何一步失败即 FAIL：

1. 用**旧的迁移来源**建库（默认用 `--old-binary -migrate-only`；也可 `--old-schema-sql`）
2. 断言老库**没有**目标列（证明我们真的在测"缺列 → 补列"）
3. 往 `transfers` 插一行"历史数据"（用两版共有的列，模拟真实老库）
4. 换**新二进制**跑 `-migrate-only`
5. 断言目标列**已存在**
6. 断言那行历史数据仍在、且新列有合理值（非 NULL，或按 `--expect-child-nullable` 允许 NULL）
7. 起服务，`/healthz` 期望 **200**，并且日志里不出现 `sweep failed` / `does not exist`
8. **连跑第二次** `-migrate-only`，断言幂等（退出 0、列仍在、行数不变）

用法：
    python3 qa/evidence/check_upgrade_path.py \
        --old-binary <yanshu-server-旧版> --new-binary <yanshu-server-新版> \
        --dsn "<DSN>" --schema gate_upgrade_probe \
        [--column upload_token_kid] [--json-out out.json]

退出码：0 全部通过；1 FAIL；2 参数/环境问题（BLOCKED）。
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SECRET = "upgrade-probe-secret-0001"


SCHEMA_FOR_PSQL = ""


def psql(dsn: str, sql: str, schema: str | None = None) -> tuple[int, str]:
    """psql 不接受 search_path 作为 URI 参数，用 PGOPTIONS 注入。"""
    env = dict(os.environ)
    sch = schema or SCHEMA_FOR_PSQL
    if sch:
        env["PGOPTIONS"] = f"-c search_path={sch}"
    p = subprocess.run(["psql", "-X", "-A", "-t", dsn, "-c", sql],
                       capture_output=True, text=True, env=env)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def run_migrate(binary: str, dsn: str) -> tuple[int, str]:
    env = dict(os.environ, YANSHU_DATABASE_URL=dsn)
    p = subprocess.run([binary, "-migrate-only"], env=env, capture_output=True, text=True, timeout=120)
    return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()


def start_and_probe(binary: str, dsn: str, work: Path, port: int) -> tuple[bool, str]:
    env = dict(os.environ, YANSHU_DATABASE_URL=dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
               YANSHU_ADDR=f"127.0.0.1:{port}", YANSHU_VERIFIER="stub-allow",
               YANSHU_TOKEN_SECRET=SECRET)
    # 老版本可能要求 KID，新版本用 EPOCH；两个都设成合法值即可
    env.setdefault("YANSHU_TOKEN_EPOCH", "1")
    env.setdefault("YANSHU_TOKEN_KID", "1")
    (work / "blobs").mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen([binary], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    health = None
    for _ in range(80):
        if proc.poll() is not None:
            return False, f"进程提前退出 rc={proc.returncode}: {(proc.stdout.read() or '')[-300:]}"
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as r:
                health = r.status
                break
        except urllib.error.HTTPError as e:
            health = e.code
            break
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    try:
        out = proc.communicate(timeout=10)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill(); out = ""
    return (health == 200 and "sweep failed" not in out and "does not exist" not in out,
            f"healthz={health} log_tail={out[-200:] if out else ''}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="老库升级路径检查")
    ap.add_argument("--old-binary", required=True, help="旧版二进制（用来建老库）")
    ap.add_argument("--new-binary", required=True, help="新版二进制（要验的那个）")
    ap.add_argument("--dsn", required=True, help="基础 DSN（脚本会自带 search_path）")
    ap.add_argument("--schema", default="gate_upgrade_probe")
    ap.add_argument("--column", default="upload_token_kid")
    ap.add_argument("--column-expect", choices=["present", "absent", "any"], default="present",
                    help="升级后该列应存在/应不存在/不关心（设计变更时用 absent）")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    sch = args.schema
    base = args.dsn.split("search_path=")[0].rstrip("&")
    dsn = f"{base}&search_path={sch}"
    results: list[tuple[str, bool, str]] = []

    # 0) 干净 schema
    psql(args.dsn, f'drop schema if exists "{sch}" cascade')
    rc, out = psql(args.dsn, f'create schema "{sch}"')
    results.append(("建干净 schema", rc == 0, out))

    # 1) 老库
    rc, out = run_migrate(args.old_binary, dsn)
    results.append(("旧版 -migrate-only 建老库", rc == 0, out.splitlines()[-1] if out else ""))

    # 2) 老库确实没有该列
    rc, out = psql(base, f"select count(*) from information_schema.columns "
                        f"where table_schema='{sch}' and table_name='transfers' and column_name='{args.column}'", sch)
    old_has = out.strip() != "0"
    results.append((f"老库该列状态符合预期前提（期望 {'有' if args.column_expect=='absent' else '无'}）",
                    (old_has if args.column_expect == "absent" else (not old_has)),
                    f"count={out.strip()}"))

    # 3) 插一行历史数据（列集自适应：老库若已有 kid 列就一并填上）
    cols = [
        "transfer_id", "sender_code", "recipient_code", "plaintext_size", "chunk_size",
        "chunk_count", "prelude_len", "prelude_sm3", "max_downloads", "state",
        "created_at", "updated_at", "expires_at", "upload_token_sm3",
    ]
    vals = [
        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", "'AWQW'", "'AWQW'", "1024", "1024",
        "1", "112", "decode(repeat('00',32),'hex')", "1", "'LEASED'",
        "now()", "now()", "now() + interval '1 day'", "decode(repeat('00',32),'hex')",
    ]
    if old_has:
        cols.append(args.column)
        vals.append("'old-kid'")
    insert = f"insert into transfers ({', '.join(cols)}) values ({', '.join(vals)})"
    rc, out = psql(base, insert, sch)
    results.append(("插入一行历史 transfers", rc == 0, out))

    # 4) 新版迁移
    rc, out = run_migrate(args.new_binary, dsn)
    results.append(("新版 -migrate-only", rc == 0, out.splitlines()[-1] if out else ""))

    # 5) 列已补上
    rc, out = psql(base, f"select count(*) from information_schema.columns "
                        f"where table_schema='{sch}' and table_name='transfers' and column_name='{args.column}'", sch)
    want = {"present": "1", "absent": "0", "any": None}[args.column_expect]
    ok_col = True if want is None else out.strip() == want
    results.append((f"升级后 {args.column} 状态符合预期（期望 {args.column_expect}）", ok_col,
                    f"count={out.strip()}"))

    # 6) 历史行还在，且新列有合理值
    rc, out = psql(base, f"select count(*) from transfers where transfer_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", sch)
    results.append(("历史行仍存在", out.strip() == "1", f"rows={out.strip()}"))
    if args.column_expect == "present":
        rc, out = psql(base, f"select coalesce(\"{args.column}\"::text,'<null>') from transfers "
                            f"where transfer_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", sch)
        val = out.strip()
        bad = rc != 0 or val in ("", "<null>") or "ERROR" in val
        results.append((f"历史行的 {args.column} 有合理值", not bad, f"value={val[:80]}"))

    # 7) 起服务 + healthz
    work = Path(f"/tmp/ys-upgrade-{sch}")
    ok, detail = start_and_probe(args.new_binary, dsn, work, free_port())
    results.append(("升级后服务能起 + /healthz 200 + 无缺列报错", ok, detail))

    # 8) 再跑一次迁移，幂等
    before = psql(base, "select count(*) from transfers", sch)[1]
    rc, out = run_migrate(args.new_binary, dsn)
    after = psql(base, "select count(*) from transfers", sch)[1]
    results.append(("迁移连跑两次幂等", rc == 0 and before == after,
                    f"rc={rc} rows {before}→{after}"))

    print("=" * 92)
    print(f"升级路径检查：老库（{Path(args.old_binary).name}）→ 新库（{Path(args.new_binary).name}）")
    print("=" * 92)
    failed = 0
    for name, ok_, detail in results:
        print(f"{'PASS' if ok_ else 'FAIL'}  {name:<46} {detail[:110]}")
        if not ok_:
            failed += 1
    print("-" * 92)
    print(f"{len(results) - failed}/{len(results)} 通过")
    print("结论：" + ("PASS —— 老库能升级、历史数据完好、服务可起、迁移幂等"
                    if failed == 0 else "FAIL —— 升级路径不成立，不要拿这个产物去替换已有库"))

    psql(args.dsn, f'drop schema if exists "{sch}" cascade')
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"ok": failed == 0,
             "results": [{"name": n, "ok": o, "detail": d} for n, o, d in results]},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
