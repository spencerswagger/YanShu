#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ③·元数据永久保留验收：文件没了，记录还在；30 天后只脱敏三个字段。

v4 的行为是「终结 7 天后物理删墓碑」，v5 改成**永久保留 + 30 天后脱敏**
（`docs/API.md` §5.2）。这条最容易被写成"删了也没人发现"，所以必须真跑：

1. 取件完成（`ack` → `CONSUMED`）后密文物理删除（blob 目录空）；
2. 记录还在，`uploader_ip` 等敏感列**有值**（刚终结，未到 30 天）；
3. 把 `terminal_at` 推到 10 天前 → 跑清道夫 → **行仍在**（v4 会在这里删掉）；
4. 推到 40 天前 → 跑清道夫 → `uploader_ip` / `prelude_sm3` / `upload_token_sm3` 三列变 NULL；
5. 其余字段（大小/块数/状态/终结原因/时间/下载次数）**逐字段不变**；
6. `GET /v1/transfers/{id}` → 200 tombstone，字段集与契约一致（无 `prelude_sm3`、无 `lease_expires_at`）；
7. 保留 ≠ 可取件：`GET prelude` / `GET chunks/0` 一律 410 `TRANSFER_CONSUMED`；
8. 幂等：再跑清道夫 3 轮，行数不变、无报错。

用法：
    python3 qa/evidence/v5/check_metadata_permanent.py \
        --binary <yanshu-server> --dsn "$TEST_DATABASE_URL" [--schema gate_v5_meta] [--json-out out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

TOMBSTONE_FIELDS = [
    "transfer_id", "sender_code", "sender_nickname", "recipient_code",
    "plaintext_size", "chunk_size", "chunk_count", "prelude_len",
    "total_ciphertext_bytes", "download_count", "max_downloads",
    "created_at", "expires_at", "state", "terminal_reason", "terminal_at",
]
SENSITIVE = ["uploader_ip", "prelude_sm3", "upload_token_sm3"]
KEEP = ["plaintext_size", "chunk_size", "chunk_count", "state", "terminal_reason",
        "created_at", "expires_at", "download_count", "max_downloads"]


def q(args, sql: str) -> str:
    rc, out = Y.psql(args.dsn, sql, args.schema)
    if rc != 0 or out.startswith(("ERROR", "psql:", "FATAL")):
        raise RuntimeError(f"SQL 失败（不允许当成通过）：{out[:200]}")
    return out


def row_count(args) -> str:
    return q(args, "select count(*) from transfers")


def wait_until(fn, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.3)
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_meta")
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-work"))
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ③ 元数据永久保留 · 密文删干净、记录留得住、30 天只脱敏三列",
                   f"schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)

    with Y.Server(args.binary, args.dsn, args.schema, Path(args.work), sweep="1s") as srv:
        c = Y.Client(srv.base)
        snd, _ = c.register_pair("meta-sender", "发送方")
        rcv, _ = c.register_pair("meta-recipient", "接收方")

        t = Y.make_transfer(c, snd, rcv, size=2 * 1024 * 1024, chunk_size=1024 * 1024, chunks=2)
        tid = t["transfer_id"]

        # 取件：prelude → 块 → ack
        st, prelude = c.get_prelude(tid)
        dl = c.headers.get("x-ys-download-id", "")
        chunk_ok = True
        for i in range(2):
            stc, data = c.get_chunk(tid, i, dl)
            chunk_ok = chunk_ok and stc == 200 and data == t["chunks"][i]
        st, ack = c.ack(tid, rcv, dl)
        rep.add("取件完成 → CONSUMED", st == 200 and ack.get("state") == "CONSUMED",
                f"{st} state={ack.get('state')} 块逐字节一致={chunk_ok}")

        # 1) 密文物理删除
        tdir = srv.blob_dir() / tid[:2] / tid
        leftover = sorted(p.name for p in tdir.rglob("*")) if tdir.is_dir() else []
        rep.add("密文物理删除（blob 无 prelude/块）", not leftover, f"残留={leftover or '无'}")

        # 2) 刚终结：记录在、敏感列有值
        rep.add("记录仍在且敏感列有值（未到 30 天）",
                q(args, f"select count(*) from transfers where transfer_id='{tid}'").strip() == "1"
                and q(args, f"select uploader_ip is not null from transfers where transfer_id='{tid}'").strip() == "t",
                "row=1 uploader_ip=not null")

        # 3) 10 天前终结 → 不得被删（v4 会删）
        Y.psql(args.dsn, "update transfers set terminal_at = now() - interval '10 days' "
                         f"where transfer_id='{tid}'", args.schema)
        time.sleep(2.5)  # sweep=1s，跑两轮
        rep.add("终结 10 天后仍保留（v4 的 7 天删除已取消）", row_count(args).strip() == "1",
                f"rows={row_count(args)}")
        rep.add("未到 30 天不脱敏",
                q(args, "select count(*) from transfers where transfer_id="
                        f"'{tid}' and uploader_ip is not null and prelude_sm3 is not null").strip() == "1",
                "uploader_ip/prelude_sm3 仍有值")

        # 4) 记下脱敏前的"应保留字段"
        before = q(args, "select " + ",".join(f"coalesce({c}::text,'<null>')" for c in KEEP)
                   + f" from transfers where transfer_id='{tid}'").replace("|", " ")

        # 5) 40 天前终结 → 三列置 NULL
        Y.psql(args.dsn, "update transfers set terminal_at = now() - interval '40 days' "
                         f"where transfer_id='{tid}'", args.schema)
        redacted = wait_until(lambda: q(
            args, "select count(*) from transfers where transfer_id="
                  f"'{tid}' and uploader_ip is null and prelude_sm3 is null "
                  "and upload_token_sm3 is null").strip() == "1")
        rep.add("终结 40 天 → uploader_ip/prelude_sm3/upload_token_sm3 置 NULL", redacted,
                "三列均为 NULL" if redacted else "等待清道夫超时")

        # 6) 其余字段逐字段不变
        after = q(args, "select " + ",".join(f"coalesce({c}::text,'<null>')" for c in KEEP)
                   + f" from transfers where transfer_id='{tid}'").replace("|", " ")
        rep.add("其余 " + str(len(KEEP)) + " 个字段逐值不变", before == after,
                f"before={before[:80]} after={after[:80]}")

        # 7) tombstone 字段集
        st, tb = c.transfer(tid)
        missing = [f for f in TOMBSTONE_FIELDS if f not in tb]
        leaked = [f for f in ("prelude_sm3", "lease_expires_at") if f in tb]
        rep.add("GET → 200 tombstone，字段集与契约一致",
                st == 200 and not missing and not leaked,
                f"{st} 缺={missing or '无'} 多={leaked or '无'} state={tb.get('state')}")

        # 8) 保留 ≠ 可取件
        st, body = c.get_prelude(tid)
        code = (body.get("error") or {}).get("code") if isinstance(body, dict) else ""
        stc, bodyc = c.get_chunk(tid, 0, "any")
        codec = (bodyc.get("error") or {}).get("code") if isinstance(bodyc, dict) else ""
        rep.add("保留 ≠ 可取件（prelude/块均 410 TRANSFER_CONSUMED）",
                st == 410 and code == "TRANSFER_CONSUMED" and stc == 410 and codec == "TRANSFER_CONSUMED",
                f"prelude={st} {code}；chunk={stc} {codec}")

        # 9) 幂等：再跑 3 轮，行数不变、无新增脱敏
        rows_before = row_count(args).strip()
        time.sleep(3.5)
        rows_after = row_count(args).strip()
        log = "\n".join(srv.sweep_log_lines())
        bad = "redact terminal transfers failed" in log or "does not exist" in log
        rep.add("清道夫幂等（多轮后行数不变、无报错）",
                rows_before == rows_after and not bad,
                f"rows {rows_before}→{rows_after} 日志报错={bad}")

    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
