#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证「递增 EPOCH **不重启**即生效」——同一个进程内完成，中途不重启。

很多实现会缓存版本号，导致"改了库但要重启才生效"。本脚本专门盯这一点：

1. 起**一次**服务（`YANSHU_TOKEN_EPOCH=1`），记下 PID；
2. 签发凭据 → 打受保护端点 → 期望 **200**；
3. **服务不停**，直接 `UPDATE token_kid_state SET kid = kid + 1`；
4. 同一进程、同一凭据再打 → 期望 **401 `AUTH_TOKEN_STALE`**；
5. 同一进程读 `/v1/config.token_epoch` → 期望**已变成新值**；
6. 全程断言 **PID 未变**（没有任何重启）。

用法：
    python3 qa/evidence/check_epoch_online_revoke.py --binary <bin> --deliver <deliver> \
        --yspk <样本> --dsn "<DSN>&search_path=<schema>" --schema <schema> --work <dir>
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

SECRET = "online-revoke-secret-0001"


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def psql(dsn: str, schema: str, sql: str) -> tuple[int, str]:
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema}")
    p = subprocess.run(["psql", "-X", "-A", "-t", dsn.split("search_path=")[0].rstrip("&"), "-c", sql],
                       capture_output=True, text=True, env=env)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--deliver", required=True)
    ap.add_argument("--yspk", required=True)
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--schema", default="gate_online")
    ap.add_argument("--work", default="/tmp/ys-online")
    args = ap.parse_args(argv)

    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    (work / "blobs").mkdir(exist_ok=True)
    port = free_port()
    env = dict(os.environ, YANSHU_DATABASE_URL=args.dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
               YANSHU_ADDR=f"127.0.0.1:{port}", YANSHU_VERIFIER="stub-allow",
               YANSHU_TOKEN_SECRET=SECRET, YANSHU_TOKEN_EPOCH="1")
    proc = subprocess.Popen([args.binary], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    pid0 = proc.pid

    def get(path, tok=None):
        r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
        if tok:
            r.add_header("X-YS-Upload-Token", tok)
        try:
            with urllib.request.urlopen(r, timeout=10) as x:
                return x.status, x.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1); break
        except Exception:
            time.sleep(0.2)

    rows = []
    d = subprocess.run([args.deliver, "--base-url", f"http://127.0.0.1:{port}", "--yspk", args.yspk,
                        "--no-ack", "--print-upload-token"], capture_output=True, text=True)
    pkg = [l.split("=", 1)[1].strip() for l in (d.stdout + d.stderr).splitlines() if l.startswith("package_id=")][0]
    tok = [l.split("=", 1)[1].strip() for l in d.stderr.splitlines() if l.startswith("upload_token=")][0]

    st, body = get(f"/v1/transfers/{pkg}/status", tok)
    rows.append(("递增前：凭据可用", st == 200, f"{st}"))
    _, cfg = get("/v1/config")
    epoch0 = json.loads(cfg).get("token_epoch")

    # —— 服务不停，直接改库 ——
    rc, out = psql(args.dsn, args.schema, "update token_kid_state set kid = kid + 1 returning kid")
    rows.append(("库内 EPOCH +1（服务未停）", rc == 0, out.splitlines()[-1] if out else ""))

    st2, body2 = get(f"/v1/transfers/{pkg}/status", tok)
    err = ""
    try:
        err = (json.loads(body2).get("error") or {}).get("code", "")
    except Exception:
        pass
    rows.append(("同一进程内旧凭据立刻 401 STALE", st2 == 401 and err == "AUTH_TOKEN_STALE", f"{st2} {err}"))

    _, cfg2 = get("/v1/config")
    epoch1 = json.loads(cfg2).get("token_epoch")
    rows.append(("同一进程内 token_epoch 已变", epoch1 is not None and epoch1 != epoch0, f"{epoch0} → {epoch1}"))

    alive = proc.poll() is None
    rows.append(("全程未重启（PID 不变且进程存活）", alive and proc.pid == pid0, f"pid={proc.pid}"))

    proc.terminate()
    print("=" * 84)
    print("在线吊销：递增 EPOCH 是否需要重启？")
    print("=" * 84)
    bad = 0
    for name, ok, detail in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<34} {detail}")
        if not ok:
            bad += 1
    print("-" * 84)
    print("结论：" + ("PASS —— 递增 EPOCH 立即生效，无需重启" if bad == 0 else "FAIL —— 与设计不符（可能需要重启）"))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
