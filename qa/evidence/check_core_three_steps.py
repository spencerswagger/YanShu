#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""原样复跑 Core 给的三步（只改一个变量），记录状态码与**原始错误名字符串**。

步骤（Core 的原文）：
  1. secret=rotation-secret-0001、KID=1 启动 → deliver --print-upload-token 取 TOKEN →
     curl -H "X-YS-Upload-Token: $TOKEN" /v1/transfers/{id}/status → 期望 200
  2. 只改 secret 为 rotation-secret-0002（KID 仍 1）重启 → 同一 token → 期望 401 AUTH_TOKEN_INVALID；
     新传输的新 token → 200
  3. 只改 KID 为 2（secret 不变）重启 → 上一轮 token → 期望 401 AUTH_TOKEN_STALE

用法：
    python3 qa/evidence/check_core_three_steps.py --binary <yanshu-server> \
        --deliver <deliver> --yspk <样本.yspk> --dsn "<DSN>&search_path=<schema>" \
        --kernel <kernel dir> [--json-out out.json]

退出码 0 全符合；1 有不符合；2 起不来。
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

SECRET1 = "rotation-secret-0001"
SECRET2 = "rotation-secret-0002"


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Srv:
    def __init__(self, binary: str, dsn: str, kid: int, secret: str, work: Path):
        self.port = free_port()
        env = dict(os.environ, YANSHU_DATABASE_URL=dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
                   YANSHU_ADDR=f"127.0.0.1:{self.port}", YANSHU_VERIFIER="stub-allow",
                   YANSHU_TOKEN_SECRET=secret, YANSHU_TOKEN_KID=str(kid))
        (work / "blobs").mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen([binary], env=env, cwd=str(work),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def wait(self) -> tuple[bool, str]:
        for _ in range(80):
            if self.proc.poll() is not None:
                return False, (self.proc.stdout.read() or "")[-400:]
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1)
                return True, ""
            except Exception:
                time.sleep(0.2)
        return False, "timeout"

    def get(self, path: str, token: str | None = None):
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method="GET")
        if token:
            r.add_header("X-YS-Upload-Token", token)
        try:
            with urllib.request.urlopen(r, timeout=10) as x:
                return x.status, x.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def err_of(body: str) -> str:
    try:
        e = json.loads(body).get("error") or {}
        return e.get("code", "")
    except Exception:
        return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--deliver", required=True)
    ap.add_argument("--yspk", required=True)
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--work", default="/tmp/ys-three")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    rows = []

    def upload(port: int) -> tuple[str, str]:
        p = subprocess.run([args.deliver, "--base-url", f"http://127.0.0.1:{port}",
                            "--yspk", args.yspk, "--no-ack", "--print-upload-token"],
                           capture_output=True, text=True)
        pkg = json.loads(p.stdout)["package_id"] if p.stdout.strip().startswith("{") else ""
        tok = ""
        for line in (p.stderr or "").splitlines():
            if line.startswith("upload_token="):
                tok = line.split("=", 1)[1].strip()
        if not pkg:
            for line in (p.stdout or "").splitlines():
                if line.startswith("package_id="):
                    pkg = line.split("=", 1)[1].strip()
        return pkg, tok

    # ---- 步骤 1 ----
    srv = Srv(args.binary, args.dsn, 1, SECRET1, work)
    ok, log = srv.wait()
    if not ok:
        print("[BLOCKED] 步骤1 起不来：\n" + log, file=sys.stderr)
        return 2
    pkg, tok = upload(srv.port)
    st, body = srv.get(f"/v1/transfers/{pkg}/status", tok)
    rows.append(("① secret=A KID=1", f"{st}", err_of(body)))
    srv.stop()

    # ---- 步骤 2：只改 secret ----
    srv = Srv(args.binary, args.dsn, 1, SECRET2, work)
    ok, log = srv.wait()
    if not ok:
        print("[BLOCKED] 步骤2 起不来：\n" + log, file=sys.stderr)
        return 2
    st2, body2 = srv.get(f"/v1/transfers/{pkg}/status", tok)
    rows.append(("② 只改 secret（KID 仍 1）", f"{st2}", err_of(body2)))
    pkg2, tok2 = upload(srv.port)
    st2b, body2b = srv.get(f"/v1/transfers/{pkg2}/status", tok2)
    rows.append(("② 新传输的新 token", f"{st2b}", err_of(body2b)))
    srv.stop()

    # ---- 步骤 3：只改 KID ----
    srv = Srv(args.binary, args.dsn, 2, SECRET2, work)
    ok, log = srv.wait()
    if not ok:
        print("[BLOCKED] 步骤3 起不来：\n" + log, file=sys.stderr)
        return 2
    st3, body3 = srv.get(f"/v1/transfers/{pkg2}/status", tok2)
    rows.append(("③ 只改 KID（KID=2）上一轮 token", f"{st3}", err_of(body3)))
    srv.stop()

    print("=" * 80)
    print("Core 三步原样复跑（只改一个变量）")
    print("=" * 80)
    for name, st, err in rows:
        print(f"{name:<28} → {st:<4} {err or '(无错误名)'}")
    want = [("200", ""), ("401", "AUTH_TOKEN_INVALID"), ("200", ""), ("401", "AUTH_TOKEN_STALE")]
    bad = [(r, w) for r, w in zip(rows, want) if r[1] != w[0] or r[2] != w[1]]
    print("-" * 80)
    print("结论：" + ("PASS —— 三步与 Core 描述一致" if not bad else f"FAIL —— 不符：{bad}"))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"ok": not bad, "rows": [{"step": n, "status": s, "error": e} for n, s, e in rows]},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
