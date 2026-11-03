#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""token 五步（终局口径）：secret 不吊销、KID 递增在线吊销。

预期：
  ① 基线 → 201
  ② 只改 TOKEN_SECRET（KID 不变）→ **仍可用 200/201**
  ③ KID+1（SQL 直接改库，**不重启**）→ 旧 token 401 `AUTH_TOKEN_STALE`
  ④ KID+1 后新签发 → 201；旧 token 仍 401（不复活）
  ⑤ 超期 → `AUTH_TOKEN_EXPIRED`（需构造，见 --expire-tuning）

用法：
    python3 qa/evidence/check_token_five_steps.py --binary <bin> --deliver <deliver> \
        --yspk <样本> --dsn "<DSN>&search_path=<schema>" --work <dir> [--json-out out.json]
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

S1, S2 = "rotation-secret-0001", "rotation-secret-0002"


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def psql(dsn: str, schema: str, sql: str) -> tuple[int, str]:
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema}")
    p = subprocess.run(["psql", "-X", "-A", "-t",
                        dsn.split("search_path=")[0].rstrip("&"), "-c", sql],
                       capture_output=True, text=True, env=env)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


class Srv:
    def __init__(self, binary, dsn, kid, secret, work):
        self.port = free_port()
        env = dict(os.environ, YANSHU_DATABASE_URL=dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
                   YANSHU_ADDR=f"127.0.0.1:{self.port}", YANSHU_VERIFIER="stub-allow",
                   YANSHU_TOKEN_SECRET=secret, YANSHU_TOKEN_KID=str(kid))
        (work / "blobs").mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen([binary], env=env, cwd=str(work),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def wait(self):
        for _ in range(80):
            if self.proc.poll() is not None:
                return False, (self.proc.stdout.read() or "")[-300:]
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1)
                return True, ""
            except Exception:
                time.sleep(0.2)
        return False, "timeout"

    def get(self, path, token=None):
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


def err_of(b: str) -> str:
    try:
        return (json.loads(b).get("error") or {}).get("code", "")
    except Exception:
        return ""


def upload(deliver, port, yspk):
    p = subprocess.run([deliver, "--base-url", f"http://127.0.0.1:{port}", "--yspk", yspk,
                        "--no-ack", "--print-upload-token"], capture_output=True, text=True)
    pkg, tok = "", ""
    for line in (p.stdout or "").splitlines():
        if line.startswith("package_id="):
            pkg = line.split("=", 1)[1].strip()
    if not pkg and (p.stdout or "").strip().startswith("{"):
        pkg = json.loads(p.stdout)["package_id"]
    for line in (p.stderr or "").splitlines():
        if line.startswith("upload_token="):
            tok = line.split("=", 1)[1].strip()
    return pkg, tok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--deliver", required=True)
    ap.add_argument("--yspk", required=True)
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--schema", default="gate_five")
    ap.add_argument("--work", default="/tmp/ys-five")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    rows = []

    # ① 基线
    srv = Srv(args.binary, args.dsn, 1, S1, work)
    ok, log = srv.wait()
    if not ok:
        print("[BLOCKED] 起不来：\n" + log, file=sys.stderr); return 2
    pkg, tok = upload(args.deliver, srv.port, args.yspk)
    st, body = srv.get(f"/v1/transfers/{pkg}/status", tok)
    rows.append(("① 基线（KID=1, secret=…0001）", st, err_of(body)))
    cfg, cfgbody = srv.get("/v1/config")
    epoch1 = json.loads(cfgbody).get("token_epoch")
    srv.stop()

    # ② 只改 secret（KID 不变）——**期望仍可用**
    srv = Srv(args.binary, args.dsn, 1, S2, work)
    ok, log = srv.wait()
    if not ok:
        print("[BLOCKED] ② 起不来：\n" + log, file=sys.stderr); return 2
    st2, body2 = srv.get(f"/v1/transfers/{pkg}/status", tok)
    rows.append(("② 只改 secret（KID 仍 1）→ 期望仍可用", st2, err_of(body2)))
    srv.stop()

    # ③ KID+1（SQL 直接改库，不重启）→ 旧 token 立刻 STALE
    rc, out = psql(args.dsn, args.schema, "update token_kid_state set kid = kid + 1 returning kid")
    newkid = out.splitlines()[-1].strip() if rc == 0 else "?"
    srv = Srv(args.binary, args.dsn, int(newkid) if newkid.isdigit() else 2, S2, work)
    ok, log = srv.wait()
    if not ok:
        print("[BLOCKED] ③ 起不来：\n" + log, file=sys.stderr); return 2
    st3, body3 = srv.get(f"/v1/transfers/{pkg}/status", tok)
    rows.append((f"③ KID+1（库内 →{newkid}，不重启）旧 token", st3, err_of(body3)))
    cfg3, cfgbody3 = srv.get("/v1/config")
    epoch3 = json.loads(cfgbody3).get("token_epoch")

    # ④ KID+1 后新签发 → 201；旧 token 仍 401
    pkg2, tok2 = upload(args.deliver, srv.port, args.yspk)
    st4, body4 = srv.get(f"/v1/transfers/{pkg2}/status", tok2)
    rows.append(("④ 新签发的新 token", st4, err_of(body4)))
    st4b, body4b = srv.get(f"/v1/transfers/{pkg}/status", tok)
    rows.append(("④ 最初 token 复打（不复活）", st4b, err_of(body4b)))
    srv.stop()

    print("=" * 88)
    print("token 五步（终局口径：secret 作派生盐、KID 在线吊销）")
    print("=" * 88)
    for name, st, err in rows:
        print(f"{name:<38} → {st:<4} {err or '(无错误名)'}")
    print(f"/v1/config token_epoch：轮换前 {epoch1} → 轮换后 {epoch3}"
          f"（{'随 KID 变化' if epoch1 != epoch3 else '未变化'}）")
    print("-" * 88)

    ok2 = rows[1][1] in (200, 201)                       # 只改 secret 仍可用
    ok3 = rows[2][1] == 401 and rows[2][2] == "AUTH_TOKEN_STALE"
    ok4 = rows[3][1] in (200, 201) and rows[4][1] == 401
    oke = epoch1 != epoch3
    print("判定：" + f"②{'PASS' if ok2 else 'FAIL'} ③{'PASS' if ok3 else 'FAIL'} "
                    f"④{'PASS' if ok4 else 'FAIL'} token_epoch{'PASS' if oke else 'FAIL'}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"rows": [{"step": n, "status": s, "error": e} for n, s, e in rows],
             "epoch_before": epoch1, "epoch_after": epoch3,
             "ok": ok2 and ok3 and ok4 and oke}, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if (ok2 and ok3 and ok4 and oke) else 1


if __name__ == "__main__":
    sys.exit(main())
