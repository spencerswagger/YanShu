#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""token 生命周期实测：轮换 `YANSHU_TOKEN_SECRET` 后，旧 `upload_token` 还能不能用？

背景：我们一度按"重启即失效"做安全假设；Core 说轮换 secret 不会吊销 token。
这条直接决定「secret 泄露能否应急吊销」，必须实测，不能猜。

做法（最小实验，两条路径都覆盖）：
  1. 用 `TOKEN_SECRET=A` 起实例 → 注册码 → 建传输 → 拿到 `upload_token`
  2. 关掉，换 `TOKEN_SECRET=B` 用**同一 schema / 同一 blob 目录**再起
  3. 拿**旧 token** 打受保护端点 `PUT /v1/transfers/{id}/prelude`
  4. 记录响应：201/204 = 旧 token 仍有效；401 = 已吊销

用法：
    python3 qa/evidence/check_token_lifecycle.py \
        --binary <yanshu-server> --dsn "<DSN>&search_path=gate_ev1" \
        --ys-tool <ys-tool> [--work /tmp/ys-token] [--json-out out.json]

退出码：0 实验跑完（无论结论是"有效"还是"已吊销"，结论写进输出）；
        2 参数/依赖问题。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

B64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
# stub-allow 下签名只做形状检查；本实验验的是 token，不是签名
SIG = B64(b"\x30\x44" + b"\x00" * 66)


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def start(binary: str, dsn: str, work: Path, secret: str):
    port = free_port()
    env = dict(os.environ, YANSHU_DATABASE_URL=dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
               YANSHU_ADDR=f"127.0.0.1:{port}", YANSHU_VERIFIER="stub-allow",
               YANSHU_TOKEN_SECRET=secret, YANSHU_LOG_DIR=str(work / "logs"))
    proc = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    return proc, port


def call(port: int, method: str, path: str, body: bytes | None = None, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="token 生命周期实测（轮换 TOKEN_SECRET）")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--ys-tool", required=True, help="用于派生用户码与 SM3")
    ap.add_argument("--work", default="/tmp/ys-token")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    (work / "logs").mkdir(exist_ok=True)
    (work / "blobs").mkdir(exist_ok=True)

    def sm3_hex(data: bytes) -> str:
        out = subprocess.run([args.ys_tool, "sm3", data.hex()], capture_output=True, text=True)
        return out.stdout.strip()

    # 用契约 §15.1 的公钥（PB_S）做登记主体：它是合法曲线点，码固定为 AWQW，
    # 且同一公钥重复注册是幂等的，不污染别的实验。
    pub65 = ("04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1"
             "16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d")
    code = subprocess.run([args.ys_tool, "user-code", pub65], capture_output=True, text=True).stdout.strip()
    prelude = os.urandom(495)

    proc, port = start(args.binary, args.dsn, work, "a" * 32)
    try:
        st, body = call(port, "POST", "/v1/challenges", json.dumps({"purpose": "REGISTER"}).encode(),
                        {"Content-Type": "application/json"})
        ch = json.loads(body)["challenge_id"]
        call(port, "POST", "/v1/codes",
             json.dumps({"code": code, "public_key": B64(bytes.fromhex(pub65)), "nickname": "probe"}).encode(),
             {"Content-Type": "application/json", "X-YS-Code": code,
              "X-YS-Challenge-Id": ch, "X-YS-Signature": SIG})

        st, body = call(port, "POST", "/v1/challenges", json.dumps({"purpose": "TRANSFER_CREATE"}).encode(),
                        {"Content-Type": "application/json"})
        ch = json.loads(body)["challenge_id"]
        create = {"recipient_code": code, "plaintext_size": 1660, "chunk_size": 1024,
                  "chunk_count": 2, "prelude_len": len(prelude),
                  "prelude_sm3": B64(bytes.fromhex(sm3_hex(prelude)))}
        st, body = call(port, "POST", "/v1/transfers", json.dumps(create).encode(),
                        {"Content-Type": "application/json", "X-YS-Code": code,
                         "X-YS-Challenge-Id": ch, "X-YS-Signature": SIG})
        if st not in (200, 201):
            print(f"[BLOCKED] 建传输失败 {st}: {body[:200]}", file=sys.stderr)
            return 2
        rep = json.loads(body)
        tid, token = rep["transfer_id"], rep["upload_token"]
        print(f"secret=A 建传输成功：{tid}（token 前缀 {token[:8]}…）")
    finally:
        proc.terminate(); proc.wait()

    proc, port = start(args.binary, args.dsn, work, "b" * 32)
    try:
        st, body = call(port, "PUT", f"/v1/transfers/{tid}/prelude", prelude,
                        {"Content-Type": "application/octet-stream", "X-YS-Upload-Token": token})
        revoked = st in (401, 403)
        print(f"secret=B 下用旧 token 打 PUT /prelude → HTTP {st}")
        print("结论：" + ("旧 token 已随 secret 轮换失效（可应急吊销）"
                          if revoked else
                          "旧 token 仍然可用 —— 轮换 secret **不能**吊销已签发 token"))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(
                {"transfer_id": tid, "status": st, "revoked": revoked},
                ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        proc.terminate(); proc.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
