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

# 裁定的错误名字面（2026-11-02）：版本轮换 = STALE、值不匹配 = INVALID、签名本身 = SIGNATURE。
# 实现若返回别的名字（例如临时的 AUTH_TOKEN_REVOKED），按 FAIL 记并注明"待改名"，不迁就实现。
WANT_STALE = "AUTH_TOKEN_STALE"
WANT_INVALID = "AUTH_TOKEN_INVALID"
PENDING = {"AUTH_TOKEN_REVOKED": "实现仍是临时名 AUTH_TOKEN_REVOKED，待 Core 改为 AUTH_TOKEN_STALE"}


def next_kid(kid: str) -> str:
    """单调递增：k1→k2、1→2、k001→k002；其它形式直接追加 +1 后缀。"""
    import re
    m = re.fullmatch(r"([A-Za-z_]*)(\d+)", kid)
    if m:
        return f"{m.group(1)}{int(m.group(2)) + 1}"
    return kid + "-next"


def kid_note(a, b) -> str:
    if not b:
        return ""
    return f" + kid={a}→{b}" if a != b else f" + kid={a}"
# stub-allow 下签名只做形状检查；本实验验的是 token，不是签名
SIG = B64(b"\x30\x44" + b"\x00" * 66)


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def start(binary: str, dsn: str, work: Path, secret: str, kid: str | None = None,
          extra: dict | None = None):
    port = free_port()
    env = dict(os.environ, YANSHU_DATABASE_URL=dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
               YANSHU_ADDR=f"127.0.0.1:{port}", YANSHU_VERIFIER="stub-allow",
               YANSHU_TOKEN_SECRET=secret, YANSHU_LOG_DIR=str(work / "logs"))
    if kid is not None:
        env["YANSHU_TOKEN_KID"] = kid
    env.update(extra or {})
    proc = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    return proc, port


def err_code(body: bytes) -> str:
    try:
        obj = json.loads(body)
        return (obj.get("error") or {}).get("code", "") or ""
    except Exception:
        return ""


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
    ap.add_argument("--kid", default=None,
                    help="设置 YANSHU_TOKEN_KID（fa479d9 起为必配项）；给了就按 kid 轮换做三态")
    ap.add_argument("--epoch-check", action="store_true",
                    help="额外做一组：只改 YANSHU_TOKEN_EPOCH（secret 不变），验证是否真存在版本吊销")
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

    proc, port = start(args.binary, args.dsn, work, "a" * 32, args.kid)
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

    # 先自证：同一密钥下旧 token 可用（基线，避免"本来就不对"被当成吊销成功）
    proc, port = start(args.binary, args.dsn, work, "a" * 32, args.kid)
    try:
        st, body = call(port, "PUT", f"/v1/transfers/{tid}/prelude", prelude,
                        {"Content-Type": "application/octet-stream", "X-YS-Upload-Token": token})
        print(f"[基线] 同一 secret{kid_note(args.kid, args.kid)} 下用 token 打 PUT /prelude → HTTP {st}"
              + (f"（{err_code(body)}）" if st >= 300 else ""))
        if st >= 300:
            print("[BLOCKED] 基线都不通过，本轮不能用来判断轮换是否生效", file=sys.stderr)
            return 2
    finally:
        proc.terminate(); proc.wait()

    # ---- 对照组 B：只改"版本"变量（secret 不动），看是否真存在 epoch 机制 ----
    if args.epoch_check:
        ep1, ep2 = "1", "2"
        proc, port = start(args.binary, args.dsn, work, "a" * 32, {"YANSHU_TOKEN_EPOCH": ep1})
        try:
            st, body = call(port, "PUT", f"/v1/transfers/{tid}/prelude", prelude,
                            {"Content-Type": "application/octet-stream", "X-YS-Upload-Token": token})
            print(f"[B-基线] secret 不变 + YANSHU_TOKEN_EPOCH={ep1} → HTTP {st}"
                  + (f"（{err_code(body)}）" if st >= 300 else ""))
        finally:
            proc.terminate(); proc.wait()
        proc, port = start(args.binary, args.dsn, work, "a" * 32, {"YANSHU_TOKEN_EPOCH": ep2})
        try:
            st, body = call(port, "PUT", f"/v1/transfers/{tid}/prelude", prelude,
                            {"Content-Type": "application/octet-stream", "X-YS-Upload-Token": token})
            print(f"[B-只改版本] secret 不变 + YANSHU_TOKEN_EPOCH={ep1}→{ep2} → HTTP {st}"
                  + (f"（{err_code(body)}）" if st >= 300 else ""))
            print("  B 结论：" + ("该变量生效（版本轮换可吊销）" if st in (401, 403)
                                else "该变量被忽略（该 commit 上没有 epoch/kid 机制）"))
        finally:
            proc.terminate(); proc.wait()

    proc, port = start(args.binary, args.dsn, work, "b" * 32,
                       next_kid(args.kid) if args.kid else None)
    try:
        st, body = call(port, "PUT", f"/v1/transfers/{tid}/prelude", prelude,
                        {"Content-Type": "application/octet-stream", "X-YS-Upload-Token": token})
        revoked = st in (401, 403)
        got = err_code(body)
        print(f"[轮换后] secret=B{kid_note(args.kid, next_kid(args.kid) if args.kid else None)} "
              f"下用旧 token 打 PUT /prelude → HTTP {st}"
              + (f"（{got}）" if st >= 300 else ""))
        if st >= 300:
            want = WANT_STALE if got != WANT_INVALID else WANT_INVALID
            if got == want:
                print(f"  名字判定：PASS（符合裁定 {want}）")
            else:
                print(f"  名字判定：FAIL（期望 {WANT_STALE}，实得 {got or '无错误名'}）"
                      + (f" —— {PENDING[got]}" if got in PENDING else ""))
        # 第三态：轮换后重新签发的新 token 应当可用
        st3, body3 = call(port, "POST", "/v1/challenges",
                          json.dumps({"purpose": "TRANSFER_CREATE"}).encode(),
                          {"Content-Type": "application/json"})
        ch3 = json.loads(body3)["challenge_id"]
        create3 = dict(create)
        st3, body3 = call(port, "POST", "/v1/transfers", json.dumps(create3).encode(),
                          {"Content-Type": "application/json", "X-YS-Code": code,
                           "X-YS-Challenge-Id": ch3, "X-YS-Signature": SIG})
        new_ok = False
        if st3 in (200, 201):
            rep3 = json.loads(body3)
            st4, body4 = call(port, "PUT", f"/v1/transfers/{rep3['transfer_id']}/prelude", prelude,
                              {"Content-Type": "application/octet-stream",
                               "X-YS-Upload-Token": rep3["upload_token"]})
            new_ok = st4 in (200, 201, 204)
            print(f"[重签发] 轮换后新建传输 + 新 token 打 PUT /prelude → HTTP {st4}"
                  + (f"（{err_code(body4)}）" if st4 >= 300 else ""))
        else:
            print(f"[重签发] 建传输失败 {st3}（{err_code(body3)}）")
        print("结论：" + ("轮换即吊销（旧 401 + 新 token 正常）"
                          if (revoked and new_ok) else
                          ("旧 token 仍可用 —— 轮换**不能**吊销（缺口未修）"
                           if not revoked else
                           "旧 token 已失效，但新签发也有问题，需人工看")))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(
                {"transfer_id": tid, "status": st, "revoked": revoked},
                ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        proc.terminate(); proc.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
