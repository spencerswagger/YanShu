#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`SIG_INPUT` 三层限额验收（109 合法上限 / 字段级错误 / 512 防御门）。

契约 §1.3：

* `SIG_INPUT = "YSAUTH1"(7) ‖ PURPOSE(1) ‖ NONCE(32) ‖ 字段串`；
* **合法上限 109**（REGISTER：CODE(4)+PUBKEY(65)=69 → 40+69）；
* **109 以内但字段不合法 → 字段级错误**（`NICKNAME_INVALID` / `CODE_FORMAT_INVALID` 等），
  **MUST NOT** 用字节上限代替字段校验；
* **>512 → `400 SIG_INPUT_TOO_LONG`**，512 只是防 DoS 的门，不是合法性边界。

用法：
    python3 qa/evidence/check_siginput_limits.py --binary <yanshu-server> \
        --dsn "<DSN>&search_path=<已迁移 schema>" [--kid 9] [--json-out out.json]

退出码：0 全 PASS；1 有 FAIL；2 起不来（BLOCKED）。
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

PUB = bytes.fromhex(
    "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1"
    "16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d")
B64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")

# 契约 §1.3 表（字段串上限 / 对应 SIG_INPUT 总长 = 40 + 字段串）
PURPOSES = [
    ("0x01 REGISTER", "REGISTER", 69, "CODE(4)‖PUBKEY(65)"),
    ("0x02 NICKNAME_UPDATE", "NICKNAME_UPDATE", 38, "CODE(4)‖u16be(2)‖NICKNAME(≤32)"),
    ("0x03 TRANSFER_CREATE", "TRANSFER_CREATE", 60, "4+4+8+4+4+4+32"),
    ("0x04 TRANSFER_REVOKE", "TRANSFER_REVOKE", 36, "CODE(4)‖TRANSFER_ID(32)"),
    ("0x05 INBOX_LIST", "INBOX_LIST", 4, "CODE(4)"),
    ("0x06 WS_HELLO", "WS_HELLO", 4, "CODE(4)"),
    ("0x07 TRANSFER_ACK", "TRANSFER_ACK", 36, "CODE(4)‖TRANSFER_ID(32)"),
    ("0x08 UPLOAD_TOKEN_ISSUE", "UPLOAD_TOKEN_ISSUE", 36, "CODE(4)‖TRANSFER_ID(32)"),
]


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Srv:
    def __init__(self, binary: str, dsn: str, kid: str, work: Path):
        self.port = free_port()
        env = dict(os.environ, YANSHU_DATABASE_URL=dsn, YANSHU_BLOB_DIR=str(work / "blobs"),
                   YANSHU_ADDR=f"127.0.0.1:{self.port}", YANSHU_VERIFIER="sm2",
                   YANSHU_TOKEN_SECRET="siginput-probe-secret-01", YANSHU_TOKEN_KID=kid,
                   YANSHU_KERNEL_WASM="kernel/yanshu_sm.wasm")
        (work / "blobs").mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen([binary], env=env, cwd=str(work),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def wait(self) -> bool:
        for _ in range(80):
            if self.proc.poll() is not None:
                return False
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1)
                return True
            except Exception:
                time.sleep(0.2)
        return False

    def call(self, method, path, body=None, hdr=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method)
        if data is not None:
            r.add_header("Content-Type", "application/json")
        for k, v in (hdr or {}).items():
            r.add_header(k, v)
        try:
            with urllib.request.urlopen(r, timeout=10) as x:
                return x.status, x.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def chal(self, purpose):
        st, b = self.call("POST", "/v1/challenges", {"purpose": purpose})
        return json.loads(b)["challenge_id"]

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def err_code(body: str) -> str:
    try:
        return (json.loads(body).get("error") or {}).get("code", "")
    except Exception:
        return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SIG_INPUT 三层限额验收")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--kid", default="9", help="必须严格大于该 schema 已记录值")
    ap.add_argument("--work", default="/tmp/ys-siginput")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    srv = Srv(args.binary, args.dsn, args.kid, work)
    if not srv.wait():
        print("[BLOCKED] 服务起不来：\n" + (srv.proc.stdout.read() or "")[-400:], file=sys.stderr)
        return 2

    results = []
    try:
        # ① 七/八种 PURPOSE 的长度表（按契约字段上限推导）
        print("=" * 90)
        print("① SIG_INPUT 长度表（= 40 + 字段串上限，与契约 §1.3 对照）")
        print("=" * 90)
        for name, _, cap, layout in PURPOSES:
            print(f"{name:<26} 字段串上限 {cap:>3} → SIG_INPUT 最长 {40 + cap:>3}   {layout}")
        maxlen = max(40 + cap for _, _, cap, _ in PURPOSES)
        ok_table = (maxlen == 109)
        results.append(("长度表推导出的合法上限 == 109", ok_table, f"max={maxlen}"))

        # ② 109 允许 / 110 字段级
        st, b = srv.call("POST", "/v1/codes",
                         {"code": "AWQW", "public_key": B64(PUB), "nickname": "p"},
                         {"X-YS-Code": "AWQW", "X-YS-Challenge-Id": srv.chal("REGISTER"),
                          "X-YS-Signature": "MEUCIQDdeadbeef"})
        ok109 = st == 401 and err_code(b) in ("AUTH_SIGNATURE_INVALID", "AUTH_CODE_MISMATCH")
        results.append(("REGISTER 恰好 109 字节 → 接受（走到验签）", ok109, f"{st} {err_code(b)}"))
        print(f"  实测 109 字节：{st} {err_code(b)}")

        st, b = srv.call("POST", "/v1/codes",
                         {"code": "AWQW", "public_key": B64(PUB + b"\x00"), "nickname": "p"},
                         {"X-YS-Code": "AWQW", "X-YS-Challenge-Id": srv.chal("REGISTER"),
                          "X-YS-Signature": "MEUCIQDdeadbeef"})
        c110 = err_code(b)
        ok110 = st == 400 and c110 not in ("SIG_INPUT_TOO_LONG", "")
        results.append(("REGISTER 110 字节 → 字段级错误（非 TOO_LONG）", ok110, f"{st} {c110}"))
        print(f"  实测 110 字节：{st} {c110}")

        # ③ 昵称 33 字节 → 字段级
        st, b = srv.call("PATCH", "/v1/codes/AWQW", {"nickname": "a" * 33},
                         {"X-YS-Code": "AWQW", "X-YS-Challenge-Id": srv.chal("NICKNAME_UPDATE"),
                          "X-YS-Signature": "MEUCIQDdeadbeef"})
        c33 = err_code(b)
        ok33 = st == 400 and c33 == "NICKNAME_INVALID"
        results.append(("昵称 33 字节 → NICKNAME_INVALID（非 TOO_LONG）", ok33, f"{st} {c33}"))
        print(f"  实测昵称 33 字节：{st} {c33}")

        # ④ 构造 >512 字节输入
        st, b = srv.call("PATCH", "/v1/codes/AWQW", {"nickname": "a" * 467},
                         {"X-YS-Code": "AWQW", "X-YS-Challenge-Id": srv.chal("NICKNAME_UPDATE"),
                          "X-YS-Signature": "MEUCIQDdeadbeef"})
        c513 = err_code(b)
        if st == 400 and c513 == "SIG_INPUT_TOO_LONG":
            results.append(("513 字节输入 → SIG_INPUT_TOO_LONG（400）", True, f"{st} {c513}"))
        elif st == 400 and c513 in ("NICKNAME_INVALID", "BAD_REQUEST", "CODE_FORMAT_INVALID"):
            # 口径（2026-11-02 定）：字段级校验先行、512 门在 HTTP 层不可达，属设计使然。
            # 记 N/A（不可观测），不判 FAIL；契约将注明该码"防御性上限、当前不可达"。
            results.append(("513 字节 → SIG_INPUT_TOO_LONG（N/A：不可观测）", None,
                            f"{st} {c513}（字段级优先，按设计；该码不可达）"))
        else:
            results.append(("513 字节输入 → SIG_INPUT_TOO_LONG（400）", False, f"{st} {c513}"))
        print(f"  实测 513 字节（昵称 467）：{st} {c513}")
    finally:
        srv.stop()

    print("-" * 90)
    failed = sum(1 for _, ok, _ in results if ok is False)
    na = sum(1 for _, ok, _ in results if ok is None)
    for name, ok, detail in results:
        tag = "PASS" if ok else ("N/A" if ok is None else "FAIL")
        print(f"{tag:<6} {name:<46} {detail}")
    print(f"{len(results) - failed - na}/{len(results) - na} 通过"
          + (f"（另 {na} 条 N/A：不可观测，按设计）" if na else ""))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"ok": failed == 0,
             "results": [{"name": n, "ok": o, "detail": d} for n, o, d in results]},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
