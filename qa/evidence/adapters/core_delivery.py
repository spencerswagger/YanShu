#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate 侧投递客户端：按 `docs/API.md` v1 把**一个已加密的 `.yspk` 包**送到 Core 的服务端。

职责边界：本脚本**不做任何加解密**。它只搬运密文字节（prelude 与块切片），
外加流程所需的码/挑战/上传令牌。包必须先用端侧内核打好（见 run_evidence1_core.sh）。

流程（API.md）：挑战 → 注册码 ×2 → 建传输 → 传 prelude → 传块 → complete
              → GET prelude（开租约）→ GET 块 → ack

鉴权说明：签名在 `--verifier stub-allow` 的服务端上只做形状检查，因此签名用固定字节占位；
**接真实 SM2 验签后必须换成真签名**（脚本会打印一行提醒）。

用法：
    python3 core_delivery.py --base-url http://127.0.0.1:18080 \
        --yspk /tmp/a.yspk \
        --sender-code ABCD --sender-pk-b64 <b64> --sender-nickname 甲 \
        --recipient-code WXYZ --recipient-pk-b64 <b64> --recipient-nickname 乙 \
        [--sm3-cmd 'ys-tool sm3'] [--json-out /tmp/delivery.json]
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# 复用证据二的解析器定位 prelude 与块切片（同一套契约解析，避免两处实现漂移）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tamper_probe import parse_envelope  # noqa: E402


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.strip())


class Client:
    def __init__(self, base: str, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.last_headers: dict[str, str] = {}

    def call(self, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict | bytes]:
        req = urllib.request.Request(self.base + path, data=body, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                self.last_headers = {k.lower(): v for k, v in resp.headers.items()}
                ctype = resp.headers.get("content-type", "")
                if "json" in ctype and raw:
                    return resp.status, json.loads(raw)
                return resp.status, raw
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw)
            except Exception:  # noqa: BLE001
                payload = {"raw": raw[:200].decode("utf-8", "replace")}
            return exc.code, payload


def sm3_hex(data: bytes, cmd: str) -> str:
    out = subprocess.run(f"{cmd} {data.hex()}", shell=True, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"SM3 命令失败：{out.stderr.strip()}")
    return out.stdout.strip()


def auth_headers(code: str, challenge_id: str) -> dict[str, str]:
    # stub-allow 只校验形状：非空即可；接真实验签后换真签名
    return {
        "X-YS-Code": code,
        "X-YS-Challenge-Id": challenge_id,
        "X-YS-Signature": b64u(b"\x30\x44" + b"\x00" * 66),
    }


def new_challenge(c: Client, purpose: str) -> str:
    status, body = c.call("POST", "/v1/challenges",
                          json.dumps({"purpose": purpose}).encode(),
                          {"Content-Type": "application/json"})
    if status not in (200, 201):
        raise SystemExit(f"挑战失败 {status}: {body}")
    return body["challenge_id"]


def register_code(c: Client, code: str, pub65: bytes, nickname: str) -> None:
    ch = new_challenge(c, "REGISTER")
    payload = {"code": code, "public_key": b64u(pub65), "nickname": nickname}
    status, body = c.call("POST", "/v1/codes", json.dumps(payload).encode(),
                          {"Content-Type": "application/json", **auth_headers(code, ch)})
    if status not in (200, 201):
        raise SystemExit(f"注册码 {code} 失败 {status}: {body}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--yspk", required=True, help="已加密的 .yspk 包")
    ap.add_argument("--sender-code", required=True)
    ap.add_argument("--sender-pk-b64", required=True, help="65 字节公钥的 base64url")
    ap.add_argument("--sender-nickname", default="gate-sender")
    ap.add_argument("--recipient-code", required=True)
    ap.add_argument("--recipient-pk-b64", required=True)
    ap.add_argument("--recipient-nickname", default="gate-recipient")
    ap.add_argument("--sm3-cmd", default="ys-tool sm3", help="SM3 命令行（hex 进 hex 出）")
    ap.add_argument("--json-out")
    ap.add_argument("--skip-download", action="store_true", help="只上传不取件（排查用）")
    ap.add_argument("--no-ack", action="store_true",
                    help="取件但不 ack：保持密文留在服务端，供证据一扫描（ack 会按策略删密文）")
    args = ap.parse_args(argv)

    raw = Path(args.yspk).read_bytes()
    env = parse_envelope(raw)
    prelude = raw[:env.prelude_len]
    chunks = [raw[c.ct_off:c.ct_off + c.ct_len + 16] for c in env.chunks]
    print(f"[pack] {args.yspk}: {len(raw)}B / {env.chunk_count} 块 / prelude {len(prelude)}B "
          f"（布局 {env.layout}）")

    c = Client(args.base_url)
    print("[auth] 签名用占位字节（服务端必须是 --verifier stub-allow / stub-deny=false）")

    register_code(c, args.sender_code, base64.urlsafe_b64decode(args.sender_pk_b64 + "=="),
                  args.sender_nickname)
    register_code(c, args.recipient_code, base64.urlsafe_b64decode(args.recipient_pk_b64 + "=="),
                  args.recipient_nickname)
    print(f"[code] 注册完成：{args.sender_code} / {args.recipient_code}")

    prelude_sm3 = sm3_hex(prelude, args.sm3_cmd)
    ch = new_challenge(c, "TRANSFER_CREATE")
    create = {
        "recipient_code": args.recipient_code,
        "plaintext_size": env.plaintext_size,
        "chunk_size": env.chunk_size,
        "chunk_count": env.chunk_count,
        "prelude_len": len(prelude),
        "prelude_sm3": b64u(unhex(prelude_sm3)),
    }
    status, body = c.call("POST", "/v1/transfers", json.dumps(create).encode(),
                          {"Content-Type": "application/json",
                           **auth_headers(args.sender_code, ch)})
    if status not in (200, 201):
        raise SystemExit(f"建传输失败 {status}: {body}")
    tid, token = body["transfer_id"], body["upload_token"]
    print(f"[transfer] {tid} 状态={body['state']} 块数={body['chunk_count']}")
    up = {"X-YS-Upload-Token": token, "Content-Type": "application/octet-stream"}

    status, body = c.call("PUT", f"/v1/transfers/{tid}/prelude", prelude, up)
    if status not in (200, 201, 204):
        raise SystemExit(f"传 prelude 失败 {status}: {body}")
    print(f"[prelude] {len(prelude)}B 上传完成（{status}）")

    for i, ct in enumerate(chunks):
        status, body = c.call("PUT", f"/v1/transfers/{tid}/chunks/{i}", ct, up)
        if status not in (200, 201, 204):
            raise SystemExit(f"传块 {i} 失败 {status}: {body}")
    print(f"[chunks] {len(chunks)} 块上传完成")

    status, body = c.call("POST", f"/v1/transfers/{tid}/complete", b"{}",
                          {"Content-Type": "application/json", "X-YS-Upload-Token": token})
    if status not in (200, 201, 204):
        raise SystemExit(f"complete 失败 {status}: {body}")
    print(f"[complete] 状态={body.get('state') if isinstance(body, dict) else status}")

    result = {"transfer_id": tid, "chunks": len(chunks), "prelude_len": len(prelude),
              "plaintext_size": env.plaintext_size}

    if not args.skip_download:
        status, got_prelude = c.call("GET", f"/v1/transfers/{tid}/prelude")
        if status != 200:
            raise SystemExit(f"取 prelude 失败 {status}: {got_prelude}")
        dl_id = c.last_headers.get("x-ys-download-id", "")
        if got_prelude != prelude:
            raise SystemExit("取回的 prelude 与上传的不一致")
        got_chunks = []
        for i in range(len(chunks)):
            status, ct = c.call("GET", f"/v1/transfers/{tid}/chunks/{i}",
                                headers={"X-YS-Download-Id": dl_id})
            if status != 200:
                raise SystemExit(f"取块 {i} 失败 {status}: {ct}")
            got_chunks.append(ct)
        if got_chunks != chunks:
            raise SystemExit("取回的块与上传的不一致")
        print(f"[download] prelude + {len(got_chunks)} 块逐字节一致")

        if args.no_ack:
            print("[ack] 跳过（--no-ack）：密文留在服务端，供证据一扫描")
            result["state"] = c.last_headers.get("x-ys-state", "leased")
            if args.json_out:
                Path(args.json_out).write_text(
                    json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[done] transfer_id={tid}")
            return 0

        ch = new_challenge(c, "TRANSFER_ACK")
        status, body = c.call("POST", f"/v1/transfers/{tid}/ack", b"{}",
                              {"Content-Type": "application/json",
                               "X-YS-Download-Id": dl_id,
                               **auth_headers(args.recipient_code, ch)})
        if status not in (200, 201):
            raise SystemExit(f"ack 失败 {status}: {body}")
        print(f"[ack] 状态={body.get('state')} 已下载次数={body.get('download_count')}")
        result["state"] = body.get("state")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    print(f"[done] transfer_id={tid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
