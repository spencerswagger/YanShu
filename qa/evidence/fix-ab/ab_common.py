#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix-ab 证据脚本共用件：SM3、最小 API 客户端、起一个真服务、结果落盘。

只依赖 python3 标准库 + `psql`。不做加解密：prelude / 块都是不透明字节，
SM3 只用于满足服务端的一致性校验。

这份文件是**独立实现**（不 import 仓库里任何被测代码，也不复用提交人的测试），
只按 docs/API.md 的线格式说话。
"""

from __future__ import annotations

import base64
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

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2


# ---------------------------------------------------------------- SM3（GB/T 32905）

def _rotl(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


_IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
       0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]


def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def sm3(data: bytes) -> bytes:
    bit_len = len(data) * 8
    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bit_len.to_bytes(8, "big")

    v = list(_IV)
    for off in range(0, len(msg), 64):
        block = msg[off:off + 64]
        w = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(16)]
        for j in range(16, 68):
            w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                     ^ _rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]

        a, b, c, d, e, f, g, h = v
        for j in range(64):
            t = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            if j < 16:
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | (~e & 0xFFFFFFFF & g)
            tt1 = (ff + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (gg + h + ss1 + w[j]) & 0xFFFFFFFF
            d, c, b, a = c, _rotl(b, 9), a, tt1
            h, g, f, e = g, _rotl(f, 19), e, _p0(tt2)
        v = [x ^ y for x, y in zip(v, [a, b, c, d, e, f, g, h])]
    return b"".join(x.to_bytes(4, "big") for x in v)


def sm3_hex(data: bytes) -> str:
    return sm3(data).hex()


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def ub64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- 用户码（CRYPTO-PACK §3.4）

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def derive_code(pub: bytes) -> str:
    """4 位用户码 = SM3(公钥) 前 20 bit 的 Crockford 编码。"""
    d = sm3(pub)
    v = (d[0] << 12) | (d[1] << 4) | (d[2] >> 4)
    return "".join(CROCKFORD[(v >> (15 - 5 * i)) & 0x1F] for i in range(4))


def keypair(label: str) -> tuple[str, bytes]:
    """确定性造一对（码, 未压缩公钥）——stub-allow 下不需要真私钥。"""
    pub = b"\x04" + sm3(b"gate-fixab:" + label.encode()) + sm3(b"gate-fixab-p2:" + label.encode())
    return derive_code(pub), pub


# ---------------------------------------------------------------- 进程 / psql

def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def with_search_path(dsn: str, schema: str) -> str:
    """把 search_path 作为 conninfo 参数追到 DSN 上（不改原有参数顺序）。

    为什么不用 PGOPTIONS：DSN 里若有 options=，conninfo 会盖掉环境变量，查询会静默落到
    public（踩过）。这里统一走 DSN，且补 `?`/`&` 分隔符，避免"原串必须自带 ?"的隐含前提。
    """
    sep = "&" if "?" in dsn else "?"
    return f"{dsn}{sep}options=-c%20search_path%3D{schema}"


def psql(dsn: str, sql: str, schema: str | None = None, timeout: float = 120) -> tuple[int, str]:
    """跑一条 psql。返回 (rc, stdout-or-stderr)。"""
    env = dict(os.environ)
    conn = with_search_path(dsn, schema) if schema else dsn
    p = subprocess.run(["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", conn, "-c", sql],
                       capture_output=True, text=True, env=env, timeout=timeout)
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    return p.returncode, out


class Server:
    """起一个真 yanshu-server（独立 schema / blob 目录 / 端口）。"""

    def __init__(self, binary: str, dsn: str, schema: str, work: Path,
                 sweep: str = "1s", secret: str = "gate-fixab-secret-0001"):
        self.binary, self.dsn, self.schema = binary, dsn, str(schema).lower()
        self.work = Path(work)
        self.sweep = sweep
        self.secret = secret
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None
        self.log = ""

    def _env(self) -> dict[str, str]:
        return dict(
            os.environ,
            YANSHU_ENV="test",
            YANSHU_DATABASE_URL=with_search_path(self.dsn, self.schema),
            YANSHU_BLOB_DIR=str(self.work / "blobs"),
            YANSHU_ADDR=f"127.0.0.1:{self.port}",
            YANSHU_VERIFIER="stub-allow",
            YANSHU_TOKEN_SECRET=self.secret,
            YANSHU_TOKEN_EPOCH="1",
            YANSHU_SWEEP_INTERVAL=self.sweep,
            YANSHU_LOG_DIR=str(self.work / "logs"),
        )

    def __enter__(self) -> "Server":
        (self.work / "blobs").mkdir(parents=True, exist_ok=True)
        (self.work / "logs").mkdir(parents=True, exist_ok=True)
        psql(self.dsn, f'drop schema if exists "{self.schema}" cascade')
        rc, out = psql(self.dsn, f'create schema "{self.schema}"')
        if rc != 0:
            print(f"[BLOCKED] 建 schema 失败：{out}", file=sys.stderr)
            raise SystemExit(EXIT_BLOCKED)
        self.proc = subprocess.Popen([self.binary], env=self._env(),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(150):
            if self.proc.poll() is not None:
                break
            try:
                with urllib.request.urlopen(f"{self.base}/healthz", timeout=1) as r:
                    if r.status == 200:
                        return self
            except Exception:  # noqa: BLE001  还没起好
                time.sleep(0.2)
        tail = ""
        if self.proc.poll() is not None:
            tail = (self.proc.stdout.read() or "")[-800:] if self.proc.stdout else ""
        print(f"[BLOCKED] 服务未起来（{self.base}/healthz）：{tail}", file=sys.stderr)
        raise SystemExit(EXIT_BLOCKED)

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.log = (self.proc.communicate(timeout=10)[0] or "")
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def __exit__(self, *exc) -> None:
        self.close()
        psql(self.dsn, f'drop schema if exists "{self.schema}" cascade')


# ---------------------------------------------------------------- HTTP 客户端

class Client:
    def __init__(self, base: str, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def call(self, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(self.base + path, data=body, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()

    def json(self, method: str, path: str, payload: dict | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], object]:
        body = json.dumps(payload).encode() if payload is not None else None
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        st, hd, raw = self.call(method, path, body, h)
        try:
            return st, hd, json.loads(raw) if raw else {}
        except Exception:  # noqa: BLE001
            return st, hd, {"_raw": raw.decode("utf-8", "replace")[:200]}

    # ---- 流程小件

    def challenge(self, purpose: str) -> str:
        st, _, b = self.json("POST", "/v1/challenges", {"purpose": purpose})
        if st != 200:
            raise RuntimeError(f"挑战失败 {st}: {b}")
        return b["challenge_id"]

    def auth(self, code: str, challenge_id: str) -> dict[str, str]:
        # stub-allow 只校验形状
        return {
            "X-YS-Code": code,
            "X-YS-Challenge-Id": challenge_id,
            "X-YS-Signature": b64u(b"\x30\x44" + b"\x00" * 66),
        }

    def register(self, label: str, nickname: str) -> tuple[str, bytes]:
        code, pub = keypair(label)
        ch = self.challenge("REGISTER")
        st, _, b = self.json("POST", "/v1/codes",
                             {"code": code, "public_key": b64u(pub), "nickname": nickname},
                             self.auth(code, ch))
        if st not in (200, 201):
            raise RuntimeError(f"注册 {code} 失败 {st}: {b}")
        return code, pub

    def create(self, sender: str, recipient: str, prelude_len: int,
               plaintext_size: int, chunk_size: int, chunk_count: int,
               prelude_sm3: str) -> dict:
        ch = self.challenge("TRANSFER_CREATE")
        st, _, b = self.json("POST", "/v1/transfers", {
            "recipient_code": recipient,
            "plaintext_size": plaintext_size,
            "chunk_size": chunk_size,
            "chunk_count": chunk_count,
            "prelude_len": prelude_len,
            "prelude_sm3": prelude_sm3,
        }, self.auth(sender, ch))
        if st not in (200, 201):
            raise RuntimeError(f"建传输失败 {st}: {b}")
        return b

    def put_prelude(self, tid: str, token: str, prelude: bytes) -> tuple[int, object]:
        st, _, raw = self.call("PUT", f"/v1/transfers/{tid}/prelude", prelude,
                               {"X-YS-Upload-Token": token,
                                "Content-Type": "application/octet-stream"})
        return st, _as_json(raw)

    def put_chunk(self, tid: str, token: str, index: int, data: bytes) -> tuple[int, object]:
        st, _, raw = self.call("PUT", f"/v1/transfers/{tid}/chunks/{index}", data,
                               {"X-YS-Upload-Token": token,
                                "Content-Type": "application/octet-stream"})
        return st, _as_json(raw)

    def complete(self, tid: str, token: str) -> tuple[int, object]:
        st, _, body = self.json("POST", f"/v1/transfers/{tid}/complete", {},
                                {"X-YS-Upload-Token": token})
        return st, body

    def revoke(self, sender: str, tid: str) -> tuple[int, object]:
        ch = self.challenge("TRANSFER_REVOKE")
        st, _, b = self.json("POST", f"/v1/transfers/{tid}/revoke", None, self.auth(sender, ch))
        return st, b


# ---------------------------------------------------------------- 结果落盘

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def err_code(body: object) -> str:
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return str(e.get("code") or "")
    return ""


def _as_json(raw: bytes):
    import json
    try:
        return json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001
        return {"_raw": raw[:200].decode("utf-8", "replace")}


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def dump(path: str | None, payload: dict) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text + "\n", encoding="utf-8")
        print(f"\n[json] {path}")
    else:
        print(text)


def require_dsn(arg: str | None) -> str:
    dsn = arg or os.environ.get("TEST_DATABASE_URL") or ""
    if not dsn:
        print("[BLOCKED] 缺少 --dsn / TEST_DATABASE_URL", file=sys.stderr)
        raise SystemExit(EXIT_BLOCKED)
    return dsn
