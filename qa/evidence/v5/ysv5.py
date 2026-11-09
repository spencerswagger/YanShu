#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 验收脚本共用件：SM3、最小 API 客户端、起一个真服务、psql 直查。

只依赖 python3 标准库 + `psql`（与 qa/evidence 其余脚本同一口径）。
不做加解密：`prelude` 与块都是**不透明字节**，SM3 只用于满足服务端的一致性校验。
"""

from __future__ import annotations

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

# ---------------------------------------------------------------- 退出码（与 qa/evidence 约定一致）
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2
EXIT_INCONCLUSIVE = 3
EXIT_PENDING = 4


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
    """纯 python SM3；与内核导出的 `ys_sm3` 逐字节一致（自检见 --selftest）。"""
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


# ---------------------------------------------------------------- 用户码（CRYPTO-PACK §3.4）

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def derive_code(pub: bytes) -> str:
    """4 位用户码 = SM3(公钥) 前 20 bit 的 Crockford 编码（与 `gm.DeriveCode` 同式）。"""
    d = sm3(pub)
    v = (d[0] << 12) | (d[1] << 4) | (d[2] >> 4)
    return "".join(CROCKFORD[(v >> (15 - 5 * i)) & 0x1F] for i in range(4))


def keypair(label: str) -> tuple[str, bytes]:
    """确定性造一对（码, 未压缩公钥）——stub-allow 下不需要真私钥。"""
    pub = b"\x04" + sm3(b"gate-v5:" + label.encode()) + sm3(b"gate-v5-p2:" + label.encode())
    return derive_code(pub), pub


def ub64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- psql / 进程

def psql(dsn: str, sql: str, schema: str | None = None) -> tuple[int, str]:
    env = dict(os.environ)
    conn = dsn
    if schema:
        if "options=" in dsn:
            # DSN 里已经带了 options（例如探"会话时区"风险时）——conninfo 的 options 会盖掉
            # PGOPTIONS，所以把 search_path 追加进同一个 options，别让它悄悄失效。
            conn = dsn + "%20-c%20search_path%3D" + schema
        else:
            env["PGOPTIONS"] = f"-c search_path={schema}"
    p = subprocess.run(["psql", "-X", "-A", "-t", conn, "-c", sql],
                       capture_output=True, text=True, env=env)
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    return p.returncode, out


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_http(url: str, proc: subprocess.Popen, tries: int = 120) -> int | None:
    for _ in range(tries):
        if proc.poll() is not None:
            return None
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                return r.status
        except Exception:  # noqa: BLE001  服务还没起好
            time.sleep(0.2)
    return None


class Server:
    """起一个真 `yanshu-server`（独立 schema + 独立 blob 目录 + 独立端口）。

    用法：
        with Server(binary=..., dsn=..., schema="gate_v5_ttl") as srv:
            c = Client(srv.base)
    """

    def __init__(self, binary: str, dsn: str, schema: str, work: Path,
                 sweep: str = "1s", keep: bool = False):
        self.binary, self.dsn, self.schema = binary, dsn, schema
        self.work = Path(work)
        self.sweep = sweep
        self.keep = keep
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None
        self.log = ""

    def env(self) -> dict[str, str]:
        return dict(
            os.environ,
            YANSHU_ENV="test",
            YANSHU_DATABASE_URL=f"{self.dsn}&search_path={self.schema}",
            YANSHU_BLOB_DIR=str(self.work / "blobs"),
            YANSHU_ADDR=f"127.0.0.1:{self.port}",
            YANSHU_VERIFIER="stub-allow",
            YANSHU_TOKEN_SECRET="gate-v5-evidence-secret-0001",
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
            raise SystemExit(f"建 schema 失败：{out}")
        self.proc = subprocess.Popen([self.binary], env=self.env(),
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
        st = wait_http(f"{self.base}/healthz", self.proc)
        if st != 200:
            self.close()
            raise SystemExit(f"服务未起来（healthz={st}）：{self.log[-400:]}")
        return self

    def blob_dir(self) -> Path:
        return self.work / "blobs"

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.log = (self.proc.communicate(timeout=10)[0] or "") + self.log
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if not self.keep:
            psql(self.dsn, f'drop schema if exists "{self.schema}" cascade')

    def __exit__(self, *exc) -> None:
        self.close()

    def sweep_log_lines(self) -> list[str]:
        """读 `YANSHU_LOG_DIR` 下当天的日志（UTC 日期）。"""
        day = time.strftime("%Y-%m-%d", time.gmtime())
        f = self.work / "logs" / f"yanshu-server-{day}.log"
        if not f.is_file():
            return []
        return f.read_text(encoding="utf-8", errors="replace").splitlines()


# ---------------------------------------------------------------- HTTP 客户端

class Client:
    def __init__(self, base: str, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.headers: dict[str, str] = {}

    def call(self, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict | bytes]:
        req = urllib.request.Request(self.base + path, data=body, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                self.headers = {k.lower(): v for k, v in r.headers.items()}
                if "json" in r.headers.get("content-type", "") and raw:
                    return r.status, json.loads(raw)
                return r.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            self.headers = {k.lower(): v for k, v in e.headers.items()}
            try:
                return e.code, json.loads(raw)
            except Exception:  # noqa: BLE001
                return e.code, raw

    def json(self, method: str, path: str, payload: dict | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict]:
        body = json.dumps(payload).encode() if payload is not None else None
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        st, out = self.call(method, path, body, h)
        return st, out if isinstance(out, dict) else {"_raw": out}

    # ---- 流程小件

    def challenge(self, purpose: str) -> str:
        st, b = self.json("POST", "/v1/challenges", {"purpose": purpose})
        if st != 200:
            raise RuntimeError(f"挑战失败 {st}: {b}")
        return b["challenge_id"]

    def auth(self, code: str, challenge_id: str) -> dict[str, str]:
        # stub-allow 只校验形状（真实验签要换真签名）
        return {
            "X-YS-Code": code,
            "X-YS-Challenge-Id": challenge_id,
            "X-YS-Signature": b64u(b"\x30\x44" + b"\x00" * 66),
        }

    def register(self, code: str, nickname: str, pub: bytes | None = None) -> None:
        if pub is None:
            pub = keypair(code)[1]
        ch = self.challenge("REGISTER")
        st, b = self.json("POST", "/v1/codes",
                          {"code": code, "public_key": b64u(pub), "nickname": nickname},
                          self.auth(code, ch))
        if st not in (200, 201):
            raise RuntimeError(f"注册 {code} 失败 {st}: {b}")

    def register_pair(self, label: str, nickname: str) -> tuple[str, bytes]:
        """按 label 造一对确定性身份并注册，返回 (码, 公钥)。"""
        code, pub = keypair(label)
        self.register(code, nickname, pub)
        return code, pub

    def inbox(self, code: str) -> tuple[int, dict]:
        ch = self.challenge("INBOX_LIST")
        return self.json("GET", "/v1/inbox", None, self.auth(code, ch))

    def create(self, sender: str, recipient: str, plaintext_size: int, chunk_size: int,
               chunk_count: int, prelude: bytes, ttl_seconds: int | None = None,
               max_downloads: int | None = None) -> dict:
        ch = self.challenge("TRANSFER_CREATE")
        payload = {
            "recipient_code": recipient,
            "plaintext_size": plaintext_size,
            "chunk_size": chunk_size,
            "chunk_count": chunk_count,
            "prelude_len": len(prelude),
            "prelude_sm3": b64u(sm3(prelude)),
        }
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        if max_downloads is not None:
            payload["max_downloads"] = max_downloads
        st, b = self.json("POST", "/v1/transfers", payload, self.auth(sender, ch))
        if st not in (200, 201):
            raise RuntimeError(f"建传输失败 {st}: {b}")
        return b

    def put_prelude(self, tid: str, token: str, prelude: bytes) -> tuple[int, dict]:
        st, out = self.call("PUT", f"/v1/transfers/{tid}/prelude", prelude,
                            {"X-YS-Upload-Token": token,
                             "Content-Type": "application/octet-stream"})
        return st, out if isinstance(out, dict) else {}

    def put_chunk(self, tid: str, token: str, index: int, data: bytes) -> tuple[int, dict]:
        st, out = self.call("PUT", f"/v1/transfers/{tid}/chunks/{index}", data,
                            {"X-YS-Upload-Token": token,
                             "Content-Type": "application/octet-stream"})
        return st, out if isinstance(out, dict) else {}

    def complete(self, tid: str, token: str) -> tuple[int, dict]:
        return self.json("POST", f"/v1/transfers/{tid}/complete", {},
                         {"X-YS-Upload-Token": token})

    def transfer(self, tid: str) -> tuple[int, dict]:
        return self.json("GET", f"/v1/transfers/{tid}")

    def get_prelude(self, tid: str) -> tuple[int, dict | bytes]:
        return self.call("GET", f"/v1/transfers/{tid}/prelude")

    def get_chunk(self, tid: str, index: int, download_id: str) -> tuple[int, dict | bytes]:
        return self.call("GET", f"/v1/transfers/{tid}/chunks/{index}",
                         None, {"X-YS-Download-Id": download_id})

    def ack(self, tid: str, code: str, download_id: str) -> tuple[int, dict]:
        ch = self.challenge("TRANSFER_ACK")
        return self.json("POST", f"/v1/transfers/{tid}/ack", {},
                         {"X-YS-Download-Id": download_id, **self.auth(code, ch)})

    def stats(self) -> tuple[int, dict]:
        return self.json("GET", "/v1/stats")

    def config(self) -> tuple[int, dict]:
        return self.json("GET", "/v1/config")


def make_transfer(c: Client, sender: str, recipient: str, *, size: int = 64 * 1024,
                  chunk_size: int = 64 * 1024, chunks: int = 1,
                  ttl_seconds: int | None = None, upload: bool = True,
                  max_downloads: int | None = None, prelude_len: int = 96) -> dict:
    """建一条传输（默认连同 prelude + 全部块一起传完并 complete）。

    返回 `{transfer_id, upload_token, prelude, chunks, created, completed}`。
    """
    prelude = bytes((i * 37 + 11) & 0xFF for i in range(prelude_len))
    created = c.create(sender, recipient, size, chunk_size, chunks, prelude,
                       ttl_seconds=ttl_seconds, max_downloads=max_downloads)
    tid, token = created["transfer_id"], created["upload_token"]
    out = {"transfer_id": tid, "upload_token": token, "prelude": prelude,
           "chunks": [], "created": created, "completed": None}
    if not upload:
        return out
    st, b = c.put_prelude(tid, token, prelude)
    if st not in (200, 201, 204):
        raise RuntimeError(f"传 prelude 失败 {st}: {b}")
    block = bytes((i * 91 + 7) & 0xFF for i in range(chunk_size + 16))
    for i in range(chunks):
        # 每块 16 字节 tag 占位 + 唯一化尾标，避免"块内容相同"掩盖搬运错误
        data = block[:chunk_size] + i.to_bytes(4, "big") + b"\x00" * 12
        st, b = c.put_chunk(tid, token, i, data)
        if st not in (200, 201, 204):
            raise RuntimeError(f"传块 {i} 失败 {st}: {b}")
        out["chunks"].append(data)
    st, b = c.complete(tid, token)
    if st not in (200, 201):
        raise RuntimeError(f"complete 失败 {st}: {b}")
    out["completed"] = b
    return out


def fetch_all(c: Client, tid: str) -> tuple[str, bytes | None]:
    """GET prelude 开租约 + 逐块取回；返回 (download_id, 是否逐字节一致)。"""
    st, prelude = c.get_prelude(tid)
    if st != 200:
        return "", None
    dl_id = c.headers.get("x-ys-download-id", "")
    return dl_id, prelude if isinstance(prelude, bytes) else b""


# ---------------------------------------------------------------- 结果输出

class Report:
    """统一的三态输出：PASS / FAIL / BLOCKED / PENDING（别把"没跑"当"通过"）。"""

    def __init__(self, title: str, subtitle: str = ""):
        self.title, self.subtitle = title, subtitle
        self.rows: list[tuple[str, str, str]] = []   # (名称, 结论, 证据)
        self.notes: list[str] = []

    def add(self, name: str, ok: bool | None, evidence: str = "") -> None:
        self.rows.append((name, "PASS" if ok is True else ("FAIL" if ok is False else "SKIP"),
                          evidence))

    def note(self, text: str) -> None:
        self.notes.append(text)

    def verdict(self) -> int:
        kinds = {k for _, k, _ in self.rows}
        if "FAIL" in kinds:
            return EXIT_FAIL
        if "SKIP" in kinds:
            return EXIT_INCONCLUSIVE
        return EXIT_PASS if self.rows else EXIT_PENDING

    def emit(self, json_out: str | None = None) -> int:
        v = self.verdict()
        line = "=" * 92
        print(line)
        print(self.title)
        if self.subtitle:
            print(self.subtitle)
        print(line)
        for name, kind, ev in self.rows:
            print(f"{kind:<4}  {name:<44} {ev[:120]}")
        for n in self.notes:
            print(f"note  {n}")
        print("-" * 92)
        n_pass = sum(1 for _, k, _ in self.rows if k == "PASS")
        print(f"{n_pass}/{len(self.rows)} 通过　结论："
              + {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL",
                 EXIT_INCONCLUSIVE: "INCONCLUSIVE（有项没跑，不算通过）",
                 EXIT_PENDING: "PENDING（参数/依赖缺失）"}[v])
        if json_out:
            Path(json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(json_out).write_text(json.dumps(
                {"title": self.title, "verdict": v,
                 "rows": [{"name": n, "kind": k, "evidence": e} for n, k, e in self.rows],
                 "notes": self.notes}, ensure_ascii=False, indent=2), encoding="utf-8")
        return v


def selftest() -> int:
    """SM3 对标准向量 + 与内核导出 `ys_sm3` 比对（有 --wasm 时才比）。"""
    cases = [
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"abcd" * 16, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
        (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
    ]
    bad = 0
    for data, want in cases:
        got = sm3_hex(data)
        ok = got == want
        print(f"{'PASS' if ok else 'FAIL'}  SM3({data[:8]!r}…) {got[:16]}…")
        bad += 0 if ok else 1
    wasm = os.environ.get("YS_KERNEL_WASM", "")
    probe = Path(__file__).resolve().parent.parent / "adapters" / "wasm_pack_probe.mjs"
    if wasm and Path(wasm).is_file():
        print(f"（内核交叉校验：{wasm} —— 由 `check_kernel_sm3.mjs` 负责，见 README）")
    return EXIT_PASS if bad == 0 else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(selftest())
