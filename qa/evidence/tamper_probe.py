#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""雁书 YanShu · Gate 证据二：密文篡改必报错（骨架版）

===============================================================================
这个脚本做什么
===============================================================================
拿一份**合法密文包**（`.yspk`，格式见 `docs/CRYPTO-PACK.md`），逐类构造破坏，
再交给「端侧解密入口」去解，验证它**明确报错**，而不是"尽力恢复"或返回部分明文：

  ① 翻转 1 个字节        —— 包头条（签名覆盖区）、块头区、数据区、tag 区
  ② 删除中间某块          —— 整条块记录删除；以及只删「密文+tag」留下块头
  ③ 交换两个块的顺序
  ④ 替换整块为另一包的合法块（`--donor` 提供第二个包）
  ⑤ 附带：截断尾块

它**不实现加解密**：解密一律外派给你配置的端侧入口。脚本只负责
「解析 → 构造破坏 → 调用 → 判定 → 打印证据」。

===============================================================================
判定口径
===============================================================================
* **baseline（对照）**：未篡改的包必须先能**解密成功**。基线不过 → 直接 BLOCKED，
  因为一个"什么都解不开"的解密器会让后面每条篡改都假 PASS。
* 每条篡改：解密返回明确错误 = PASS；解密成功 = FAIL（含"返回部分明文"）。
* 全 PASS 退出码 0；任何一条 FAIL 退出码 1；配置/依赖问题 2。

===============================================================================
执行路径（按就绪程度选，输出会标明走的是哪条）
===============================================================================
    --backend cmd          生产/半生产入口：你自己的 CLI 或测试二进制
                           契约：`{in}` 换成密文路径；解密成功 exit 0；
                           失败 exit≠0，并把错误码（`CRYPTO_*`）打到 stdout/stderr
    --backend cargo-test   端侧 crate 的测试函数（Rune 未导出 CLI 时用它）
                           契约：cargo test 用两个过滤器，一个断言"合法包能解"、
                           一个断言"篡改包必须报错"；退出码 0 = 断言成立
    --backend selftest     自测替身（合成完整性校验，**不是密码学**），只用来
                           证明本脚本的构造与判定逻辑没问题，不能当证据用
    --backend always-ok    恒成功替身，测试专用：证明"解密成功会被判 FAIL"

若用的是 `cargo-test` / `selftest` / `always-ok`，输出会明确打印
「当前走的是测试入口而非生产导出路径」。

===============================================================================
用法
===============================================================================
    # 0) 自测（不需要 Rune，也不需要网络）
    python3 qa/evidence/tamper_probe.py --selftest

    # 1) 用契约样例包自检解析与构造（不跑解密）
    python3 qa/evidence/tamper_probe.py --fixture builtin --backend selftest --dry-run

    # 2) 等 Rune 就绪后：真实入口 + 真实包
    python3 qa/evidence/tamper_probe.py \
        --envelope /tmp/a.yspk --donor /tmp/b.yspk \
        --backend cmd \
        --decrypt-cmd 'rune-cli decrypt --in {in} --key ~/.yanshu/key.bin'

    # 3) 走 Rune crate 的测试函数
    python3 qa/evidence/tamper_probe.py --envelope /tmp/a.yspk \
        --backend cargo-test --rune-crate ../YS-RUNE/crates/rune \
        --cargo-test-error-filter tamper_rejects \
        --cargo-test-ok-filter accepts_valid

环境变量：YS_ENVELOPE / YS_DONOR / YS_DECRYPT_CMD / YS_RUNE_CRATE

===============================================================================
当前骨架状态（2026-11-02 首夜）
===============================================================================
可直接跑： 契约样例解析、四类篡改构造、判定逻辑、自测、cargo/cmd 后端接线
缺依赖未闭环：
  * Rune 尚未导出 CLI/测试二进制 → 只能用 `--backend selftest` 自证逻辑；
    真实证据要等 Rune 给出解密入口（或 `cargo-test` 的两个过滤器）。
  * 真实 `.yspk` 样本要等端侧加密可用（或用 §12 从服务端 prelude+切片重组）。
  * `docs/API.md` 未落盘 → 不做"从服务端拉包"这条分支（见 TODO）。
===============================================================================
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

# --------------------------------------------------------------------------- #
# CRYPTO-PACK 常量（v1，冻结）
# --------------------------------------------------------------------------- #

HEADER_LEN = 112
MIN_CHUNK_SIZE = 16
MAX_CHUNK_SIZE = 1048576
TAG_LEN = 16
CHUNK_HDR_LEN = 16
WALKED_WRAPPED_KEY_LEN = 129
UNCOMPRESSED_PUB_LEN = 65

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2

HERE = Path(__file__).resolve().parent
FIXTURE_HEX = HERE / "fixtures" / "yspk-contract-v2.hex"
FIXTURE_HEX_V1 = HERE / "fixtures" / "yspk-contract-v1.hex"


# --------------------------------------------------------------------------- #
# 包结构解析
# --------------------------------------------------------------------------- #

class EnvelopeError(Exception):
    """结构层面的拒绝；code 用 CRYPTO-PACK §13 的端侧错误码。"""

    def __init__(self, code: str, msg: str):
        super().__init__(f"{code}: {msg}")
        self.code = code
        self.msg = msg


def _u8(b: bytes, o: int) -> int:
    return b[o]


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from(">H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from(">Q", b, o)[0]


@dataclass
class ChunkRec:
    seq: int            # 在块区里的序号
    rec_off: int        # 整条记录的起始偏移
    rec_len: int        # 16 + ct_len + 16
    index_field: int    # 块头里声明的 CHUNK_INDEX
    pt_len: int
    ct_len: int
    last_flag: int

    @property
    def ct_off(self) -> int:
        return self.rec_off + CHUNK_HDR_LEN

    @property
    def tag_off(self) -> int:
        return self.ct_off + self.ct_len


@dataclass
class Envelope:
    raw: bytes
    version: tuple[int, int]
    flags: int
    chunk_size: int
    chunk_count: int
    plaintext_size: int
    wrapped_key_len: int
    manifest_len: int
    manifest_pt_len: int
    sender_pub_len: int
    sig_len: int
    prelude_len: int
    chunks: list[ChunkRec] = field(default_factory=list)

    def summary(self) -> str:
        lens = ",".join(str(c.rec_len) for c in self.chunks[:8])
        more = "" if len(self.chunks) <= 8 else ",…"
        return (f"{len(self.raw):,}B · YSPK {self.version[0]}.{self.version[1]} · "
                f"CHUNK_SIZE={self.chunk_size} · CHUNK_COUNT={self.chunk_count} · "
                f"PT={self.plaintext_size}B · PRELUDE={self.prelude_len}B · "
                f"块记录长度=[{lens}{more}]")


def parse_envelope(data: bytes, strict: bool = True) -> Envelope:
    """按 CRYPTO-PACK §4/§5/§6 解析。strict=False 只解析到能定位块区为止。"""
    if len(data) < HEADER_LEN:
        raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT", f"短于 {HEADER_LEN} 字节的头")
    if data[0:4] != b"YSPK":
        raise EnvelopeError("CRYPTO_MAGIC_MISMATCH", f"MAGIC={data[0:4]!r}")
    version = (data[4], data[5])
    if version != (1, 0):
        raise EnvelopeError("CRYPTO_VERSION_UNSUPPORTED", f"版本 {version}")
    if _u16(data, 6) != HEADER_LEN:
        raise EnvelopeError("CRYPTO_HEADER_INVALID", f"HEADER_LEN={_u16(data, 6)}")

    env = Envelope(
        raw=data,
        version=version,
        flags=_u32(data, 8),
        chunk_size=_u32(data, 16),
        chunk_count=_u32(data, 20),
        plaintext_size=_u64(data, 24),
        wrapped_key_len=_u64(data, 32),
        manifest_len=_u64(data, 40),
        manifest_pt_len=_u32(data, 48),
        sender_pub_len=_u32(data, 52),
        sig_len=_u64(data, 72),
        prelude_len=0,
    )
    if not (MIN_CHUNK_SIZE <= env.chunk_size <= MAX_CHUNK_SIZE):
        raise EnvelopeError("CRYPTO_HEADER_INVALID", f"CHUNK_SIZE={env.chunk_size}")
    if not (1 <= env.chunk_count <= 1048576):
        raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT", f"CHUNK_COUNT={env.chunk_count}")
    if env.manifest_len != env.manifest_pt_len + TAG_LEN:
        raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT",
                            f"MANIFEST_LEN={env.manifest_len} vs PT={env.manifest_pt_len}+16")
    if env.wrapped_key_len != WALKED_WRAPPED_KEY_LEN:
        raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT", f"WRAPPED_KEY_LEN={env.wrapped_key_len}")
    if env.sender_pub_len != UNCOMPRESSED_PUB_LEN:
        raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT", f"SENDER_PUB_LEN={env.sender_pub_len}")

    env.prelude_len = (HEADER_LEN + env.sender_pub_len + env.wrapped_key_len
                       + env.manifest_len + env.sig_len)
    if env.prelude_len > len(data):
        raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT",
                            f"PRELUDE_LEN={env.prelude_len} 超出包长 {len(data)}")

    off = env.prelude_len
    for i in range(env.chunk_count):
        if off + CHUNK_HDR_LEN + TAG_LEN > len(data):
            raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT",
                                f"第 {i} 块记录越界（off={off}，包长={len(data)}）")
        hdr = data[off:off + CHUNK_HDR_LEN]
        idx, pt, ct, last = _u32(hdr, 0), _u32(hdr, 4), _u32(hdr, 8), hdr[12]
        rec_len = CHUNK_HDR_LEN + ct + TAG_LEN
        if off + rec_len > len(data):
            raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT",
                                f"第 {i} 块密文越界（CT_LEN={ct}）")
        rec = ChunkRec(i, off, rec_len, idx, pt, ct, last)
        env.chunks.append(rec)
        off += rec_len
        if strict:
            if ct != pt:
                raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT",
                                    f"第 {i} 块 CT_LEN={ct} != PT_LEN={pt}")
            if idx != i:
                raise EnvelopeError("CRYPTO_CHUNK_ORDER", f"第 {i} 块 CHUNK_INDEX={idx}")
            want_last = 1 if i == env.chunk_count - 1 else 0
            if last != want_last:
                raise EnvelopeError("CRYPTO_CHUNK_ORDER",
                                    f"第 {i} 块 LAST_FLAG={last}（应为 {want_last}）")
            if hdr[13:16] != b"\x00\x00\x00":
                raise EnvelopeError("CRYPTO_HEADER_INVALID", f"第 {i} 块 RESERVED 非 0")

    if strict:
        if off != len(data):
            raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT",
                                f"包尾多出 {len(data) - off} 字节（ENVELOPE_LEN={off}）")
        expect = -(-env.plaintext_size // env.chunk_size) if env.chunk_size else 0
        if env.chunk_count != max(1, expect):
            raise EnvelopeError("CRYPTO_LENGTH_INCONSISTENT",
                                f"CHUNK_COUNT={env.chunk_count} 与 ceil(PT/CHUNK_SIZE)={expect} 不符")
    return env


# --------------------------------------------------------------------------- #
# 篡改构造
# --------------------------------------------------------------------------- #

@dataclass
class Tamper:
    case: str
    desc: str
    data: bytes | None = None
    skip: str = ""


def _middle(env: Envelope) -> ChunkRec:
    return env.chunks[len(env.chunks) // 2]


def _xor(buf: bytes, off: int, mask: int = 0x01) -> bytes:
    b = bytearray(buf)
    b[off] ^= mask
    return bytes(b)


def t_flip_envelope_header(env: Envelope, _donor: Envelope | None) -> Tamper:
    off = 56  # KDF_SALT 首字节，位于 HDR_CORE（签名覆盖区）
    return Tamper("flip-envelope-header", f"HEADER[{off}]^=0x01（KDF_SALT，签名覆盖区）",
                  _xor(env.raw, off))


def t_flip_chunk_header(env: Envelope, _donor: Envelope | None) -> Tamper:
    rec = _middle(env)
    off = rec.rec_off  # CHUNK_INDEX 低字节
    return Tamper("flip-chunk-header", f"块[{rec.seq}] 块头 CHUNK_INDEX 末字节 ^=0x01",
                  _xor(env.raw, off))


def t_flip_chunk_data(env: Envelope, _donor: Envelope | None) -> Tamper:
    rec = _middle(env)
    off = rec.ct_off + max(0, rec.ct_len // 2)
    return Tamper("flip-chunk-data", f"块[{rec.seq}] 密文中间 1 字节 ^=0x01",
                  _xor(env.raw, off))


def t_flip_chunk_tag(env: Envelope, _donor: Envelope | None) -> Tamper:
    rec = _middle(env)
    off = rec.tag_off + 3
    return Tamper("flip-chunk-tag", f"块[{rec.seq}] GCM tag 中间 1 字节 ^=0x01",
                  _xor(env.raw, off))


def t_drop_middle_chunk(env: Envelope, _donor: Envelope | None) -> Tamper:
    if len(env.chunks) < 2:
        return Tamper("drop-middle-chunk", "删除中间块", skip="包只有 1 块，没有'中间块'")
    rec = _middle(env)
    data = env.raw[:rec.rec_off] + env.raw[rec.rec_off + rec.rec_len:]
    return Tamper("drop-middle-chunk",
                  f"删除块[{rec.seq}] 整条记录（{rec.rec_len}B，包长 {len(env.raw)}→{len(data)}）",
                  data)


def t_drop_chunk_slice(env: Envelope, _donor: Envelope | None) -> Tamper:
    if len(env.chunks) < 2:
        return Tamper("drop-chunk-slice", "只删密文+tag", skip="包只有 1 块")
    rec = _middle(env)
    data = env.raw[:rec.ct_off] + env.raw[rec.ct_off + rec.ct_len + TAG_LEN:]  # 留块头，块头声明不变
    return Tamper("drop-chunk-slice",
                  f"删除块[{rec.seq}] 的密文+tag（留块头，制造 CT_LEN 不一致）", data)


def t_swap_chunks(env: Envelope, _donor: Envelope | None) -> Tamper:
    if len(env.chunks) < 2:
        return Tamper("swap-chunks", "交换两块顺序", skip="包只有 1 块")
    a, b = env.chunks[0], env.chunks[1]
    if a.rec_len != b.rec_len:
        return Tamper("swap-chunks", "交换两块顺序",
                      skip=f"块[{a.seq}]/[{b.seq}] 长度不同（{a.rec_len}/{b.rec_len}），交换即改变包长，另案")
    seg_a = env.raw[a.rec_off:a.rec_off + a.rec_len]
    seg_b = env.raw[b.rec_off:b.rec_off + b.rec_len]
    data = env.raw[:a.rec_off] + seg_b + seg_a + env.raw[b.rec_off + b.rec_len:]
    return Tamper("swap-chunks", f"交换块[{a.seq}] 与块[{b.seq}]（等长 {a.rec_len}B）", data)


def t_splice_donor_chunk(env: Envelope, donor: Envelope | None) -> Tamper:
    if len(env.chunks) < 2:
        return Tamper("splice-donor-chunk", "用另一包的合法块替换", skip="包只有 1 块")
    if donor is None:
        return Tamper("splice-donor-chunk", "用另一包的合法块替换", skip="未提供 --donor")
    rec = _middle(env)
    if rec.seq >= len(donor.chunks):
        return Tamper("splice-donor-chunk", "用另一包的合法块替换",
                      skip=f"donor 只有 {len(donor.chunks)} 块，没有第 {rec.seq} 块")
    drec = donor.chunks[rec.seq]
    if drec.rec_len != rec.rec_len:
        return Tamper("splice-donor-chunk", "用另一包的合法块替换",
                      skip=f"donor 块[{rec.seq}] 长度 {drec.rec_len} ≠ 目标 {rec.rec_len}")
    seg = donor.raw[drec.rec_off:drec.rec_off + drec.rec_len]
    data = env.raw[:rec.rec_off] + seg + env.raw[rec.rec_off + rec.rec_len:]
    return Tamper("splice-donor-chunk",
                  f"块[{rec.seq}] 整条替换为 donor 的块[{rec.seq}]（{rec.rec_len}B，合法块）", data)


def t_truncate_tail(env: Envelope, _donor: Envelope | None) -> Tamper:
    if len(env.chunks) < 2:
        return Tamper("truncate-tail", "截断尾块", skip="包只有 1 块")
    last = env.chunks[-1]
    data = env.raw[:last.rec_off]
    return Tamper("truncate-tail", f"截掉尾块[{last.seq}]（{last.rec_len}B）", data)


REQUIRED_CASES: list[tuple[str, Callable[[Envelope, Envelope | None], Tamper]]] = [
    ("flip-envelope-header", t_flip_envelope_header),
    ("flip-chunk-header", t_flip_chunk_header),
    ("flip-chunk-data", t_flip_chunk_data),
    ("drop-middle-chunk", t_drop_middle_chunk),
    ("swap-chunks", t_swap_chunks),
    ("splice-donor-chunk", t_splice_donor_chunk),
]

EXTRA_CASES: list[tuple[str, Callable[[Envelope, Envelope | None], Tamper]]] = [
    ("flip-chunk-tag", t_flip_chunk_tag),
    ("drop-chunk-slice", t_drop_chunk_slice),
    ("truncate-tail", t_truncate_tail),
]

ALL_CASES = {name: fn for name, fn in REQUIRED_CASES + EXTRA_CASES}


# --------------------------------------------------------------------------- #
# 解密后端
# --------------------------------------------------------------------------- #

class Backend:
    label = "unknown"
    production = False          # 是否生产导出路径
    note = ""

    def decrypt_succeeds(self, data: bytes) -> tuple[bool | None, str]:
        """未篡改的包能否解密成功。None = 该后端不提供正向用例。"""
        raise NotImplementedError

    def decrypt_fails(self, data: bytes) -> tuple[bool, str]:
        """篡改后的包是否**明确报错**。True = 报错（符合预期）。"""
        raise NotImplementedError


class SelftestBackend(Backend):
    """自测替身：结构校验 + 合成完整性摘要（**不是密码学**，不能当证据）。"""

    label = "selftest"
    production = False
    note = "合成完整性校验，只验证脚本逻辑，不是密码学证据"

    def __init__(self, pristine: bytes):
        self._digest = hashlib.sha256(pristine).digest()

    def _check(self, data: bytes) -> tuple[bool, str]:
        try:
            parse_envelope(data)
        except EnvelopeError as exc:
            return False, exc.code
        if hashlib.sha256(data).digest() != self._digest:
            return False, "CRYPTO_CHUNK_AUTH_FAILED"
        return True, ""

    def decrypt_succeeds(self, data: bytes) -> tuple[bool | None, str]:
        ok, detail = self._check(data)
        return ok, detail

    def decrypt_fails(self, data: bytes) -> tuple[bool, str]:
        ok, detail = self._check(data)
        return (not ok), (detail or "解密成功")


class AlwaysOkBackend(Backend):
    """测试专用：恒成功。用来证明判定逻辑不会把'解密成功'放过。"""

    label = "always-ok"
    production = False
    note = "测试替身：永远报告解密成功"

    def decrypt_succeeds(self, data: bytes) -> tuple[bool | None, str]:
        return True, ""

    def decrypt_fails(self, data: bytes) -> tuple[bool, str]:
        return False, "解密成功（恒成功替身）"


class CmdBackend(Backend):
    """外部命令后端：解密成功 exit 0；失败 exit≠0 且打印错误码。"""

    production = True
    label = "cmd"

    def __init__(self, template: str, error_regex: str = r"CRYPTO_[A-Z0-9_]+",
                 timeout: float = 120.0):
        self.template = template
        self.error_regex = re.compile(error_regex)
        self.timeout = timeout
        self.note = template

    def _run(self, data: bytes, workdir: str, tag: str) -> tuple[int, str, bool]:
        path = os.path.join(workdir, f"probe-{tag}.yspk")
        with open(path, "wb") as f:
            f.write(data)
        cmd = (self.template
               .replace("{in}", shlex.quote(path))
               .replace("{out}", shlex.quote(os.path.join(workdir, f"probe-{tag}.out"))))
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=self.timeout)
        text = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        m = self.error_regex.search(text)
        if m:
            return proc.returncode, m.group(0), True
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        return proc.returncode, first[:160], False

    def decrypt_succeeds(self, data: bytes) -> tuple[bool | None, str]:
        with tempfile.TemporaryDirectory(prefix="ys-probe-") as wd:
            rc, detail, _matched = self._run(data, wd, "baseline")
        return rc == 0, detail

    def decrypt_fails(self, data: bytes) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory(prefix="ys-probe-") as wd:
            rc, detail, matched = self._run(data, wd, "tamper")
        if rc == 0:
            return False, "解密命令返回 0（视为成功解密）"
        if not matched:
            # 只凭退出码判定，如实标注，别把"程序崩了"当成"明确报错"
            return True, f"退出码 {rc}（未取到 CRYPTO_* 错误码：{detail or '-'}）"
        return True, detail


class CargoTestBackend(Backend):
    """直接调 Rune crate 的测试函数（Rune 未导出 CLI 时用）。

    契约（需要 Rune 配合提供两个测试过滤器）：
      * error-filter：断言"篡改包解密必须报错"，测试通过 → 说明确实报错了
      * ok-filter   ：断言"合法包能解密"，测试通过 → baseline 成立
    通过环境变量 `YS_TAMPER_ENVELOPE` 传密文路径。
    """

    production = False
    label = "cargo-test"

    def __init__(self, crate: str, error_filter: str, ok_filter: str | None,
                 timeout: float = 600.0):
        self.crate = crate
        self.error_filter = error_filter
        self.ok_filter = ok_filter
        self.timeout = timeout
        self.note = f"crate={crate} filter={error_filter}"
        if not (Path(crate) / "Cargo.toml").is_file():
            raise EnvelopeError("BLOCKED", f"Rune crate 不在这里：{crate}/Cargo.toml")

    def _run(self, data: bytes, filt: str) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory(prefix="ys-cargo-") as wd:
            path = os.path.join(wd, "probe.yspk")
            with open(path, "wb") as f:
                f.write(data)
            env = dict(os.environ, YS_TAMPER_ENVELOPE=path)
            proc = subprocess.run(
                ["cargo", "test", "--manifest-path", str(Path(self.crate) / "Cargo.toml"),
                 filt, "--", "--exact", "--nocapture"],
                capture_output=True, text=True, env=env, timeout=self.timeout)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        m = re.search(r"CRYPTO_[A-Z0-9_]+", out)
        detail = m.group(0) if m else (out.splitlines()[-1][:160] if out else f"退出码 {proc.returncode}")
        return proc.returncode == 0, detail

    def decrypt_succeeds(self, data: bytes) -> tuple[bool | None, str]:
        if not self.ok_filter:
            return None, "未配置 --cargo-test-ok-filter，baseline 未验证"
        return self._run(data, self.ok_filter)

    def decrypt_fails(self, data: bytes) -> tuple[bool, str]:
        passed, detail = self._run(data, self.error_filter)
        if passed:
            return True, detail
        return False, f"Rune 的'{self.error_filter}'断言未成立：{detail}"


def build_backend(args, pristine: bytes) -> Backend:
    if args.backend == "selftest":
        return SelftestBackend(pristine)
    if args.backend == "always-ok":
        return AlwaysOkBackend()
    if args.backend == "cmd":
        if not args.decrypt_cmd:
            raise EnvelopeError("BLOCKED", "--backend cmd 需要 --decrypt-cmd（或 YS_DECRYPT_CMD）")
        return CmdBackend(args.decrypt_cmd, args.error_regex, args.timeout)
    if args.backend == "cargo-test":
        crate = args.rune_crate or ""
        if not crate:
            raise EnvelopeError("BLOCKED", "--backend cargo-test 需要 --rune-crate（或 YS_RUNE_CRATE）")
        return CargoTestBackend(crate, args.cargo_test_error_filter,
                                args.cargo_test_ok_filter, args.timeout)
    raise EnvelopeError("BLOCKED", f"未知后端 {args.backend}")


# --------------------------------------------------------------------------- #
# 执行与判定
# --------------------------------------------------------------------------- #

@dataclass
class CaseResult:
    case: str
    desc: str
    status: str        # PASS / FAIL / SKIP
    expect: str
    detail: str
    artifact: str = ""


def execute(backend: Backend, pristine: bytes, donor: bytes | None,
            case_names: Sequence[str], out_dir: str | None, keep: bool,
            log=print) -> tuple[list[CaseResult], int]:
    env = parse_envelope(pristine)
    env_donor = parse_envelope(donor) if donor else None
    results: list[CaseResult] = []

    run_dir = out_dir or tempfile.mkdtemp(prefix="ys-tamper-")
    if out_dir:
        Path(out_dir).mkdir(parents=True, exist_ok=True)

    # ---- baseline 对照 ----
    ok, detail = backend.decrypt_succeeds(pristine)
    if ok is None:
        results.append(CaseResult("baseline", "未篡改的包", "SKIP", "ok", detail))
    elif ok:
        results.append(CaseResult("baseline", "未篡改的包", "PASS", "ok", "解密成功"))
    else:
        results.append(CaseResult("baseline", "未篡改的包", "FAIL", "ok", detail))
        log("[BLOCKED] baseline 都解不开，后面的篡改证据没有意义（先修解密入口）")
        return results, EXIT_BLOCKED

    # ---- 逐条篡改 ----
    for name in case_names:
        fn = ALL_CASES[name]
        t = fn(env, env_donor)
        if t.skip or t.data is None:
            results.append(CaseResult(name, t.desc, "SKIP", "error", t.skip))
            continue
        artifact = ""
        if t.data is not None:
            path = os.path.join(run_dir, f"{name}.yspk")
            Path(path).write_bytes(t.data)
            artifact = path
        failed_ok, why = backend.decrypt_fails(t.data)
        status = "PASS" if failed_ok else "FAIL"
        if not failed_ok:
            why = f"解密成功/未明确报错：{why}"
        results.append(CaseResult(name, t.desc, status, "error", why, artifact))

    if not keep and not out_dir:
        shutil.rmtree(run_dir, ignore_errors=True)

    code = EXIT_PASS
    if any(r.status == "FAIL" for r in results):
        code = EXIT_FAIL
    return results, code


def print_report(backend: Backend, env_summary: str, results: Sequence[CaseResult],
                 started: float) -> None:
    print()
    print("=" * 104)
    print(f"后端：{backend.label}    {('生产/半生产导出路径' if backend.production else '⚠ 当前走的是测试入口而非生产导出路径')}")
    if backend.note:
        print(f"说明：{backend.note}")
    print(f"包  ：{env_summary}")
    print("=" * 104)
    print(f"{'用例':<24}{'结果':<7}{'期望':<7}说明")
    print("-" * 104)
    for r in results:
        print(f"{r.case:<24}{r.status:<7}{r.expect:<7}{r.detail}")
        if r.desc:
            print(f"{'':<24}{'':<7}{'':<7}↳ {r.desc}")
    print("-" * 104)
    n_pass = sum(1 for r in results if r.status == "PASS")
    n_fail = sum(1 for r in results if r.status == "FAIL")
    n_skip = sum(1 for r in results if r.status == "SKIP")
    print(f"合计：PASS {n_pass} / FAIL {n_fail} / SKIP {n_skip}    耗时 {time.time() - started:.2f}s")
    if n_fail:
        print("结论：FAIL —— 至少一类篡改没有被明确报错")
    else:
        print("结论：PASS —— 所有篡改均被明确拒绝")


# --------------------------------------------------------------------------- #
# 样例包
# --------------------------------------------------------------------------- #

def load_fixture(path: Path | None = None) -> bytes:
    path = path or FIXTURE_HEX
    if not path.is_file():
        raise EnvelopeError("BLOCKED", f"契约样例缺失：{path}")
    hexstr = "".join(
        ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    )
    return bytes.fromhex(hexstr)


def build_synthetic_envelope(chunk_pt_lens: Sequence[int], chunk_size: int = 32) -> bytes:
    """造一个**结构合法**的假包（内容随机），只用于解析/构造/判定自测。

    不含任何真实密钥：WRAPPED_KEY / SIG / tag 全是随机字节，密码学上无效。
    """
    n = len(chunk_pt_lens)
    total = sum(chunk_pt_lens)
    manifest_pt = os.urandom(174)
    manifest_len = len(manifest_pt) + TAG_LEN
    sig = os.urandom(71)
    sender_pub = b"\x04" + os.urandom(64)
    wrapped = os.urandom(WALKED_WRAPPED_KEY_LEN)
    header = bytearray(HEADER_LEN)
    header[0:4] = b"YSPK"
    header[4:6] = bytes([1, 0])
    struct.pack_into(">H", header, 6, HEADER_LEN)
    struct.pack_into(">I", header, 8, 0x00000002)           # FLAGS: SENDER_SIGNED
    header[12:16] = bytes([1, 1, 1, 1])
    struct.pack_into(">I", header, 16, chunk_size)
    struct.pack_into(">I", header, 20, n)
    struct.pack_into(">Q", header, 24, total)
    struct.pack_into(">Q", header, 32, len(wrapped))
    struct.pack_into(">Q", header, 40, manifest_len)
    struct.pack_into(">I", header, 48, len(manifest_pt))
    struct.pack_into(">I", header, 52, len(sender_pub))
    header[56:72] = os.urandom(16)                          # KDF_SALT
    struct.pack_into(">Q", header, 72, len(sig))
    # RESERVED 已全 0
    out = bytearray(header) + sender_pub + wrapped + manifest_pt + os.urandom(TAG_LEN) + sig
    for i, pt_len in enumerate(chunk_pt_lens):
        rec = bytearray(CHUNK_HDR_LEN)
        struct.pack_into(">I", rec, 0, i)
        struct.pack_into(">I", rec, 4, pt_len)
        struct.pack_into(">I", rec, 8, pt_len)
        rec[12] = 1 if i == n - 1 else 0
        out += rec + os.urandom(pt_len) + os.urandom(TAG_LEN)
    return bytes(out)


# --------------------------------------------------------------------------- #
# 自测
# --------------------------------------------------------------------------- #

def _selftest() -> int:
    results: list[tuple[str, bool, str]] = []

    def case(name, fn):
        try:
            results.append((name, True, str(fn() or "")))
        except AssertionError as exc:
            results.append((name, False, str(exc)))
        except Exception as exc:  # noqa: BLE001
            results.append((name, False, f"{type(exc).__name__}: {exc}"))

    def c_fixture():
        raw = load_fixture()
        env = parse_envelope(raw)
        assert len(raw) == 743, f"契约样例应为 743 字节，实为 {len(raw)}"
        assert env.chunk_count == 3, env.chunk_count
        assert env.prelude_len == 567, env.prelude_len
        assert [c.rec_len for c in env.chunks] == [64, 64, 48], [c.rec_len for c in env.chunks]
        assert env.chunk_size == 32 and env.plaintext_size == 80
        return f"743B / 3 块 / PRELUDE=567 / 块长=[64,64,48]"

    def c_fixture_v1():
        raw = load_fixture(FIXTURE_HEX_V1)
        env = parse_envelope(raw)
        assert len(raw) == 522, len(raw)
        assert env.chunk_count == 1 and env.chunk_size == 1048576, (env.chunk_count, env.chunk_size)
        assert env.chunks[0].rec_len == 37 and env.chunks[0].last_flag == 1
        return "522B / 1 块 / CHUNK_SIZE=1MiB"

    def c_synthetic():
        for lens in ([32], [32, 32], [32, 32, 16], [1]):
            raw = build_synthetic_envelope(lens)
            env = parse_envelope(raw)
            assert env.chunk_count == len(lens)
        return "1/2/3 块合成包均可解析"

    def c_baseline_and_tamper():
        raw = load_fixture()
        donor = build_synthetic_envelope([32, 32, 16])
        names = [n for n, _ in REQUIRED_CASES]
        res, code = execute(SelftestBackend(raw), raw, donor, names, None, False, log=lambda *_: None)
        assert res[0].case == "baseline" and res[0].status == "PASS", res[0]
        bad = [r for r in res[1:] if r.status != "PASS"]
        assert not bad, f"以下篡改未被判为报错：{[(r.case, r.detail) for r in bad]}"
        assert code == EXIT_PASS, code
        codes = {r.case: r.detail for r in res[1:]}
        return "baseline PASS；" + "，".join(f"{k}={v}" for k, v in codes.items())

    def c_extra_cases():
        raw = load_fixture()
        donor = build_synthetic_envelope([32, 32, 16])
        names = [n for n, _ in EXTRA_CASES]
        res, code = execute(SelftestBackend(raw), raw, donor, names, None, False, log=lambda *_: None)
        bad = [r for r in res if r.case != "baseline" and r.status != "PASS"]
        assert not bad, f"附加用例有漏网：{[(r.case, r.detail) for r in bad]}"
        assert code == EXIT_PASS
        return "3 条附加用例全部被拒绝"

    def c_judge_not_vacuous():
        raw = load_fixture()
        names = [n for n, _ in REQUIRED_CASES]
        res, code = execute(AlwaysOkBackend(), raw, None, names, None, False, log=lambda *_: None)
        fails = [r for r in res if r.status == "FAIL"]
        assert fails, "恒成功后端竟然全 PASS —— 判定逻辑是空转"
        assert code == EXIT_FAIL, code
        return f"恒成功后端被判 {len(fails)} 条 FAIL（判定逻辑有效）"

    def c_single_chunk_skip():
        raw = build_synthetic_envelope([32])
        res, code = execute(SelftestBackend(raw), raw, None,
                            ["drop-middle-chunk", "swap-chunks"], None, False, log=lambda *_: None)
        skips = [r for r in res if r.status == "SKIP"]
        assert len(skips) == 2, f"单块包应 SKIP 而非崩：{[(r.case, r.status) for r in res]}"
        assert code == EXIT_PASS
        return "单块包自动 SKIP，不误判不崩"

    def c_parse_rejects():
        raw = load_fixture()
        try:
            parse_envelope(raw[:200])
        except EnvelopeError as exc:
            assert exc.code.startswith("CRYPTO_"), exc.code
            return f"截断包被拒：{exc.code}"
        raise AssertionError("截断包竟然解析通过")

    def c_error_summary():
        raw = load_fixture()
        res, _ = execute(SelftestBackend(raw), raw, None, ["flip-chunk-data"], None, False,
                         log=lambda *_: None)
        tamper = [r for r in res if r.case == "flip-chunk-data"][0]
        assert tamper.detail.startswith("CRYPTO_"), tamper.detail
        return f"错误摘要可读：{tamper.detail}"

    def c_cmd_backend():
        """cmd 后端接线：合法包 → 成功；篡改包 → 取到 CRYPTO_* 错误码。"""
        raw = load_fixture()
        with tempfile.TemporaryDirectory(prefix="ys-cmdstub-") as td:
            base = Path(td) / "base.yspk"
            base.write_bytes(raw)
            stub = Path(td) / "decrypt.py"
            stub.write_text(
                "import sys, pathlib\n"
                f"base = pathlib.Path({str(base)!r}).read_bytes()\n"
                "data = pathlib.Path(sys.argv[1]).read_bytes()\n"
                "if data == base:\n"
                "    print('ok')\n"
                "    sys.exit(0)\n"
                "print('CRYPTO_CHUNK_AUTH_FAILED', file=sys.stderr)\n"
                "sys.exit(3)\n", encoding="utf-8")
            be = CmdBackend(f"{shlex.quote(sys.executable)} {shlex.quote(str(stub))} {{in}}",
                            timeout=30)
            ok, _ = be.decrypt_succeeds(raw)
            assert ok is True, "cmd 后端：合法包竟判失败"
            fails, why = be.decrypt_fails(raw[:-1])
            assert fails and why == "CRYPTO_CHUNK_AUTH_FAILED", (fails, why)

            mute = Path(td) / "mute.py"
            mute.write_text("import sys\nsys.exit(4)\n", encoding="utf-8")
            be2 = CmdBackend(f"{shlex.quote(sys.executable)} {shlex.quote(str(mute))} {{in}}",
                             timeout=30)
            fails2, why2 = be2.decrypt_fails(raw)
            assert fails2 and "未取到" in why2, why2
        return "cmd 后端接线正常；无错误码时如实标注"

    case("解析契约样例（YSPK v1 / 743B）", c_fixture)
    case("解析单块契约样例（522B）", c_fixture_v1)
    case("合成包解析", c_synthetic)
    case("四类篡改 + 块头/数据区翻转", c_baseline_and_tamper)
    case("附加用例（tag/截断/半块）", c_extra_cases)
    case("判定逻辑非空转", c_judge_not_vacuous)
    case("单块包降级为 SKIP", c_single_chunk_skip)
    case("截断包解析被拒", c_parse_rejects)
    case("错误摘要可读", c_error_summary)
    case("cmd 后端接线", c_cmd_backend)

    print("=" * 90)
    print("tamper_probe.py 自测")
    print("=" * 90)
    failed = sum(1 for _, ok, _ in results if not ok)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<34} {detail}")
    print("-" * 90)
    print(f"{len(results) - failed}/{len(results)} 通过")
    return EXIT_PASS if failed == 0 else EXIT_FAIL


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="雁书 Gate 证据二：密文篡改必报错（骨架版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--envelope", default=os.environ.get("YS_ENVELOPE"),
                    help="合法密文包（.yspk）路径")
    ap.add_argument("--donor", default=os.environ.get("YS_DONOR"),
                    help="另一个合法包，用于'Replace 整块为另一包的合法块'")
    ap.add_argument("--fixture", choices=["builtin"], help="使用内置契约样例包")
    ap.add_argument("--backend", default=os.environ.get("YS_BACKEND", "selftest"),
                    choices=["selftest", "cmd", "cargo-test", "always-ok"])
    ap.add_argument("--decrypt-cmd", default=os.environ.get("YS_DECRYPT_CMD"),
                    help="cmd 后端的命令模板，支持 {in} / {out} 占位符")
    ap.add_argument("--rune-crate", default=os.environ.get("YS_RUNE_CRATE"))
    ap.add_argument("--cargo-test-error-filter", default="tamper_rejects")
    ap.add_argument("--cargo-test-ok-filter", default=None)
    ap.add_argument("--error-regex", default=r"CRYPTO_[A-Z0-9_]+")
    ap.add_argument("--cases", help="逗号分隔的用例白名单（默认要求的 6 条）")
    ap.add_argument("--extra-cases", action="store_true", help="追加 tag/半块/截断 3 条")
    ap.add_argument("--out-dir", help="篡改产物落盘目录（给了就保留）")
    ap.add_argument("--keep", action="store_true", help="保留临时篡改产物")
    ap.add_argument("--dry-run", action="store_true", help="只解析与构造，不调解密")
    ap.add_argument("--json-out")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()

    started = time.time()

    # ---- 取包 ----
    try:
        if args.fixture == "builtin":
            pristine = load_fixture()
            src = f"内置契约样例（{FIXTURE_HEX.name}）"
        elif args.envelope:
            pristine = Path(args.envelope).read_bytes()
            src = args.envelope
        else:
            print("[BLOCKED] 需要 --envelope 或 --fixture builtin", file=sys.stderr)
            return EXIT_BLOCKED
    except (OSError, EnvelopeError) as exc:
        print(f"[BLOCKED] 读不了密文包：{exc}", file=sys.stderr)
        return EXIT_BLOCKED

    try:
        env = parse_envelope(pristine)
    except EnvelopeError as exc:
        print(f"[BLOCKED] 密文包结构不合法：{exc.code} {exc.msg}", file=sys.stderr)
        return EXIT_BLOCKED

    donor = None
    if args.donor:
        try:
            donor = Path(args.donor).read_bytes()
            parse_envelope(donor)
        except (OSError, EnvelopeError) as exc:
            print(f"[BLOCKED] --donor 不可用：{exc}", file=sys.stderr)
            return EXIT_BLOCKED

    print(f"[input] 包：{src}")
    print(f"[input] {env.summary()}")

    names = [n for n, _ in REQUIRED_CASES]
    if args.extra_cases:
        names += [n for n, _ in EXTRA_CASES]
    if args.cases:
        want = [c.strip() for c in args.cases.split(",") if c.strip()]
        unknown = [c for c in want if c not in ALL_CASES]
        if unknown:
            print(f"[BLOCKED] 未知用例：{unknown}", file=sys.stderr)
            return EXIT_BLOCKED
        names = want

    if args.dry_run:
        print("\n[dry-run] 只构造不执行：")
        for n in names:
            t = ALL_CASES[n](env, parse_envelope(donor) if donor else None)
            print(f"  {'SKIP' if t.skip else 'OK  '}  {n:<22} {t.skip or t.desc}")
        return EXIT_PASS

    try:
        backend = build_backend(args, pristine)
    except EnvelopeError as exc:
        print(f"[BLOCKED] {exc.msg}", file=sys.stderr)
        return EXIT_BLOCKED

    if not backend.production:
        print("[warn] 当前走的是测试入口而非生产导出路径 —— 这份结果不能作为最终验收证据")

    try:
        results, code = execute(backend, pristine, donor, names, args.out_dir, args.keep)
    except (EnvelopeError, subprocess.TimeoutExpired, RuntimeError) as exc:
        print(f"[BLOCKED] 执行中断：{exc}", file=sys.stderr)
        return EXIT_BLOCKED

    print_report(backend, env.summary(), results, started)
    if args.json_out:
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "backend": backend.label,
            "production_path": backend.production,
            "envelope": {"source": src, "summary": env.summary(), "bytes": len(pristine)},
            "exit_code": code,
            "cases": [{"case": r.case, "status": r.status, "expect": r.expect,
                       "detail": r.detail, "desc": r.desc, "artifact": r.artifact}
                      for r in results],
        }
        Path(args.json_out).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
        print(f"[report] 明细已写入 {args.json_out}")
    return code


if __name__ == "__main__":
    sys.exit(main())
