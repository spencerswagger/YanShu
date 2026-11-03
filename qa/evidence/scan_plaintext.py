#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""雁书 YanShu · Gate 证据一：服务器侧「无明文 / 无文件名」检索脚本（骨架版）

===============================================================================
这个脚本是什么
===============================================================================
对一次投递（或已存在的投递）在**服务端**留下的东西做取证式检索：

    ① 存储目录（服务端落盘的密文块 / prelude）
    ② 数据库（或索引库）

检索项：原文件名、文件名主干、扩展名、每段明文片段、以及这些内容的
base64 / hex / percent-encode 形态。命中即说明服务端看到了不该看到的东西。

它**不实现加解密**、**不修改被检对象**、**不读取任何密钥或凭据文件**。
数据库连接串只从命令行/环境变量取，输出一律打码。

===============================================================================
用法
===============================================================================
    # 0) 自测：不需要任何外部依赖，验证脚本本身不是空壳
    python3 qa/evidence/scan_plaintext.py --selftest

    # 1) 生成一份投递样本（文件名 + 高熵随机串 + 中文短句），并打印描述文件
    python3 qa/evidence/scan_plaintext.py --emit-sample /tmp/ys-sample

    # 2) 对「已有投递」留下的存储 + 数据库做检索
    python3 qa/evidence/scan_plaintext.py \
        --storage-root /var/lib/yanshu/blobs \
        --dsn "$TEST_DATABASE_URL" \
        --sample /tmp/ys-sample/sample.json

    # 3) 现场跑一次完整投递再检索（端侧未就绪时用外部命令钩子）
    python3 qa/evidence/scan_plaintext.py \
        --deliver-cmd './scripts/send-sample.sh' \
        --storage-root ... --dsn ...

环境变量（都可被命令行参数覆盖）：
    YS_STORAGE_ROOT   服务端存储根目录
    YS_DSN            数据库连接串（PostgreSQL；经 psql 读取）
    YS_DB_FILE        SQLite 数据库文件（与 YS_DSN 二选一或都不给）
    YS_SAMPLE         投递样本描述 JSON
    YS_DELIVER_CMD    投递命令（可选）
    YS_RECIPIENT_CODE 收件方 4 位码（只透传给投递命令，不打印、不入库）
    YS_PSQL           psql 可执行文件路径（默认 psql）

===============================================================================
退出码
===============================================================================
    0  PASS        所有「强信号」检索项均未命中
    1  FAIL        有命中（逐条打印位置；片段只打印定位上下文，不整段回显）
    2  BLOCKED     配置/依赖问题（无检索目标、投递命令失败、psql 不可用……）
    3  INCONCLUSIVE 语料为空（扫了 0 文件 0 字节 0 行）——"没命中"不构成证据
    4  PENDING     参数未就绪（--profile core-skeleton 时服务端还没合入/没起/migrations
                   未跑）——既不算 PASS 也不算 FAIL

===============================================================================
命中强度的口径（重要，别当成偷工减料）
===============================================================================
短 ASCII 记号（如 `txt`、`.txt`）在随机密文里有真实概率**偶然出现**：
3 字节记号在 1 GB 随机数据里期望命中 ~0.25 次。若把它也判 FAIL，
证据会长期假红、失去意义。因此：

  * 载荷 ≥ 8 字节的检索项 → 强信号（hard），命中 = FAIL
  * 载荷 <  8 字节的检索项 → 弱信号（advisory），命中照常打印位置，但不改退出码
  * `--strict` 把所有弱信号也升级为 FAIL（要字面语义时用它）

扩展名固定产出两项：`.txt`（带点，强/弱按长度）与 `txt`（裸串，恒为弱信号）。
任何 advisory 命中都会在末尾单独汇总，不会被"静默吞掉"。

===============================================================================
当前骨架状态（2026-11-02 首夜）
===============================================================================
可直接跑： 自测、样本生成、对任意目录的检索、对 PostgreSQL/SQLite 的检索、
          投递命令钩子、JSON 报告输出
缺依赖未闭环：
  * 端到端投递（A→服务器→B）要等 Core + Rune 的最小闭环；本脚本用
    `--deliver-cmd` 挂外部命令，闭环一成把命令填进去即可，脚本不用改。
  * `docs/API.md` 尚未落盘，所以没有内置 HTTP 投递实现（见 `deliver_via_http`
    的 TODO，落盘后补这一条分支即可）。
  * 存储布局（块文件名 / prelude 存法）由 Core 定；本脚本按"整目录递归"扫，
    不假设任何命名规则。
===============================================================================
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.parse import quote

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

READ_BUF = 1 << 20          # 1 MiB 分块读，与 CHUNK_SIZE 同量级
CTX_BYTES = 8               # 命中位置只回显左右各 8 字节，避免整段回显明文
MIN_HARD_LEN = 8            # ≥ 8 字节视为强信号

EXIT_PASS = 0
EXIT_HIT = 1
EXIT_BLOCKED = 2
EXIT_INCONCLUSIVE = 3
EXIT_PENDING = 4        # 参数未就绪（服务端还没合入/没起）：既不算 PASS 也不算 FAIL

HARD = "hard"
ADVISORY = "advisory"

# --------------------------------------------------------------------------- #
# 服务端骨架 profile（来自 feat/server-skeleton 的约定，未合入 main 前只当"待确认"）
#
# 存储布局：<YANSHU_BLOB_DIR>/<pkg[0:2]>/<pkg>/prelude
#                          /<pkg>/chunks/<index>       （server/internal/blob/disk.go）
# 库表：server/internal/store/migrations/0001_init.sql 的白名单，任何白名单外的
#       表/列都要在报告里点出来（Core 自己的 schema_test.go 也在守这条）。
# --------------------------------------------------------------------------- #

PROFILE_GENERIC = "generic"
PROFILE_CORE = "core-skeleton"

CORE_BLOB_DIR_ENV = "YANSHU_BLOB_DIR"
CORE_BLOB_DIR_DEFAULT = "./data/blobs"
CORE_DSN_ENV = "YANSHU_DATABASE_URL"
CORE_LOG_DIR_ENV = "YANSHU_LOG_DIR"

# 白名单基线：对齐到哪个 commit 的 migrations（表结构变了就要改这里，并在结果文件写明）
CORE_SCHEMA_BASELINE = "feat/server-skeleton@c3c2fc9 (server/internal/store/migrations/0001_init.sql)"

# 7 张业务表 + 1 张迁移记账表（schema_migrations 由 store.go 建，不是 migrations 文件里的）
CORE_BUSINESS_TABLES = {
    # 对齐 feat/server-skeleton @ c3c2fc9（server/internal/store/migrations/0001_init.sql）
    "codes": {"code", "public_key", "nickname", "registered_at", "updated_at"},
    "auth_challenges": {"challenge_id", "purpose", "nonce", "expires_at", "used"},
    "transfers": {"transfer_id", "sender_code", "recipient_code", "plaintext_size",
                  "chunk_size", "chunk_count", "prelude_len", "prelude_received",
                  "prelude_sm3", "received_chunks", "total_ciphertext_bytes",
                  "download_count", "max_downloads", "state", "terminal_reason",
                  "terminal_at", "created_at", "updated_at", "expires_at",
                  "upload_token_sm3", "uploader_ip"},
    "transfer_chunks": {"transfer_id", "chunk_index", "length", "ciphertext_sm3",
                        "stored_at"},
    "transfer_downloads": {"download_id", "transfer_id", "created_at",
                           "lease_expires_at", "acked_at"},
    "idempotency_keys": {"key_hash", "sender_code", "request_fingerprint",
                         "transfer_id", "created_at", "expires_at"},
    "audit_events": {"id", "ts", "method", "path", "status", "bytes", "ip", "request_id"},
}

# 迁移记账表：由 server/internal/store/store.go 建（不在 0001_init.sql 里），
# 只有版本号与时间，**不是业务表**。基线共 7 业务 + 1 记账 = 8 张。
CORE_BOOKKEEPING_TABLES = {
    "schema_migrations": {"version", "applied_at"},
}

CORE_SCHEMA = {**CORE_BUSINESS_TABLES, **CORE_BOOKKEEPING_TABLES}


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Pattern:
    """一条待检索的字节串，对应样本里的一个「检索项 + 形态」。"""
    item_id: str
    form: str          # raw / b64 / b64-nopad / b64url / b64url-nopad / hex-lower / hex-upper / pct
    needle: bytes


@dataclass
class SearchItem:
    """一个检索项（文件名 / 主干 / 扩展名 / 明文片段），可展开成多个形态。"""
    item_id: str
    kind: str                       # file-name / file-stem / file-ext-dot / file-ext-bare / fragment
    strength: str                   # HARD / ADVISORY
    note: str = ""
    patterns: list[Pattern] = field(default_factory=list)


@dataclass
class Hit:
    item_id: str
    form: str
    target: str                     # storage / postgres / sqlite
    loc: str                        # 人可读位置
    offset: int
    before: bytes
    after: bytes
    strength: str


@dataclass
class Stats:
    files: int = 0
    bytes_scanned: int = 0
    db_tables: int = 0
    db_rows: int = 0
    db_cells: int = 0
    log_files: int = 0
    log_bytes: int = 0

    @property
    def empty(self) -> bool:
        return (self.bytes_scanned == 0 and self.log_bytes == 0
                and self.db_rows == 0 and self.db_cells == 0)


@dataclass
class SampleSpec:
    sample_id: str
    file_name: str
    mime: str
    fragments: list[dict]


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #

def redact_dsn(dsn: str | None) -> str:
    """把连接串里的口令打码，任何输出都不带凭据。"""
    if not dsn:
        return "(none)"
    return re.sub(r"(://[^:/@]+):[^@]*@", r"\1:***@", dsn)


def hexpreview(b: bytes) -> str:
    return b.hex() if b else ""


def load_sample(path: str) -> SampleSpec:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    for key in ("file_name", "fragments"):
        if key not in raw:
            raise SystemExit(f"[BLOCKED] 样本描述缺字段 {key!r}：{path}")
    frags = []
    for f in raw["fragments"]:
        if "value" in f:
            frags.append({"id": f.get("id", f"frag{len(frags)}"), "value": f["value"]})
        elif "b64" in f:
            frags.append({"id": f.get("id", f"frag{len(frags)}"),
                          "value": base64.b64decode(f["b64"]).decode("utf-8", "surrogateescape")})
        else:
            raise SystemExit(f"[BLOCKED] 片段的 value/b64 都没有：{f!r}")
    return SampleSpec(
        sample_id=raw.get("sample_id", "sample"),
        file_name=raw["file_name"],
        mime=raw.get("mime", "text/plain"),
        fragments=frags,
    )


def build_sample_spec(seed_token: str | None = None) -> tuple[SampleSpec, bytes]:
    """生成一份投递样本：高熵随机串 + 中文短句，附一点填充让文件不至于太小。"""
    token = seed_token or base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip("=")
    zh = "鸿雁传书，一声便至，过而不留。"
    name = "验收样本-首夜.txt"
    spec = SampleSpec(
        sample_id="gate-skeleton-001",
        file_name=name,
        mime="text/plain",
        fragments=[
            {"id": "hi-entropy", "value": token},
            {"id": "zh-sentence", "value": zh},
        ],
    )
    body = (
        "yan-shu sample\n"
        f"token: {token}\n"
        f"note: {zh}\n"
        + ("padding-0123456789abcdef" * 64)
        + "\n"
    ).encode("utf-8")
    return spec, body


# --------------------------------------------------------------------------- #
# 检索项 → 形态
# --------------------------------------------------------------------------- #

def _forms(payload: bytes, with_pct: bool = False) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = [("raw", payload)]
    b64 = base64.b64encode(payload)
    out.append(("b64", b64))
    out.append(("b64-nopad", b64.rstrip(b"=")))
    u64 = base64.urlsafe_b64encode(payload)
    out.append(("b64url", u64))
    out.append(("b64url-nopad", u64.rstrip(b"=")))
    h = payload.hex().encode("ascii")
    out.append(("hex-lower", h))
    out.append(("hex-upper", h.upper()))
    if with_pct:
        out.append(("pct", quote(payload.decode("utf-8", "surrogateescape"), safe="").encode("ascii")))
    return out


def build_items(spec: SampleSpec, strict: bool = False) -> list[SearchItem]:
    """把样本展开成检索项；强度按载荷长度定，`--strict` 时全部升级为强信号。"""

    def strength_of(payload: bytes, force_advisory: bool = False) -> str:
        if strict:
            return HARD
        if force_advisory:
            return ADVISORY
        return HARD if len(payload) >= MIN_HARD_LEN else ADVISORY

    items: list[SearchItem] = []

    name_b = spec.file_name.encode("utf-8")
    items.append(SearchItem(
        item_id="file-name", kind="file-name", strength=strength_of(name_b),
        note=f"原文件名（{len(name_b)}B）",
        patterns=[Pattern("file-name", f, n) for f, n in _forms(name_b, with_pct=True)],
    ))

    stem, ext = os.path.splitext(spec.file_name)
    if stem:
        stem_b = stem.encode("utf-8")
        items.append(SearchItem(
            item_id="file-stem", kind="file-stem", strength=strength_of(stem_b),
            note=f"文件名主干（{len(stem_b)}B，不带扩展名）",
            patterns=[Pattern("file-stem", f, n) for f, n in _forms(stem_b)],
        ))
    if ext:
        dot_b = ext.encode("utf-8")
        items.append(SearchItem(
            item_id="file-ext-dot", kind="file-ext-dot", strength=strength_of(dot_b),
            note=f"扩展名带点（{dot_b!r}）",
            patterns=[Pattern("file-ext-dot", f, n) for f, n in [("raw", dot_b)]],
        ))
        bare_b = ext.lstrip(".").encode("utf-8")
        items.append(SearchItem(
            item_id="file-ext-bare", kind="file-ext-bare", strength=strength_of(bare_b, force_advisory=True),
            note=f"扩展名裸串（{bare_b!r}，短记号，偶然命中概率不可忽略 → 恒为弱信号）",
            patterns=[Pattern("file-ext-bare", "raw", bare_b)],
        ))

    for f in spec.fragments:
        payload = f["value"].encode("utf-8")
        item_id = f"fragment:{f['id']}"
        items.append(SearchItem(
            item_id=item_id, kind="fragment", strength=strength_of(payload),
            note=f"明文片段（{len(payload)}B）",
            patterns=[Pattern(item_id, fm, n) for fm, n in _forms(payload)],
        ))
    return items


def flatten(items: Sequence[SearchItem]) -> list[Pattern]:
    return [p for it in items for p in it.patterns]


# --------------------------------------------------------------------------- #
# 流式检索
# --------------------------------------------------------------------------- #

def iter_file(path: str, buf: int = READ_BUF) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while True:
            block = f.read(buf)
            if not block:
                return
            yield block


def find_hits(chunks: Iterable[bytes], patterns: Sequence[Pattern],
              max_hits_per_form: int = 5) -> Iterator[tuple[Pattern, int, bytes, bytes]]:
    """在连续字节流里找所有 needle，返回 (pattern, 绝对偏移, 前文, 后文)。

    跨块命中用 max_len-1 字节的 carry 处理；重复命中用 seen 去重。
    """
    if not patterns:
        return
    maxlen = max(len(p.needle) for p in patterns)
    carry = b""
    base = 0                     # carry[0] 的绝对偏移
    counts: dict[tuple[str, str], int] = {}
    seen: set[tuple[str, str, int]] = set()

    for chunk in chunks:
        data = carry + chunk
        for pat in patterns:
            key = (pat.item_id, pat.form)
            if counts.get(key, 0) >= max_hits_per_form:
                continue
            start = 0
            while True:
                idx = data.find(pat.needle, start)
                if idx < 0:
                    break
                abs_off = base + idx
                sig = (pat.item_id, pat.form, abs_off)
                if sig not in seen:
                    seen.add(sig)
                    counts[key] = counts.get(key, 0) + 1
                    before = data[max(0, idx - CTX_BYTES):idx]
                    after = data[idx + len(pat.needle): idx + len(pat.needle) + CTX_BYTES]
                    yield pat, abs_off, before, after
                    if counts[key] >= max_hits_per_form:
                        break
                start = idx + 1
        keep = maxlen - 1
        if keep > 0 and len(data) > keep:
            carry = data[-keep:]
            base += len(data) - len(carry)
        else:
            base += len(data)
            carry = b""


# --------------------------------------------------------------------------- #
# 目标① 存储目录
# --------------------------------------------------------------------------- #

def scan_storage(root: str, patterns: Sequence[Pattern], stats: Stats,
                 max_hits_per_form: int = 5, target: str = "storage") -> list[Hit]:
    """扫一个目录树。target=logs 时计数进日志桶，便于报告里分开看。"""
    hits: list[Hit] = []
    is_log = target == "logs"
    root = os.path.abspath(root)
    if os.path.isfile(root):
        # 允许直接给单个文件（例如按日滚动的日志），否则 os.walk 会静默扫 0 个文件
        parent, single = os.path.dirname(root), os.path.basename(root)
        trees = [(parent, [], [single])]
    else:
        trees = os.walk(root)
    for dirpath, dirnames, filenames in trees:
        dirnames.sort()
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            if not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if is_log:
                stats.log_files += 1
                stats.log_bytes += size
            else:
                stats.files += 1
                stats.bytes_scanned += size
            try:
                for pat, off, before, after in find_hits(iter_file(path), patterns, max_hits_per_form):
                    hits.append(Hit(pat.item_id, pat.form, target, path, off, before, after, ""))
            except OSError as exc:
                print(f"[warn] 读不了 {path}: {exc}", file=sys.stderr)
    return hits


def scan_log_cmd(cmd: str, patterns: Sequence[Pattern], stats: Stats,
                 max_hits_per_form: int, timeout: float) -> list[Hit]:
    """把一条命令的输出（stdout+stderr）当日志流扫，例如 docker logs / journalctl。"""
    proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
    blob = (proc.stdout or b"") + b"\n" + (proc.stderr or b"")
    stats.log_files += 1
    stats.log_bytes += len(blob)
    label = f"log:{cmd}"
    hits: list[Hit] = []
    for pat, off, before, after in find_hits([blob], patterns, max_hits_per_form):
        hits.append(Hit(pat.item_id, pat.form, "logs", label, off, before, after, ""))
    return hits


# --------------------------------------------------------------------------- #
# 目标② 数据库
# --------------------------------------------------------------------------- #

SQL_LIST_TABLES = (
    "select format('%I.%I', table_schema, table_name) "
    "from information_schema.tables "
    "where table_type='BASE TABLE' "
    "and table_schema = current_schema() "
    "order by 1"
)


def _psql_env(schema: str | None) -> dict:
    env = dict(os.environ)
    if schema:
        # psql 的 URI 不认 search_path 参数；用 PGOPTIONS 指定，等价且不污染 DSN
        env["PGOPTIONS"] = (env.get("PGOPTIONS", "") + f" -c search_path={schema}").strip()
    return env


def _psql(dsn: str, sql: str, timeout: float,
          schema: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [os.environ.get("YS_PSQL", "psql"), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
         "-d", dsn, "-c", sql],
        capture_output=True, timeout=timeout, env=_psql_env(schema),
    )


def scan_postgres(dsn: str, patterns: Sequence[Pattern], stats: Stats,
                  max_hits_per_form: int = 5, timeout: float = 120.0,
                  schema: str | None = None) -> list[Hit]:
    """把每张表的每行渲染成一行 JSON 再扫。

    * TEXT/VARCHAR 列：明文原样出现 → 直接命中
    * BYTEA 列：PG 渲染成 `\\x<hex>` → 由 hex 形态命中（**这是刻意的**：bytea
      里的明文以十六进制在 SQL 层流出，检索 hex 形态正是为了抓它）
    * 定位：表名 + 行号 + ctid，够人去复核，不打印整行内容
    """
    hits: list[Hit] = []
    proc = _psql(dsn, SQL_LIST_TABLES, timeout, schema)
    if proc.returncode != 0:
        raise RuntimeError(f"psql 列表失败：{proc.stderr.decode('utf-8', 'replace').strip()}")
    tables = [t for t in proc.stdout.decode("utf-8", "replace").splitlines() if t.strip()]

    ctid_re = re.compile(r'"_ctid"\s*:\s*"\((\d+),(\d+)\)"')

    for table in tables:
        stats.db_tables += 1
        sql = f"select row_to_json(x) from (select ctid::text as _ctid, * from {table}) x"
        p = subprocess.Popen(
            [os.environ.get("YS_PSQL", "psql"), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
             "-d", dsn, "-c", sql],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_psql_env(schema),
        )
        try:
            for lineno, line in enumerate(p.stdout, 1):
                stats.db_rows += 1
                m = ctid_re.search(line.decode("utf-8", "replace"))
                where = f"db:pg/{table} row#{lineno}" + (f" ctid=({m.group(1)},{m.group(2)})" if m else "")
                for pat, off, before, after in find_hits([line], patterns, max_hits_per_form):
                    hits.append(Hit(pat.item_id, pat.form, "postgres", where, off, before, after, ""))
        finally:
            err = p.stderr.read().decode("utf-8", "replace").strip()
            p.stdout.close()
            p.stderr.close()
            rc = p.wait()
        if rc != 0:
            raise RuntimeError(f"psql 扫表 {table} 失败：{err}")
    return hits


SQL_LIST_COLUMNS = (
    "select table_name || '.' || column_name "
    "from information_schema.columns "
    "where table_schema = current_schema() order by 1"
)


def core_schema_check(dsn: str, timeout: float,
                      schema: str | None = None) -> tuple[list[str], list[str]]:
    """核对库里的表/列是否都落在服务端骨架的白名单内。

    返回 (缺表, 白名单外的表/列)。缺表通常意味着 migrations 还没跑（骨架未起）。
    """
    proc = _psql(dsn, SQL_LIST_COLUMNS, timeout, schema)
    if proc.returncode != 0:
        raise RuntimeError(f"psql 读 schema 失败：{proc.stderr.decode('utf-8', 'replace').strip()}")
    seen: dict[str, set[str]] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip() or "." not in line:
            continue
        table, column = line.split(".", 1)
        seen.setdefault(table, set()).add(column)
    missing = [t for t in CORE_SCHEMA if t not in seen]
    extra: list[str] = []
    for table, cols in seen.items():
        if table not in CORE_SCHEMA:
            extra.append(f"白名单外的表 {table}（{len(cols)} 列）")
            continue
        for col in sorted(cols - CORE_SCHEMA[table]):
            extra.append(f"白名单外的列 {table}.{col}")
    return missing, extra


def scan_sqlite(path: str, patterns: Sequence[Pattern], stats: Stats,
                max_hits_per_form: int = 5) -> list[Hit]:
    hits: list[Hit] = []
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in con.execute(
            "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name")]
        for table in tables:
            stats.db_tables += 1
            cols = [d[1] for d in con.execute(f'PRAGMA table_info("{table}")')]
            try:
                cur = con.execute(f'select rowid, * from "{table}"')
            except sqlite3.OperationalError:
                cur = con.execute(f'select NULL, * from "{table}"')
            for row in cur:
                stats.db_rows += 1
                rowid = row[0]
                for col, val in zip(cols, row[1:]):
                    if val is None:
                        continue
                    stats.db_cells += 1
                    buf = val if isinstance(val, (bytes, bytearray)) else str(val).encode("utf-8")
                    where = f"db:sqlite/{table} rowid={rowid} col={col}"
                    for pat, off, before, after in find_hits([bytes(buf)], patterns, max_hits_per_form):
                        hits.append(Hit(pat.item_id, pat.form, "sqlite", where, off, before, after, ""))
    finally:
        con.close()
    return hits


# --------------------------------------------------------------------------- #
# 投递（可插拔）
# --------------------------------------------------------------------------- #

# 投递命令的标识约定：JSON（--json-out 文件或 stdout）或 key=value 行
DELIVER_KEYS = ("code", "package_id", "blob_dir", "db_url", "log_path", "schema")
# 必填：没有包 ID 不知道投了什么，没有 blob_dir 不知道扫哪儿 —— 这两个绝不猜
DELIVER_REQUIRED = ("package_id", "blob_dir")
# 不同实现的同义键（Core 的 deliver 用 transfer_id/storage_path）
DELIVER_ALIASES = {"transfer_id": "package_id", "storage_path": "blob_dir"}


def parse_deliver_output(text: str) -> dict[str, str]:
    """从投递命令的 stdout 里取标识：先按 JSON 整体解析，再退回 key=value 行。"""
    found: dict[str, str] = {}
    body = (text or "").strip()
    if body.startswith("{"):
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            for k in DELIVER_KEYS:
                if obj.get(k) not in (None, ""):
                    found[k] = str(obj[k])
            for src, dst in DELIVER_ALIASES.items():
                if dst not in found and obj.get(src) not in (None, ""):
                    found[dst] = str(obj[src])
            if found:
                return found
    for line in body.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().lstrip("-").replace("-", "_")
        v = v.strip().strip('"').strip("'")
        if k in DELIVER_KEYS and v:
            found[k] = v
    return found


def deliver_via_cmd(cmd: str, sample_json: str, sample_bin: str, spec: SampleSpec,
                    recipient_code: str, timeout: float) -> str:
    """跑一条外部命令完成一次投递；命令通过环境变量拿到样本与收件码。"""
    env = dict(os.environ)
    env.update({
        "YS_SAMPLE_JSON": os.path.abspath(sample_json),
        "YS_SAMPLE_FILE": os.path.abspath(sample_bin),
        "YS_SAMPLE_NAME": spec.file_name,
        "YS_SAMPLE_MIME": spec.mime,
        "YS_SAMPLE_ID": spec.sample_id,
        "YS_RECIPIENT_CODE": recipient_code,
    })
    print(f"[deliver] $ {cmd}")
    proc = subprocess.run(cmd, shell=True, env=env, timeout=timeout,
                          capture_output=True, text=True)
    for line in (proc.stdout or "").splitlines():
        print(f"[deliver] {line}")
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()[-5:]
        raise RuntimeError(f"投递命令退出码 {proc.returncode}：{' / '.join(tail)}")
    return proc.stdout or ""


def deliver_via_http(*_args, **_kwargs) -> None:
    """TODO(闭环后补)：`docs/API.md` 落盘后，按 §12 的 prelude + 块切片映射实现
    `--deliver http` 分支（POST prelude / PUT chunk / 提交清单），不要自己发明契约。
    当前一律抛 BLOCKED，绝不做"猜测式投递"。"""
    raise NotImplementedError("http 投递分支待 docs/API.md 落盘后实现")


# --------------------------------------------------------------------------- #
# 报告
# --------------------------------------------------------------------------- #

def report(items: Sequence[SearchItem], hits: Sequence[Hit], stats: Stats,
           targets: Sequence[str], strict: bool, started: float) -> int:
    by_key: dict[tuple[str, str], list[Hit]] = {}
    for h in hits:
        by_key.setdefault((h.item_id, h.target), []).append(h)

    strength_of = {it.item_id: it.strength for it in items}
    note_of = {it.item_id: it.note for it in items}
    form_count = {it.item_id: len(it.patterns) for it in items}

    print()
    print("=" * 108)
    print(f"{'':3}{'检索项':<24}{'强度':<9}{'目标':<11}{'形态数':<7}{'结果':<7}说明")
    print("-" * 108)
    hard_hits = advisory_hits = 0
    for idx, item in enumerate(items, 1):
        for target in targets:
            hs = by_key.get((item.item_id, target), [])
            if not hs:
                print(f"[{idx:02d}] {item.item_id:<24}{item.strength:<9}{target:<11}"
                      f"{form_count[item.item_id]:<7}{'MISS':<7}-")
                continue
            if item.strength == HARD:
                hard_hits += len(hs)
            else:
                advisory_hits += len(hs)
            verdict = "HIT" if item.strength == HARD else "HIT(weak)"
            print(f"[{idx:02d}] {item.item_id:<24}{item.strength:<9}{target:<11}"
                  f"{form_count[item.item_id]:<7}{verdict:<7}{note_of[item.item_id]}")
            for h in hs:
                print(f"       ↳ {h.loc}  offset={h.offset:,}  form={h.form}  "
                      f"before={hexpreview(h.before) or '-'} after={hexpreview(h.after) or '-'}")

    print("-" * 108)
    # 逐目标的空语料告警：某个目标扫了 0 字节/0 行，"没命中"在那个目标上不成立
    if "storage" in targets and stats.bytes_scanned == 0:
        print("[warn] storage 目标扫了 0 字节：投递可能没落到这个目录，"
              "该目标的 PASS 不算数（换目录或补投递后重跑）")
    if "logs" in targets and stats.log_bytes == 0:
        print("[warn] logs 目标扫了 0 字节：日志路径可能不对，该目标的 PASS 不算数")
    if "postgres" in targets and stats.db_rows == 0:
        print("[warn] postgres 目标扫了 0 行：库可能是空的或 schema 不对，该目标的 PASS 不算数")
    print(f"扫描：存储文件 {stats.files:,} 个 / {stats.bytes_scanned:,} 字节；"
          f"日志 {stats.log_files:,} 份 / {stats.log_bytes:,} 字节；"
          f"数据库 {stats.db_tables} 表 / {stats.db_rows:,} 行 / {stats.db_cells:,} 单元格；"
          f"耗时 {time.time() - started:.2f}s")
    print(f"命中：强信号 {hard_hits}，弱信号 {advisory_hits}（弱信号不计入退出码，"
          f"{'--strict 已开启，全部按强信号算' if strict else '需要字面语义请加 --strict'}）")

    if hard_hits:
        print("结论：FAIL —— 服务端侧出现了明文或文件名")
        return EXIT_HIT
    if stats.empty:
        print("结论：INCONCLUSIVE —— 扫了 0 字节 0 行，什么都没扫到的 PASS 不算证据")
        return EXIT_INCONCLUSIVE
    print("结论：PASS —— 所有强信号检索项均未命中")
    return EXIT_PASS


def dump_json(path: str, items: Sequence[SearchItem], hits: Sequence[Hit],
              stats: Stats, exit_code: int) -> None:
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exit_code": exit_code,
        "stats": {
            "files": stats.files, "bytes_scanned": stats.bytes_scanned,
            "log_files": stats.log_files, "log_bytes": stats.log_bytes,
            "db_tables": stats.db_tables, "db_rows": stats.db_rows, "db_cells": stats.db_cells,
        },
        "schema_baseline": CORE_SCHEMA_BASELINE,
        "items": [{"id": it.item_id, "kind": it.kind, "strength": it.strength,
                   "note": it.note, "forms": len(it.patterns)} for it in items],
        "hits": [{"item": h.item_id, "form": h.form, "target": h.target, "loc": h.loc,
                  "offset": h.offset,
                  # 只留定位上下文，不留明文
                  "before_hex": h.before.hex(), "after_hex": h.after.hex()} for h in hits],
    }
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[report] 明细已写入 {path}")


# --------------------------------------------------------------------------- #
# 自测（证明脚本不是空壳）
# --------------------------------------------------------------------------- #

def _selftest() -> int:
    tmp = tempfile.mkdtemp(prefix="ys-scan-selftest-")
    results: list[tuple[str, bool, str]] = []

    def case(name: str, fn) -> None:
        try:
            detail = fn() or ""
            results.append((name, True, str(detail)))
        except AssertionError as exc:
            results.append((name, False, str(exc)))
        except Exception as exc:  # noqa: BLE001
            results.append((name, False, f"{type(exc).__name__}: {exc}"))

    spec, body = build_sample_spec("T" + os.urandom(12).hex())
    items = build_items(spec)
    patterns = flatten(items)
    token = spec.fragments[0]["value"].encode()
    zh = spec.fragments[1]["value"].encode()
    name_b = spec.file_name.encode()

    def c_sample():
        d = Path(tmp) / "sample"
        d.mkdir()
        (d / "sample.json").write_text(json.dumps({
            "sample_id": spec.sample_id, "file_name": spec.file_name,
            "mime": spec.mime, "fragments": spec.fragments}, ensure_ascii=False), encoding="utf-8")
        (d / "sample.bin").write_bytes(body)
        back = load_sample(str(d / "sample.json"))
        assert back.file_name == spec.file_name, "样本回读不一致"
        return f"检索项 {len(items)} 个 / 形态 {len(patterns)} 个"

    def c_clean():
        """3 MiB 随机语料：强信号必须 0 误报。

        弱信号（裸扩展名这种 3 字节记号）在随机数据里本来就有 ~18% 概率偶然出现，
        那正是把它定成 advisory 的原因 —— 这里只断言强信号不误报，并把观测到的
        弱信号条数如实打出来。
        """
        root = Path(tmp) / "clean"
        root.mkdir()
        (root / "blob-000.bin").write_bytes(os.urandom(3 * 1024 * 1024))
        st = Stats()
        hs = scan_storage(str(root), patterns, st)
        hard_ids = {i.item_id for i in items if i.strength == HARD}
        hard_hits = [h for h in hs if h.item_id in hard_ids]
        assert not hard_hits, f"强信号误报：{[h.item_id for h in hard_hits][:5]}"
        assert st.bytes_scanned == 3 * 1024 * 1024, st.bytes_scanned
        weak = len(hs) - len(hard_hits)
        return f"3 MiB 随机密文：强信号 0 误报（弱信号命中 {weak} 条，属预期）"

    def c_boundary():
        root = Path(tmp) / "boundary"
        root.mkdir()
        filler = os.urandom(READ_BUF - 3)
        (root / "blob-001.bin").write_bytes(filler + zh + os.urandom(4096))
        st = Stats()
        hs = scan_storage(str(root), patterns, st)
        want = READ_BUF - 3
        got = [h for h in hs if h.item_id == "fragment:zh-sentence" and h.form == "raw"]
        assert got, "跨 1 MiB 缓冲区边界的命中没找到"
        assert got[0].offset == want, f"偏移不对：{got[0].offset} != {want}"
        return f"跨缓冲边界命中 @ {want}"

    def c_b64():
        root = Path(tmp) / "b64"
        root.mkdir()
        blob = os.urandom(1024) + base64.b64encode(token) + os.urandom(1024)
        (root / "blob-002.bin").write_bytes(blob)
        st = Stats()
        hs = scan_storage(str(root), patterns, st)
        assert any(h.form == "b64" for h in hs), "base64 形态没命中"
        return "base64 形态命中"

    def c_name():
        root = Path(tmp) / "names"
        root.mkdir()
        (root / "index.ndjson").write_bytes(
            b'{"file":"' + name_b + b'","size":123}\n' + os.urandom(256))
        st = Stats()
        hs = scan_storage(str(root), patterns, st)
        assert any(h.item_id == "file-name" and h.form == "raw" for h in hs), "文件名没命中"
        return "文件名（JSON 索引）命中"

    def c_sqlite():
        db = Path(tmp) / "x.db"
        con = sqlite3.connect(str(db))
        con.execute("create table blobs(id integer primary key, payload blob, meta text)")
        con.execute("insert into blobs(payload, meta) values (?, ?)",
                    (b"\x00" + token + b"\x00", "clean"))
        con.execute("insert into blobs(payload, meta) values (?, ?)",
                    (os.urandom(64), token.hex()))          # 十六进制形态泄露
        con.execute("insert into blobs(payload, meta) values (?, ?)",
                    (os.urandom(64), "nothing here"))       # 干净行
        con.commit()
        con.close()
        st = Stats()
        hs = scan_sqlite(str(db), patterns, st)
        forms = {(h.item_id, h.form) for h in hs}
        assert ("fragment:hi-entropy", "raw") in forms, f"BLOB 原文没命中：{forms}"
        assert ("fragment:hi-entropy", "hex-lower") in forms, f"TEXT 十六进制没命中：{forms}"
        assert all("rowid=3" not in h.loc for h in hs), "干净行被误报"
        return f"sqlite 命中 {len(hs)} 处，干净行 0 误报"

    def c_empty():
        root = Path(tmp) / "empty"
        root.mkdir()
        st = Stats()
        hs = scan_storage(str(root), patterns, st)
        assert not hs and st.empty, "空语料应判 INCONCLUSIVE"
        return "空语料 → INCONCLUSIVE"

    def c_logs():
        """日志是第三个泄露面：干净日志不误报，泄漏日志必须抓到。"""
        root = Path(tmp) / "logs"
        root.mkdir()
        log = root / "server.log"
        log.write_text(
            "2026-11-02T00:00:00Z INFO listening on :8080\n"
            + "2026-11-02T00:00:01Z INFO upload package=b3f1 bytes=8192\n" * 40,
            encoding="utf-8")
        hard_ids = {i.item_id for i in items if i.strength == HARD}
        st = Stats()
        hs = scan_storage(str(root), patterns, st, target="logs")
        assert not [h for h in hs if h.item_id in hard_ids], \
            f"干净日志出现强信号命中：{[h.item_id for h in hs]}"
        assert st.log_files == 1 and st.log_bytes > 0, (st.log_files, st.log_bytes)

        log.write_text("2026-11-02T00:00:02Z WARN upload name=" + spec.file_name
                       + " token=" + spec.fragments[0]["value"] + "\n", encoding="utf-8")
        st2 = Stats()
        hs2 = scan_storage(str(root), patterns, st2, target="logs")
        assert any(h.item_id == "file-name" and h.target == "logs" for h in hs2), \
            "日志里的文件名没抓到"
        assert any(h.item_id == "fragment:hi-entropy" for h in hs2), "日志里的高熵串没抓到"
        return f"干净日志 0 误报；泄漏日志命中 {len(hs2)} 处（target=logs）"

    def c_deliver_ids():
        """投递标识解析：JSON / key=value、同义键、必填项缺失。"""
        full = {"code": "ABCD", "package_id": "0123456789abcdef0123456789abcdef",
                "blob_dir": "/var/lib/yanshu/blobs", "db_url": "postgres://u:p@h/db",
                "log_path": "/var/log/yanshu/server.log", "schema": "gate_ev1"}
        got = parse_deliver_output(json.dumps(full))
        assert got == full, got

        kv = ("code=WXYZ\npackage_id=fa11fa11fa11fa11fa11fa11fa11fa11\n"
              "blob_dir=/tmp/blobs\ndb_url=postgres://x/y\nlog_path=/tmp/s.log\n")
        got2 = parse_deliver_output(kv)
        assert got2["code"] == "WXYZ" and got2["blob_dir"] == "/tmp/blobs", got2

        # Core deliver 的同义键：transfer_id → package_id，storage_path → blob_dir
        core = json.dumps({"ok": True, "transfer_id": "abc", "storage_path": "/x/abc",
                           "schema": "gate_ev1", "db_url": "postgres://h/d"})
        got3 = parse_deliver_output(core)
        assert got3["package_id"] == "abc" and got3["blob_dir"] == "/x/abc", got3
        assert not [k for k in DELIVER_REQUIRED if k not in got3], "同义键映射后必填项应齐"

        partial = parse_deliver_output('{"code":"ABCD","package_id":"x"}')
        missing = [k for k in DELIVER_REQUIRED if k not in partial]
        assert missing == ["blob_dir"], missing
        return "JSON/key=value/同义键均可解析；必填项缺失能点名"

    def c_core_schema():
        """core-skeleton 白名单核对：缺表与白名单外的列都要能点出来。"""
        import unittest.mock as mock
        fake = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=("codes.code\ncodes.nickname\ntransfers.transfer_id\n"
                    "transfers.leaky_filename\nweird_table.x\n").encode(),
            stderr=b"")
        with mock.patch.object(sys.modules[__name__], "_psql", return_value=fake):
            missing, extra = core_schema_check("postgres://x", 1.0)
        assert "transfer_downloads" in missing and "codes" not in missing, missing
        assert any("transfers.leaky_filename" in e for e in extra), extra
        assert any("weird_table" in e for e in extra), extra
        return f"缺表 {len(missing)} 张、白名单外 {len(extra)} 项均被点出"

    def c_strict():
        loose = build_items(spec)
        strict_items = build_items(spec, strict=True)
        bare_loose = next(i for i in loose if i.item_id == "file-ext-bare").strength
        bare_strict = next(i for i in strict_items if i.item_id == "file-ext-bare").strength
        assert bare_loose == ADVISORY and bare_strict == HARD, "强度升级失效"
        return "--strict 能把弱信号升级为 FAIL"

    case("样本生成/回读", c_sample)
    case("干净语料不误报", c_clean)
    case("跨 1 MiB 边界命中", c_boundary)
    case("base64 形态命中", c_b64)
    case("文件名命中", c_name)
    case("SQLite（BLOB 原文 + TEXT 十六进制）", c_sqlite)
    case("空语料判 INCONCLUSIVE", c_empty)
    case("core 白名单核对", c_core_schema)
    case("投递标识解析", c_deliver_ids)
    case("日志泄露检查", c_logs)
    case("--strict 升级口径", c_strict)

    print("=" * 72)
    print("scan_plaintext.py 自测")
    print("=" * 72)
    failed = 0
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<36} {detail}")
        if not ok:
            failed += 1
    print("-" * 72)
    print(f"{len(results) - failed}/{len(results)} 通过")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if failed == 0 else 1


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def cmd_emit_sample(outdir: str) -> int:
    spec, body = build_sample_spec()
    d = Path(outdir)
    d.mkdir(parents=True, exist_ok=True)
    desc = {
        "sample_id": spec.sample_id,
        "file_name": spec.file_name,
        "mime": spec.mime,
        "fragments": spec.fragments,
    }
    (d / "sample.json").write_text(json.dumps(desc, ensure_ascii=False, indent=2), encoding="utf-8")
    (d / "sample.bin").write_bytes(body)
    print(f"[sample] 描述文件 {d/'sample.json'}")
    print(f"[sample] 样本文件 {d/'sample.bin'}（{len(body)} 字节）")
    print(f"[sample] 文件名 {spec.file_name!r}；片段 "
          f"{[f['id'] for f in spec.fragments]}")
    print("[sample] 提示：真实取证时请用**这一份**描述去检索，"
          "换文件名/换随机串会让检索项与密文对不上")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="雁书 Gate 证据一：服务端无明文/无文件名检索（骨架版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--profile", default=os.environ.get("YS_PROFILE", PROFILE_GENERIC),
                    choices=[PROFILE_GENERIC, PROFILE_CORE],
                    help="core-skeleton：从服务端骨架的约定取默认值并核对表/列白名单")
    ap.add_argument("--storage-root", default=os.environ.get("YS_STORAGE_ROOT"),
                    help="服务端存储根目录（递归扫描）")
    ap.add_argument("--dsn", default=os.environ.get("YS_DSN"),
                    help="PostgreSQL 连接串（经 psql 读取；口令不会打印）")
    ap.add_argument("--db-file", default=os.environ.get("YS_DB_FILE"),
                    help="SQLite 数据库文件")
    ap.add_argument("--sample", default=os.environ.get("YS_SAMPLE"),
                    help="投递样本描述 JSON（缺省则用内置样本生成）")
    ap.add_argument("--deliver-cmd", default=os.environ.get("YS_DELIVER_CMD"),
                    help="可选：跑一次投递的外部命令（拿到 YS_SAMPLE_FILE 等环境变量）")
    ap.add_argument("--deliver-json", default=os.environ.get("YS_DELIVER_JSON"),
                    help="投递命令写出的 JSON 结果文件（如 Core deliver 的 --json-out）；"
                         "优先于从 stdout 解析")
    ap.add_argument("--recipient-code", default=os.environ.get("YS_RECIPIENT_CODE", ""),
                    help="收件方 4 位码，只透传给投递命令，不打印")
    ap.add_argument("--deliver-timeout", type=float, default=600.0)
    ap.add_argument("--wait", type=float, default=0.0,
                    help="投递后等多少秒再扫（给服务端落盘/DB 提交留时间）")
    ap.add_argument("--strict", action="store_true",
                    help="所有弱信号也按 FAIL 处理（字面语义）")
    ap.add_argument("--max-hits-per-form", type=int, default=5,
                    help="每个形态最多记几条命中（默认 5，避免刷屏）")
    ap.add_argument("--psql-timeout", type=float, default=120.0)
    ap.add_argument("--pg-schema", default=os.environ.get("YS_PG_SCHEMA"),
                    help="PG schema（默认按 DSN；用 PGOPTIONS 传 search_path，不污染 DSN）")
    ap.add_argument("--log-path", default=os.environ.get("YS_LOG_PATH"),
                    help="服务端日志（文件或目录，递归扫）。第三个容易漏的泄露面")
    ap.add_argument("--log-cmd", default=os.environ.get("YS_LOG_CMD"),
                    help="用一条命令取日志流来扫，例如 'docker logs yanshu-server'")
    ap.add_argument("--log-timeout", type=float, default=120.0)
    ap.add_argument("--json-out", help="把明细写成 JSON（便于出报告）")
    ap.add_argument("--emit-sample", metavar="DIR", help="生成投递样本后退出")
    ap.add_argument("--selftest", action="store_true", help="跑自测后退出")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    if args.emit_sample:
        return cmd_emit_sample(args.emit_sample)

    started = time.time()

    # ---- 样本 ----
    tmp_sample_dir: str | None = None
    body: bytes | None = None
    if args.sample:
        try:
            spec = load_sample(args.sample)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[BLOCKED] 读不了样本描述 {args.sample}：{exc}", file=sys.stderr)
            return EXIT_BLOCKED
        print(f"[sample] {args.sample} → 文件名 {spec.file_name!r}，片段 {len(spec.fragments)} 段")
    else:
        spec, body = build_sample_spec()
        print(f"[sample] 未指定 --sample，用内置样本：文件名 {spec.file_name!r}，"
              f"片段 {[f['id'] for f in spec.fragments]}")
        print("[sample] 注意：内置样本只在“投递与检索用同一份描述”时才有意义")

    # 投递需要一份落盘的样本；没给 --sample 时临时生成，投递完即删
    if args.deliver_cmd and not args.sample:
        tmp_sample_dir = tempfile.mkdtemp(prefix="ys-sample-")
        desc = {"sample_id": spec.sample_id, "file_name": spec.file_name,
                "mime": spec.mime, "fragments": spec.fragments}
        (Path(tmp_sample_dir) / "sample.json").write_text(
            json.dumps(desc, ensure_ascii=False, indent=2), encoding="utf-8")
        (Path(tmp_sample_dir) / "sample.bin").write_bytes(body or b"")
        args.sample = str(Path(tmp_sample_dir) / "sample.json")

    items = build_items(spec, strict=args.strict)
    patterns = flatten(items)

    # ---- 可选：先跑一次投递 ----
    if args.deliver_cmd:
        sample_json = args.sample or ""
        sample_bin = os.path.join(os.path.dirname(os.path.abspath(args.sample)), "sample.bin")
        try:
            deliver_out = deliver_via_cmd(args.deliver_cmd, sample_json, sample_bin, spec,
                                          args.recipient_code, args.deliver_timeout)
        except (subprocess.TimeoutExpired, RuntimeError) as exc:
            print(f"[BLOCKED] 投递失败：{exc}", file=sys.stderr)
            return EXIT_BLOCKED

        ids: dict[str, str] = {}
        if args.deliver_json:
            try:
                ids = parse_deliver_output(Path(args.deliver_json).read_text(encoding="utf-8"))
            except OSError as exc:
                print(f"[PENDING] 读不了 --deliver-json {args.deliver_json}：{exc}", file=sys.stderr)
                return EXIT_PENDING
        if not ids:
            ids = parse_deliver_output(deliver_out)

        missing = [k for k in DELIVER_REQUIRED if k not in ids]
        if missing:
            print(f"[PENDING] 投递结果里缺这些必填标识：{'、'.join(missing)}", file=sys.stderr)
            print("          约定：`--deliver-json` 文件或 stdout 给 JSON/key=value，"
                  "键为 " + " / ".join(DELIVER_KEYS)
                  + "（同义键 transfer_id→package_id、storage_path→blob_dir）；"
                    "缺必填项按退出码 4 处理，不猜路径。", file=sys.stderr)
            return EXIT_PENDING
        print("[deliver] 标识：" + " ".join(
            f"{k}={redact_dsn(ids[k]) if k == 'db_url' else ids[k]}" for k in DELIVER_KEYS
            if ids.get(k)) + f"（来源：{'--deliver-json' if args.deliver_json else 'stdout'}）")
        # 显式参数优先，其次用投递结果里报出来的路径
        args.storage_root = args.storage_root or ids.get("blob_dir")
        args.dsn = args.dsn or ids.get("db_url")
        args.log_path = args.log_path or ids.get("log_path")
        args.pg_schema = args.pg_schema or ids.get("schema")
        if args.wait > 0:
            print(f"[deliver] 等待 {args.wait}s 让服务端落盘/提交")
            time.sleep(args.wait)
        if tmp_sample_dir:
            shutil.rmtree(tmp_sample_dir, ignore_errors=True)

    # ---- 目标（core-skeleton profile 会先从服务端骨架的约定里取默认值）----
    core = args.profile == PROFILE_CORE
    pending: list[str] = []
    if core:
        if not args.storage_root:
            args.storage_root = os.environ.get(CORE_BLOB_DIR_ENV, "")
            if not args.storage_root and os.path.isdir(CORE_BLOB_DIR_DEFAULT):
                args.storage_root = CORE_BLOB_DIR_DEFAULT
        if not args.dsn and not args.db_file:
            args.dsn = os.environ.get(CORE_DSN_ENV, "")
        if not args.log_path and not args.log_cmd:
            args.log_path = os.environ.get(CORE_LOG_DIR_ENV, "")

    targets: list[str] = []
    if args.storage_root:
        if os.path.isdir(args.storage_root):
            targets.append("storage")
        elif core:
            pending.append(f"存储根目录不存在：{args.storage_root}"
                           f"（{CORE_BLOB_DIR_ENV} 未指向已落盘的目录）")
        else:
            print(f"[BLOCKED] 存储根目录不存在：{args.storage_root}", file=sys.stderr)
            return EXIT_BLOCKED
    if args.dsn:
        targets.append("postgres")
    if args.db_file:
        if os.path.isfile(args.db_file):
            targets.append("sqlite")
        elif core:
            pending.append(f"SQLite 文件不存在：{args.db_file}")
        else:
            print(f"[BLOCKED] SQLite 文件不存在：{args.db_file}", file=sys.stderr)
            return EXIT_BLOCKED
    if args.log_cmd:
        targets.append("logs")
    elif args.log_path:
        if os.path.exists(args.log_path):
            targets.append("logs")
        elif core:
            pending.append(f"日志路径不存在：{args.log_path}（{CORE_LOG_DIR_ENV}）")
        else:
            print(f"[BLOCKED] 日志路径不存在：{args.log_path}", file=sys.stderr)
            return EXIT_BLOCKED
    if core and not args.log_path and not args.log_cmd:
        pending.append(f"日志路径未知：给 --log-path / --log-cmd，或设 {CORE_LOG_DIR_ENV}")
    if core and not args.storage_root:
        pending.append(f"{CORE_BLOB_DIR_ENV} 未设置、{CORE_BLOB_DIR_DEFAULT} 也不存在")
    if core and not args.dsn and not args.db_file:
        pending.append(f"{CORE_DSN_ENV} 未设置（拿不到 packages / package_chunks）")

    if not targets:
        if core:
            print("[PENDING] 待 Core 合入 + 参数确认 —— 下面几项还没有可用取值：",
                  file=sys.stderr)
            for item in pending:
                print(f"  · {item}", file=sys.stderr)
            print("  → 这不是 PASS 也不是 FAIL：服务端骨架还没落到 main / 还没跑起来，"
                  "没有可检对象。", file=sys.stderr)
            return EXIT_PENDING
        print("[BLOCKED] 至少给一个检索目标：--storage-root / --dsn / --db-file "
              "（或对应的 YS_* 环境变量）", file=sys.stderr)
        return EXIT_BLOCKED

    for item in pending:
        print(f"[warn] {item}")
    if core:
        print(f"[profile] core-skeleton：存储布局 <root>/<pkg[0:2]>/<pkg>/{{prelude,chunks/<idx>}}；"
              f"表白名单 {len(CORE_SCHEMA)} 张")

    print(f"[target] storage={args.storage_root or '(none)'} "
          f"postgres={redact_dsn(args.dsn) if args.dsn else '(none)'} "
          f"sqlite={args.db_file or '(none)'} "
          f"logs={(args.log_path or args.log_cmd or '(none)')}")
    print(f"[target] 检索项 {len(items)} 个 / 形态 {len(patterns)} 个 "
          f"（强 {sum(1 for i in items if i.strength == HARD)}，"
          f"弱 {sum(1 for i in items if i.strength == ADVISORY)}）")

    stats = Stats()
    hits: list[Hit] = []
    schema_notes: list[str] = []
    missing_tables: list[str] = []
    if core and "postgres" in targets:
        try:
            missing_tables, extra = core_schema_check(args.dsn, args.psql_timeout,
                                                      args.pg_schema)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"[PENDING] 待 Core 合入 + 参数确认 —— 库连上了但读不到 schema：{exc}",
                  file=sys.stderr)
            return EXIT_PENDING
        if missing_tables:
            schema_notes.append("缺表：" + "、".join(missing_tables)
                                + "（migrations 未跑 / 骨架未起）")
        schema_notes.extend(extra)
        for note in schema_notes:
            print(f"[schema] {note}")
        if extra:
            # 白名单外的表/列一律 FAIL：否则实现方改表时，白名单会静默放过
            print(f"[FAIL] schema 漂移：基线 {CORE_SCHEMA_BASELINE}"
                  f"（{len(CORE_BUSINESS_TABLES)} 张业务表 + {len(CORE_BOOKKEEPING_TABLES)} 张迁移记账表）之外还有 "
                  f"{len(extra)} 处（见上面 [schema] 行）——先确认是契约变更还是多余字段",
                  file=sys.stderr)
            return EXIT_HIT
        if len(missing_tables) == len(CORE_SCHEMA):
            print("[PENDING] 待 Core 合入 + 参数确认 —— 库里一张服务端表都没有"
                  "（migrations 未跑），现在扫出的「没命中」不能算证据。", file=sys.stderr)
            return EXIT_PENDING

    try:
        if "logs" in targets:
            if args.log_cmd:
                hits += scan_log_cmd(args.log_cmd, patterns, stats,
                                     args.max_hits_per_form, args.log_timeout)
            else:
                hits += scan_storage(args.log_path, patterns, stats,
                                     args.max_hits_per_form, target="logs")
        if "storage" in targets:
            hits += scan_storage(args.storage_root, patterns, stats, args.max_hits_per_form)
        if "postgres" in targets:
            hits += scan_postgres(args.dsn, patterns, stats, args.max_hits_per_form,
                                  args.psql_timeout, args.pg_schema)
        if "sqlite" in targets:
            hits += scan_sqlite(args.db_file, patterns, stats, args.max_hits_per_form)
    except (RuntimeError, subprocess.TimeoutExpired, sqlite3.Error) as exc:
        print(f"[BLOCKED] 检索中断：{exc}", file=sys.stderr)
        return EXIT_BLOCKED

    strength_of = {i.item_id: i.strength for i in items}
    for h in hits:
        h.strength = strength_of.get(h.item_id, ADVISORY)

    code = report(items, hits, stats, targets, args.strict, started)
    if args.json_out:
        dump_json(args.json_out, items, hits, stats, code)
    return code


if __name__ == "__main__":
    sys.exit(main())
