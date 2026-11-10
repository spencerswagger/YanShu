#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""干净环境真实收发自测（一条命令，可复跑）。

它回答四个问题，全部要**原始证据**、不看报告数字：
  1. 纯净检出 + 空数据目录 + 新库，能不能起得来并**真收真发**（逐块 sha256 两侧一致）；
  2. `down && up` 之后**密钥不变**（secrets 文件 sha256 一致），且重启前已上传的密文
     能原样取回（sha256 不变）、`upload_token` 仍然有效（说明 TOKEN_SECRET 没被换掉）；
  3. 契约违例**必须报错**：终结态上传 → `410`、伪造凭据 → `401`、未路由路径 → 错误信封
     （信封这条在 main 未合 #58 时记 SKIP，不冒充通过）；
  4. 建索引期间**写入不被阻塞**：同一张表上普通 `CREATE INDEX`（事务）会挡住写，
     `CREATE INDEX CONCURRENTLY` 不会 —— 两次实测对比，而不是读迁移文件推断。

用法：
  python3 qa/evidence/release/clean_env_selftest.py \
      --ref origin/main --dsn "$TEST_DATABASE_URL" [--work /tmp/yanshu-clean] \
      [--rows 600000] [--skip-index] [--skip-restart] [--keep] [--json-out out.json]

前置：`go`、`psql`、`git`；DSN 的角色要能 `CREATE DATABASE`。
退出码：0 全过；1 有 FAIL；2 前置缺失（BLOCKED，不算失败）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "qa" / "evidence" / "v5"))
import ysv5 as Y  # noqa: E402  已合入 main 的共用件（SM3 / Client / 用户码派生）

EXIT_PASS, EXIT_FAIL, EXIT_BLOCKED = 0, 1, 2


# ---------------------------------------------------------------- 小工具

def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def psql(dsn: str, sql: str, timeout: float = 600) -> tuple[int, str]:
    p = subprocess.run(["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", dsn, "-c", sql],
                       capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    return p.returncode, out


def dsn_with_db(dsn: str, db: str) -> str:
    u = urllib.parse.urlsplit(dsn)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, "/" + db, u.query, ""))


def init_secrets(d: Path) -> dict[str, Path]:
    """与 compose 的 `init` 容器同口径：文件不存在或为空才生成（hex、0600）。

    每次 `up` 之前都跑一遍 —— 这样"有人把 `[ -s ]` 判断去掉 → up 重新生成密钥"这种真实
    回退才会被测试看见；只在首次生成、之后不再执行 init 的写法，down/up 那两条断言结构上
    不可能红（Owl 复审 P1）。
    """
    out = {}
    for name, nbytes in (("token_secret", 32), ("pg_password", 24)):
        f = d / name
        if (not f.exists()) or f.stat().st_size == 0:
            f.write_text(os.urandom(nbytes).hex())
            f.chmod(0o600)
        out[name] = f
    return out


def build_env(port: int, keys: dict[str, Path], dsn_db: str, blobs: Path, logs: Path) -> dict:
    """每次启动都**从文件重新读** secret —— 否则测的是"我把同一个值喂给了两个进程"。"""
    return dict(os.environ,
                YANSHU_ENV="test", YANSHU_VERIFIER="stub-allow",
                YANSHU_ADDR=f"127.0.0.1:{port}",
                YANSHU_DATABASE_URL=dsn_db,
                YANSHU_BLOB_DIR=str(blobs),
                YANSHU_LOG_DIR=str(logs),
                YANSHU_TOKEN_SECRET=keys["token_secret"].read_text().strip(),
                YANSHU_TOKEN_EPOCH="1",
                YANSHU_SWEEP_INTERVAL="1s",
                _HEALTH=f"http://127.0.0.1:{port}/healthz")


def unsafe_work(p: Path) -> str:
    """防手滑：`--work` 会被 rmtree，绝不允许指向 /、家目录、仓库本身或其父目录。"""
    p = p.resolve()
    if p in (Path("/"), Path("/tmp"), Path.home(), REPO):
        return "禁区路径"
    if p == REPO or REPO in p.parents:
        return "不能在工作树内删"
    if len(p.parts) < 3:
        return "路径太浅（至少两段）"
    return ""


class Report:
    def __init__(self, title: str, subtitle: str = ""):
        self.title, self.subtitle = title, subtitle
        self.rows: list[tuple[str, str, str]] = []
        self.notes: list[str] = []
        self.raw: dict = {}

    def add(self, name: str, ok, ev: str = "") -> None:
        kind = "PASS" if ok is True else ("FAIL" if ok is False else "WARN")
        self.rows.append((name, kind, ev))
        print(f"{kind:<4}  {name:<46} {ev[:110]}", flush=True)

    def note(self, text: str) -> None:
        self.notes.append(text)
        print(f"note  {text}", flush=True)

    def emit(self, json_out: str | None) -> int:
        bad = [r for r in self.rows if r[1] == "FAIL"]
        warn = [r for r in self.rows if r[1] == "WARN"]
        ok = [r for r in self.rows if r[1] == "PASS"]
        print("-" * 96)
        print(f"PASS {len(ok)}　WARN(SKIP) {len(warn)}　FAIL {len(bad)}　共 {len(self.rows)} 项　结论："
              + ("PASS" if not bad else "FAIL"))
        if json_out:
            Path(json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(json_out).write_text(json.dumps({
                "title": self.title, "subtitle": self.subtitle, "at": now(),
                "rows": [{"name": n, "kind": k, "evidence": e} for n, k, e in self.rows],
                "notes": self.notes, "raw": self.raw,
                "verdict": "PASS" if not bad else "FAIL",
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        return EXIT_PASS if not bad else EXIT_FAIL


# ---------------------------------------------------------------- 服务端进程

class Proc:
    def __init__(self, binary: Path, env: dict, cwd: Path, log: Path):
        self.binary, self.env, self.cwd, self.log = binary, env, cwd, log
        self.p: subprocess.Popen | None = None

    def start(self, timeout: float = 40) -> bool:
        self.log.parent.mkdir(parents=True, exist_ok=True)
        f = open(self.log, "ab")
        self.p = subprocess.Popen([str(self.binary)], env=self.env, cwd=str(self.cwd),
                                  stdout=f, stderr=subprocess.STDOUT)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.p.poll() is not None:
                return False
            try:
                with urllib.request.urlopen(self.env["_HEALTH"], timeout=1) as r:
                    if r.status == 200:
                        return True
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        return False

    def stop(self, timeout: float = 20) -> tuple[bool, str]:
        if not self.p or self.p.poll() is not None:
            return True, "already stopped"
        self.p.send_signal(signal.SIGTERM)
        try:
            self.p.wait(timeout=timeout)
            return True, f"exit={self.p.returncode}"
        except subprocess.TimeoutExpired:
            self.p.kill()
            return False, "SIGTERM 超时，已 kill"


# ---------------------------------------------------------------- 建索引锁写（实测）

class Writer(threading.Thread):
    def __init__(self, dsn: str, table: str, gap: float = 0.02):
        super().__init__(daemon=True)
        self.dsn, self.table, self.gap = dsn, table, gap
        self.samples: list[tuple[float, float, float]] = []
        self.errors: list[str] = []
        self.stop_flag = threading.Event()

    def run(self) -> None:
        i = 0
        while not self.stop_flag.is_set():
            i += 1
            t0 = time.monotonic()
            rc, out = psql(self.dsn, f"INSERT INTO {self.table} (k) VALUES (md5('w{i}'))", timeout=180)
            t1 = time.monotonic()
            if rc != 0:
                self.errors.append(out[:160])
            self.samples.append((t0, t1, (t1 - t0) * 1000))
            self.stop_flag.wait(self.gap)


def window(samples, t0: float, t1: float) -> dict:
    vals = sorted(ms for (s, e, ms) in samples if e >= t0 and s <= t1)
    if not vals:
        return {"n": 0}
    return {"n": len(vals), "max_ms": round(max(vals), 1),
            "p50_ms": round(statistics.median(vals), 1),
            "over_300ms": sum(1 for v in vals if v > 300)}


def index_lock_check(dsn: str, rows: int) -> tuple[bool, str, dict]:
    """普通 CREATE INDEX 会挡写、CONCURRENTLY 不会 —— 用同一路 writer 量。"""
    psql(dsn, "DROP TABLE IF EXISTS selftest_idx")
    rc, out = psql(dsn, f"""CREATE TABLE selftest_idx (id bigserial PRIMARY KEY, k text NOT NULL);
INSERT INTO selftest_idx (k) SELECT md5(i::text) FROM generate_series(1, {rows}) i;
ANALYZE selftest_idx;""", timeout=300)
    if rc != 0:
        return False, f"造数失败：{out[:80]}", {}

    w = Writer(dsn, "selftest_idx")
    w.start()
    time.sleep(2.0)
    try:
        a0 = time.monotonic()
        rc, out = psql(dsn, "BEGIN; CREATE INDEX idx_plain ON selftest_idx (k); COMMIT;")
        a1 = time.monotonic()
        if rc != 0:
            return False, f"普通建索引失败：{out[:80]}", {}
        time.sleep(1.5)
        psql(dsn, "DROP INDEX idx_plain")
        time.sleep(0.5)
        b0 = time.monotonic()
        rc, out = psql(dsn, "CREATE INDEX CONCURRENTLY idx_conc ON selftest_idx (k)")
        b1 = time.monotonic()
        if rc != 0:
            return False, f"CONCURRENTLY 建索引失败：{out[:80]}", {}
        time.sleep(1.0)
    finally:
        w.stop_flag.set()
        w.join(timeout=180)

    base, a, b = window(w.samples, 0, a0), window(w.samples, a0, a1), window(w.samples, b0, b1)
    a_build, b_build = (a1 - a0) * 1000, (b1 - b0) * 1000
    if a_build < 300:
        return False, f"索引建得太快（{a_build:.0f}ms），阻塞窗口不可判定：加大 --rows", \
            {"base": base, "plain": a, "concurrent": b, "a_build_ms": round(a_build, 1),
             "b_build_ms": round(b_build, 1)}
    ok = a.get("max_ms", 0) >= 300 and b.get("max_ms", 99999) < 300 and not w.errors
    ev = (f"普通建索引 {a_build:.0f}ms/写最长 {a.get('max_ms')}ms（>300ms {a.get('over_300ms')} 条）；"
          f"CONCURRENTLY {b_build:.0f}ms/写最长 {b.get('max_ms')}ms")
    return ok, ev, {"base": base, "plain": a, "concurrent": b,
                    "a_build_ms": round(a_build, 1), "b_build_ms": round(b_build, 1),
                    "writer_errors": w.errors[:3]}


# ---------------------------------------------------------------- 主流程

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="干净环境真实收发自测")
    ap.add_argument("--ref", default="origin/main", help="纯净检出的 git ref（默认 origin/main）")
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--work", default="/tmp/yanshu-clean-env")
    ap.add_argument("--rows", type=int, default=600000, help="建索引锁写用的行数")
    ap.add_argument("--skip-index", action="store_true")
    ap.add_argument("--skip-restart", action="store_true")
    ap.add_argument("--keep", action="store_true", help="保留工作目录与新库（排障用）")
    ap.add_argument("--allow-no-envelope", action="store_true",
                    help="树里没有 #58（fallback.go）时允许把 §0.2 记 WARN；默认按 FAIL（防空转）")
    ap.add_argument("--selftest-break-keys", action="store_true",
                    help="自检用：down 之后偷偷换掉 token_secret，验证「secrets sha256 不变」会红")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    if not args.dsn:
        print("[BLOCKED] 需要 --dsn 或 TEST_DATABASE_URL", file=sys.stderr)
        return EXIT_BLOCKED
    for tool in ("git", "go", "psql"):
        if not shutil.which(tool):
            print(f"[BLOCKED] 缺 {tool}", file=sys.stderr)
            return EXIT_BLOCKED

    work = Path(args.work).resolve()
    if why := unsafe_work(work):
        print(f"[BLOCKED] --work {work} 不允许（{why}）", file=sys.stderr)
        return EXIT_BLOCKED

    src = work / "src"
    secrets = work / "secrets"
    blobs, logs, bindir = work / "blobs", work / "logs", work / "bin"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    db = f"yanshu_selftest_{stamp.lower()}"

    rep = Report("干净环境真实收发自测", f"ref={args.ref} work={work} db={db} at={now()}")
    srv: Proc | None = None
    db_created = False
    try:
        if work.exists() and not args.keep:
            shutil.rmtree(work)
        for d in (src, secrets, blobs, logs, bindir):
            d.mkdir(parents=True, exist_ok=True)

        # 0) 纯净检出
        try:
            rev = subprocess.run(["git", "-C", str(REPO), "rev-parse", args.ref],
                                 capture_output=True, text=True, check=True).stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"[BLOCKED] 取不到 {args.ref}：{e}", file=sys.stderr)
            return EXIT_BLOCKED
        p1 = subprocess.Popen(["git", "-C", str(REPO), "archive", rev], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["tar", "-x", "-C", str(src)], stdin=p1.stdout)
        p1.stdout.close()
        p2.communicate()
        if p1.wait() != 0 or p2.returncode != 0:
            print("[BLOCKED] git archive 失败（ref 不存在？）", file=sys.stderr)
            return EXIT_BLOCKED
        rep.raw["ref"], rep.raw["commit"] = args.ref, rev
        n_files = sum(1 for _ in src.rglob("*") if _.is_file())
        rep.add("纯净检出（无 .git、空数据目录）",
                not (src / ".git").exists() and n_files > 50,
                f"commit={rev[:12]} files={n_files}")

        # 1) 新库
        rc, out = psql(args.dsn, f'CREATE DATABASE "{db}"')
        if rc != 0:
            print(f"[BLOCKED] 建库失败：{out}", file=sys.stderr)
            return EXIT_BLOCKED
        db_created = True
        dsn_db = dsn_with_db(args.dsn, db)
        rc, n = psql(dsn_db, "select count(*) from information_schema.tables where table_schema='public'")
        rep.add("新库是空的（迁移前 public 无表）", rc == 0 and n == "0", f"tables={n}")

        # 2) 密钥（compose init 同口径）
        keys = init_secrets(secrets)
        key_sha1 = {k: sha256_file(p) for k, p in keys.items()}
        modes = {k: oct(p.stat().st_mode & 0o777) for k, p in keys.items()}
        rep.add("secrets 首次生成（0600，hex）",
                all(modes[k] == "0o600" for k in modes)
                and all(re.fullmatch(r"[0-9a-f]+", p.read_text()) for p in keys.values()),
                f"sha256={ {k: v[:12] for k, v in key_sha1.items()} } mode={modes}")

        # 3) 构建 + 首次启动（env 从文件读）
        binpath = bindir / "yanshu-server"
        b = subprocess.run(["go", "build", "-o", str(binpath), "./cmd/yanshu-server"],
                           cwd=str(src / "server"), capture_output=True, text=True)
        if b.returncode != 0:
            print(f"[BLOCKED] 构建失败：{b.stderr[-400:]}", file=sys.stderr)
            return EXIT_BLOCKED
        bin_sha = sha256_file(binpath)
        rep.raw["binary_sha256"] = bin_sha
        port = free_port()
        srv = Proc(binpath, build_env(port, keys, dsn_db, blobs, logs),
                   src / "server", logs / "selftest-server.log")
        ok = srv.start()
        rep.add("首次启动（空数据目录 + 新库，迁移自动落库）", ok,
                f"healthz={'200' if ok else 'FAIL'} log={srv.log}")
        if not ok:
            return EXIT_FAIL

        base = f"http://127.0.0.1:{port}"
        c = Y.Client(base)
        sender, _ = c.register_pair("clean-sender", "发送方")
        recipient, _ = c.register_pair("clean-recipient", "接收方")

        # 4) 真收真发 A
        chunk_size = 262144
        ta = Y.make_transfer(c, sender, recipient, size=chunk_size * 3,
                             chunk_size=chunk_size, chunks=3)
        tid_a = ta["transfer_id"]
        tdir = blobs / tid_a[:2] / tid_a
        rep.add("上传完成后密文确实落盘（ack 前）", tdir.is_dir(),
                f"{tdir.relative_to(blobs)} exists={tdir.is_dir()}")
        st, prelude = c.get_prelude(tid_a)
        dl = c.headers.get("x-ys-download-id", "")
        got_sha, want_sha = [], [sha256_bytes(ta["prelude"])]
        pre_ok = st == 200 and isinstance(prelude, bytes) and prelude == ta["prelude"]
        for i in range(3):
            stc, data = c.get_chunk(tid_a, i, dl)
            want_sha.append(sha256_bytes(ta["chunks"][i]))
            got_sha.append(sha256_bytes(data) if isinstance(data, bytes) else "err")
            pre_ok = pre_ok and stc == 200 and data == ta["chunks"][i]
        sta, ack = c.ack(tid_a, recipient, dl)
        rep.raw["transfer_a"] = {"transfer_id": tid_a, "sha256": want_sha}
        rep.add("真收真发 A：prelude+3 块逐字节一致 + ack→CONSUMED",
                pre_ok and sta == 200 and ack.get("state") == "CONSUMED",
                f"sha256(prelude)={want_sha[0][:12]}… blocks={[s[:8] for s in got_sha]} ack={sta} {ack.get('state')}")
        rep.add("ack 后密文物理删除", not tdir.is_dir(), f"残留={tdir.is_dir()}")

        # 5) 真收真发 B（留 READY 给重启比对）
        tb = Y.make_transfer(c, sender, recipient, size=chunk_size,
                             chunk_size=chunk_size, chunks=1)
        tid_b = tb["transfer_id"]
        st, pb = c.get_prelude(tid_b)
        dlb = c.headers.get("x-ys-download-id", "")
        stc, cb = c.get_chunk(tid_b, 0, dlb)
        sha_b_before = {"prelude": sha256_bytes(pb) if isinstance(pb, bytes) else "err",
                        "chunk0": sha256_bytes(cb) if isinstance(cb, bytes) else "err"}
        rep.raw["transfer_b"] = {"transfer_id": tid_b, "sha256_before": sha_b_before}
        rep.add("真收真发 B：留一条 READY 供 down/up 后比对",
                st == 200 and stc == 200 and sha_b_before["prelude"] == sha256_bytes(tb["prelude"]),
                f"tid={tid_b[:12]} sha={ {k: v[:10] for k, v in sha_b_before.items()} }")

        # 6) 契约违例
        st410, raw410 = c.call("PUT", f"/v1/transfers/{tid_a}/prelude", ta["prelude"],
                               {"Content-Type": "application/octet-stream"})
        body410 = raw410 if isinstance(raw410, dict) else {}
        code410 = (body410.get("error") or {}).get("code", "") if isinstance(body410, dict) else ""
        rep.add("契约 §1.7.4：终结态上传必须 410（且不返回 401）",
                st410 == 410 and code410 == "TRANSFER_CONSUMED", f"{st410} {code410}")

        bogus = Y.b64u(os.urandom(32))
        st401, body401 = c.put_prelude(tid_b, bogus, tb["prelude"])
        code401 = (body401.get("error") or {}).get("code", "") if isinstance(body401, dict) else ""
        rep.add("契约 §1.7.4：未终结 + 伪造凭据必须 401 AUTH_TOKEN_INVALID",
                st401 == 401 and code401 == "AUTH_TOKEN_INVALID", f"{st401} {code401}")

        stx, raw = c.call("GET", "/v1/definitely-not-an-endpoint")
        # ysv5.Client.call 已经按 content-type 解过 JSON（这里拿到的是 dict），
        # 只有非 JSON 响应（例如未合 #58 时的 text/plain）才是 bytes —— 别再对 dict 调 json.loads。
        try:
            obj = raw if isinstance(raw, dict) else (json.loads(raw) if raw else {})
            is_env = isinstance(obj.get("error"), dict) and bool(obj["error"].get("code"))
            codex = (obj.get("error") or {}).get("code", "")
        except Exception:  # noqa: BLE001
            is_env, codex = False, ""
        # 树里有 #58（fallback.go）→ 信封是硬要求，坏了必须红；
        # 只有显式 --allow-no-envelope 才允许把"树里没有 #58"记 WARN（不冒充通过）。
        has_fallback = (src / "server/internal/httpapi/fallback.go").is_file()
        if is_env:
            rep.add("契约 §0.2：未路由路径必须是错误信封",
                    stx == 404 and codex == "ROUTE_NOT_FOUND", f"{stx} {codex}")
        elif has_fallback:
            rep.add("契约 §0.2：未路由路径必须是错误信封", False,
                    f"{stx} {raw[:60]!r}（树里有 fallback.go，却回非信封）")
        elif args.allow_no_envelope:
            rep.add("契约 §0.2：未路由路径必须是错误信封", None,
                    f"{stx} text/plain（树里无 fallback.go，--allow-no-envelope 记 SKIP）")
        else:
            rep.add("契约 §0.2：未路由路径必须是错误信封", False,
                    f"{stx} text/plain（树里无 fallback.go；要放过请显式 --allow-no-envelope）")

        # 7) 建索引锁写
        if args.skip_index:
            rep.add("建索引期间写入不被阻塞（跳过）", None, "--skip-index")
        else:
            ok_idx, ev_idx, raw_idx = index_lock_check(dsn_db, args.rows)
            rep.raw["index_lock"] = raw_idx
            rep.add("建索引期间写入不被阻塞（普通 vs CONCURRENTLY 实测）", ok_idx, ev_idx)

        # 8) down && up
        if args.skip_restart:
            rep.add("down && up 后密钥不变（跳过）", None, "--skip-restart")
        else:
            stopped, how = srv.stop()
            rep.add("down：进程正常退出", stopped, how)
            if args.selftest_break_keys:
                (secrets / "token_secret").write_text(os.urandom(32).hex())
                rep.note("--selftest-break-keys：已故意改写 token_secret，下面「secrets sha256 不变」应 FAIL")
            keys_up = init_secrets(secrets)          # 每次 up 都重跑 init（真实部署语义）
            srv.env = build_env(port, keys_up, dsn_db, blobs, logs)
            ok2 = srv.start()
            key_sha_up = {k: sha256_file(p) for k, p in keys_up.items()}
            # 只存 sha256，绝不存密钥原值（secret scanner 会咬；行里也只打前 12 位）
            rep.raw["secrets_sha256"] = {"before": key_sha1, "up": key_sha_up}
            rep.add("down && up 后 secrets sha256 不变",
                    key_sha1 == key_sha_up and ok2,
                    f"token={key_sha_up['token_secret'][:12]}… pg={key_sha_up['pg_password'][:12]}…")
            st, pb2 = c.get_prelude(tid_b)
            dl2 = c.headers.get("x-ys-download-id", "")
            stc2, cb2 = c.get_chunk(tid_b, 0, dl2)
            sha_b_after = {"prelude": sha256_bytes(pb2) if isinstance(pb2, bytes) else "err",
                           "chunk0": sha256_bytes(cb2) if isinstance(cb2, bytes) else "err"}
            rep.raw["transfer_b"]["sha256_after"] = sha_b_after
            rep.add("重启后取回同一密文 sha256 不变",
                    st == 200 and stc2 == 200 and sha_b_after == sha_b_before,
                    f"before={sha_b_before['prelude'][:10]}… after={sha_b_after['prelude'][:10]}…")
            sts, _ = c.json("GET", f"/v1/transfers/{tid_b}/status", None,
                            {"X-YS-Upload-Token": tb["upload_token"]})
            # 注意：这条只证明"凭据不因重启失效"，**不能**用来证明 secret 没换 ——
            # upload_token 的校验是 SM3(token) 与库里哈希比对，secret 只作派生盐。
            # 密钥不变的证明在上面那条 secrets 文件 sha256（每次 up 前重跑 init 后再比）。
            rep.add("重启后旧 upload_token 仍可用（凭据不因重启失效）", sts == 200,
                    f"status={sts}（secret 不作验签，密钥不变见上行）")

        rep.note(f"binary sha256={bin_sha}")
        return rep.emit(args.json_out)
    finally:
        if srv is not None:
            srv.stop()
        if db_created and not args.keep:
            psql(args.dsn, f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        if not args.keep and work.exists():
            shutil.rmtree(work, ignore_errors=True)
            print(f"note  工作目录已删除：{work}")
        elif args.keep:
            print(f"note  工作目录保留：{work}　db={db}")


if __name__ == "__main__":
    raise SystemExit(main())
