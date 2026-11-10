#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""服务端内嵌内核（`server/kernel/yanshu_sm.wasm`）是否等于**验收过的那份产物**。

为什么单独一条证据：同一 commit 在不同环境重建出的 wasm **sha256 可能不同**
（本沙盒实测出现过 127,313 B / `c1b87d0a…` 与 130,653 B / `8b89dd7f…` 两种，都是 v0.1.1 时代）。
如果服务端验签加载的不是验收过的那份字节，那"验签通过"这句话就没有验收基础。
**同源不等于同字节** —— 这里比 sha256，不比 commit。

检查项：

1. `server/kernel/yanshu_sm.wasm` 的 sha256 **必须等于**
   `server/internal/auth/verifier.go` 的 `FrozenKernelSHA256` 白名单**首条**
   （首条 = 当前冻结产物；当前 = `daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de`）。
   白名单是运行期真正拦人的那一份，所以它才是门槛；脚本不再另写一份期望值。
   不等 → FAIL，并打印两侧字节数与 sha，以及白名单里**每一条**（含大小），不吃"白名单只有旧值"的亏；
2. 二级校验：该产物的 `ys_version()` 必须是 `0x00010000`，导出必须是
   43 个函数 + `memory`（合计 44 导出、0 import）—— 万一将来允许不同构建，也不能连版本/导出都对不上；
3. 文件不存在 → BLOCKED（说明拿不到可核对的产物，不能当作通过）。

**内核升级时改这里的字节数与导出数**（`FROZEN_BYTES` / `FROZEN_FUNCS`），期望 sha 由
`server/internal/auth/verifier.go` 白名单**首条**自动推导（首条 = 当前冻结产物），
不再在脚本里另写一份——避免"脚本写的和线上白名单不是同一份"这种过期问题。

用法：
    python3 qa/evidence/check_server_kernel.py --server-dir <含 server/kernel 的源码根> \
        [--expect-sha <hex>] [--json-out out.json]

退出码：0 一致；1 不一致（FAIL）；2 缺参数/缺产物（BLOCKED）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "adapters" / "wasm_pack_probe.mjs"

# sha → 字节数。**只用于报错/展示**，不参与判定（判定 = verifier.go 白名单首条 + 向量套件）。
# 与 `server/internal/auth/verifier.go` 的 `FrozenKernelSHA256` 对齐；脚本运行时会自检覆盖率，
# 白名单里出现这里没登记大小的 sha 会打 [warn]（判定不受影响，但报错信息会漏大小）。
WHITELIST = {
    # 当前流式内核（140,762 B / 43 函数 + memory = 44 导出）
    "daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de": 140762,
    # 上一版流式内核（140,742 B）：回滚目标
    "8766048ffdd16b9de8c4f3fea49590ec0802418dea9ad0fdca68f0e05bb625f8": 140742,
    # 初版内核（127,313 B / 34 函数）：灰度期旧镜像
    "c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f": 127313,
    # v0.1.1 期 Core 环境从成员目录构建出的字节（130,653 B）：**不在现行白名单**，仅历史对照
    "8b89dd7fc033b9f4b316238d1d7507b161bbc74ff3547643d00981ed8da154f9": 130653,
}
# 当前冻结（v0.1.2）：140,762 B / 43 函数 + memory / 0 import；sha 从 verifier.go 白名单首条推导
FROZEN_BYTES = 140762
FROZEN_VERSION = "0x00010000"
FROZEN_FUNCS = 43

# 历史（v0.1.1 的冻结内核，回滚时对照用；v0.1.2 起不再作为期望值）：
#   FROZEN_SHA   = c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f
#   FROZEN_BYTES = 127313
#   FROZEN_FUNCS = 34

# 兜底：白名单解析失败时才用它（正常路径不读这个常量）
FROZEN_SHA_FALLBACK = "daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de"


def frozen_sha_from_whitelist(server_dir: Path) -> tuple[str, list[str]]:
    """从 server/internal/auth/verifier.go 的 sha256 白名单推导期望 sha（首条 = 当前）。

    返回 (期望 sha, 白名单全部条目)。解析不到就返回 ("", [])，由调用方报歧义。
    """
    src = server_dir / "server" / "internal" / "auth" / "verifier.go"
    if not src.is_file():
        return "", []
    text = src.read_text(encoding="utf-8", errors="replace")
    shas: list[str] = []
    for line in text.splitlines():
        m = re.search(r'"([0-9a-f]{64})"\s*:\s*true', line)
        if m:
            shas.append(m.group(1))
    return (shas[0] if shas else ""), shas


def whitelist_rows(all_shas: list[str]) -> list[tuple[str, str, str]]:
    """把 verifier.go 白名单翻成展示行：(sha, 大小串, 标签)，顺序即 verifier.go 里的顺序。"""
    rows: list[tuple[str, str, str]] = []
    for i, s in enumerate(all_shas):
        size = WHITELIST.get(s)
        rows.append((s, f"{size:,} B" if size else "大小未登记", "当前" if i == 0 else "允许加载"))
    return rows


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _node(wasm: Path, *args: str) -> tuple[int, str]:
    p = subprocess.run(["node", str(DRIVER), "--wasm", str(wasm), *args],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


def run_vector_suite(wasm: Path, vd: Path) -> bool:
    """冻结向量套件：user-code 5 组 / normalize 20 组 / sm2 验签 15 条。

    判定标准：**该产物本身**能不能跑出向量里的期望值。这是 sha 之外的"同源"证据。
    """
    ok = True
    uc = vd / "user-code-vectors.json"
    if uc.is_file():
        vec = json.loads(uc.read_text(encoding="utf-8"))["vectors"]
        bad = []
        for v in vec:
            rc, got = _node(wasm, "user-code", v["pub65"], "--wire")
            rc2, sym = _node(wasm, "check-symbol", v["pub65"], "--wire")
            if rc != 0 or got != v["code"] or (("check" in v) and sym != v["check"]):
                bad.append((v.get("name"), got, sym, v.get("code"), v.get("check")))
        print(f"{'PASS' if not bad else 'FAIL'}  向量：user-code {len(vec)} 组" +
              ("" if not bad else f"（不符：{bad[:2]}）"))
        ok = ok and not bad
    nm = vd / "normalize-vectors.json"
    if nm.is_file():
        data = json.loads(nm.read_text(encoding="utf-8"))
        vec = data["vectors"] if isinstance(data, dict) else data
        bad = []
        for v in vec:
            rc, got = _node(wasm, "normalize", v["in"])
            want_ok = bool(v.get("ok", True))
            if want_ok:
                if rc != 0 or got != v.get("out"):
                    bad.append((v.get("in"), got, v.get("out")))
            else:
                if rc == 0:
                    bad.append((v.get("in"), got, "应拒绝"))
        print(f"{'PASS' if not bad else 'FAIL'}  向量：normalize {len(vec)} 组" +
              ("" if not bad else f"（不符：{bad[:2]}）"))
        ok = ok and not bad
    sv = vd / "sm2-verify-vectors.json"
    if sv.is_file():
        vec = json.loads(sv.read_text(encoding="utf-8"))["verify_vectors"]
        bad, ran, skipped = [], 0, []
        for v in vec:
            # 口径（Rune 221c300 起）：向量自带 `executable` 字段，
            # false = 该条需要的能力超出已验证 ABI（例如验签没有 userID 入参），不计入统计。
            if v.get("executable") is False:
                skipped.append(v.get("name"))
                continue
            # 兜底：老向量没有 executable 字段时，用 userID 判断（固定默认串才可执行）
            if "executable" not in v and v.get("user_id") and v["user_id"] != "1234567812345678":
                skipped.append(v.get("name"))
                continue
            pub = v["pub65"][2:] if v["pub65"].startswith("04") else v["pub65"]
            rc, got = _node(wasm, "verify-der", pub, v["sig_input"], v["sig_der"])
            want = "PASS" if v.get("expect_verify") in (True, "True", "true") else "FAIL"
            ran += 1
            if got != want:
                bad.append((v.get("name"), got, want))
        note = (f"（{len(vec)} 条中 {ran} 条可执行；不可执行而跳过：{skipped}"
                f"——ABI 无 userID 入参，对应库层断言另行覆盖）") if skipped else ""
        print(f"{'PASS' if not bad else 'FAIL'}  向量：sm2 验签 {ran} 条{note}" +
              ("" if not bad else f"（不符：{bad[:2]}）"))
        ok = ok and not bad
    return ok


def check_git_tracking(repo: Path, expect_sha: str, ref: str = "HEAD") -> bool:
    """二进制资产必须（1）被 git 跟踪（2）blob 与工作区同字节且等于冻结值。

    这条防的是真实事故：根 `.gitignore` 的 `*.wasm` 会让 `git add -A` **静默跳过**内核，
    仓库里根本没有这个文件，别人 clone 后 `YANSHU_VERIFIER=sm2` 起不来。
    """
    rel = "server/kernel/yanshu_sm.wasm"
    ok = True

    p = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", ref, "--", rel],
                       capture_output=True, text=True)
    tracked = p.stdout.strip() == rel
    print(f"{'PASS' if tracked else 'FAIL'}  被 git 跟踪（{rel} @ {ref}）" +
          ("" if tracked else "——可能被 .gitignore 忽略（git add -A 会静默漏提交）"))
    ok = ok and tracked

    blob = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"{ref}:{rel}"],
                          capture_output=True)
    if blob.returncode != 0:
        print(f"FAIL  读不出 HEAD blob（{rel}）：{blob.stderr.decode()[:80]}")
        return False
    got = hashlib.sha256(blob.stdout).hexdigest()
    same = got == expect_sha
    print(f"{'PASS' if same else 'FAIL'}  HEAD blob sha256 == 冻结值（{len(blob.stdout):,} 字节 / {got[:16]}…）")
    ok = ok and same

    wt = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--", rel],
                        capture_output=True, text=True)
    clean = wt.stdout.strip() == ""
    print(f"{'PASS' if clean else 'WARN'}  工作区与 HEAD 一致（未提交改动：{wt.stdout.strip() or '无'}）")
    return ok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="服务端内嵌内核是否等于冻结产物")
    ap.add_argument("--server-dir", required=True, help="源码根（其下有 server/kernel/yanshu_sm.wasm）")
    ap.add_argument("--expect-sha", default=None,
                    help="只认这一个 sha（默认走白名单 + 向量套件）")
    ap.add_argument("--git-ref", default="HEAD", help="要核的提交（默认 HEAD）")
    ap.add_argument("--repo", default=None,
                    help="源码仓库路径；给了就额外验「被 git 跟踪 + blob sha == 冻结值」")
    ap.add_argument("--vectors-dir", default=None,
                    help="冻结向量目录（含 user-code-vectors.json / normalize-vectors.json / sm2-verify-vectors.json）；"
                         "给了就跑向量套件")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    wasm = Path(args.server_dir) / "server" / "kernel" / "yanshu_sm.wasm"
    if not wasm.is_file():
        print(f"[BLOCKED] 找不到内嵌内核：{wasm}\n"
              f"           （该文件不在 git 里，只能在工作树里核对；拿不到就不能算通过）",
              file=sys.stderr)
        return 2

    got_sha = sha256_of(wasm)
    got_bytes = wasm.stat().st_size
    derived, all_shas = frozen_sha_from_whitelist(Path(args.server_dir))
    expect = args.expect_sha or derived or FROZEN_SHA_FALLBACK
    if not derived and not args.expect_sha:
        print(f"[warn] 未能从 verifier.go 推导白名单，回落到兜底常量 {FROZEN_SHA_FALLBACK[:12]}…")
    if args.expect_sha:
        print(f"[note] 用 --expect-sha 覆盖期望值：{args.expect_sha}（不是白名单首条；"
              f"白名单首条是 {derived or '解析失败'}）")
    elif len(all_shas) > 1:
        print(f"[note] verifier.go 白名单共 {len(all_shas)} 条，取**首条**为当前期望：{expect[:12]}…")
    if all_shas:
        unknown = [s for s in all_shas if s not in WHITELIST]
        if unknown:
            print("[warn] verifier.go 白名单有 %d 条没在本脚本 WHITELIST 登记大小（判定不受影响，"
                  "但下次报错会漏大小，记得补）：%s"
                  % (len(unknown), ", ".join(s[:12] + "…" for s in unknown)))
    if args.expect_sha:
        ok_sha = got_sha == args.expect_sha
    else:
        ok_sha = got_sha == expect
    if not ok_sha:
        # 报错信息不能骗人：列的是 verifier.go 里**真正**的白名单（首条才是期望值），
        # 而不是脚本里那张只供展示的表（历史上就是这张表漏了新 sha，让人以为"白名单只有旧值"）。
        print("[note] verifier.go 白名单（首条 = 当前期望；白名单不只一条，别只看这个列表判断对错）：")
        if all_shas:
            for s, size, tag in whitelist_rows(all_shas):
                print(f"        {s}  {size}  [{tag}]")
        else:
            print("        （解析不到 verifier.go，回落到脚本静态表，仅供参照）：")
            for s, size in WHITELIST.items():
                print(f"        {s}  {size:,} B")

    print("=" * 88)
    print("服务端内嵌内核 vs 验收冻结产物")
    print("=" * 88)
    print(f"文件     ：{wasm}")
    print(f"实际     ：{got_bytes:,} 字节  sha256={got_sha}")
    print(f"冻结期望 ：{FROZEN_BYTES:,} 字节  sha256={expect}  "
          f"（{'--expect-sha 覆盖' if args.expect_sha else '来自 verifier.go 白名单首条'}）")
    print(f"{'PASS' if ok_sha else 'FAIL'}  内核 sha256 {'一致' if ok_sha else '不一致——服务端验的不是验收过的那份产物'}")
    ok_bytes = got_bytes == FROZEN_BYTES
    print(f"{'PASS' if ok_bytes else 'FAIL'}  字节数 {got_bytes:,}（期望 {FROZEN_BYTES:,}，"
          f"check_server_kernel.py 的 FROZEN_BYTES）")

    ok_meta = True
    p = subprocess.run(["node", str(DRIVER), "--wasm", str(wasm), "exports"],
                       capture_output=True, text=True)
    ver = subprocess.run(["node", str(DRIVER), "--wasm", str(wasm), "version"],
                         capture_output=True, text=True)
    if p.returncode != 0 or ver.returncode != 0:
        print(f"FAIL  读不出导出/版本：exports rc={p.returncode} version rc={ver.returncode}")
        ok_meta = False
    else:
        info = json.loads(p.stdout.strip())
        version = ver.stdout.strip().split()[0]
        ok_v = version == FROZEN_VERSION
        ok_f = info["functions"] == FROZEN_FUNCS and info.get("hasMemory") is True
        print(f"{'PASS' if ok_v else 'FAIL'}  ys_version() = {version}（期望 {FROZEN_VERSION}）")
        print(f"{'PASS' if ok_f else 'FAIL'}  导出 = {info['functions']} 函数 + "
              f"{'memory' if info.get('hasMemory') else '无 memory'}（期望 {FROZEN_FUNCS} + memory）")
        ok_meta = ok_v and ok_f

    ok_git = True
    if args.repo:
        ok_git = check_git_tracking(Path(args.repo), expect, args.git_ref)
    else:
        print("SKIP  git 跟踪/blob sha（未给 --repo）")

    ok_vec = True
    if args.vectors_dir:
        vd = Path(args.vectors_dir)
        ok_vec = run_vector_suite(wasm, vd)
    else:
        print("SKIP  向量套件（未给 --vectors-dir）")

    ok = ok_sha and ok_bytes and ok_meta and ok_vec and ok_git
    print("-" * 88)
    print("结论：" + ("PASS —— 服务端加载的就是验收过的那份产物" if ok else
                    "FAIL —— 内嵌内核与冻结产物不一致（先换成冻结产物，再看其他证据）"))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "ok": ok, "path": str(wasm), "bytes": got_bytes, "sha256": got_sha,
            "expect_sha256": expect, "expect_bytes": FROZEN_BYTES,
            "version": ver.stdout.strip(), "exports": json.loads(p.stdout) if p.returncode == 0 else None,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
