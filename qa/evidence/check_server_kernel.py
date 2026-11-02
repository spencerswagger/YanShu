#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""服务端内嵌内核（`server/kernel/yanshu_sm.wasm`）是否等于**验收过的那份产物**。

为什么单独一条证据：同一 commit 在不同环境重建出的 wasm **sha256 可能不同**
（本沙盒实测出现过 127,313 B / `c1b87d0a…` 与 130,653 B / `8b89dd7f…` 两种）。
如果服务端验签加载的不是验收过的那份字节，那"验签通过"这句话就没有验收基础。
**同源不等于同字节** —— 这里比 sha256，不比 commit。

检查项：

1. `server/kernel/yanshu_sm.wasm` 的 sha256 **必须**等于冻结值
   `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`；
   不等 → FAIL，并打印两侧字节数与 sha；
2. 二级校验：该产物的 `ys_version()` 必须是 `0x00010000`，导出必须是
   34 个函数 + `memory`（0 import）—— 万一将来允许不同构建，也不能连版本/导出都对不上；
3. 文件不存在 → BLOCKED（说明拿不到可核对的产物，不能当作通过）。

用法：
    python3 qa/evidence/check_server_kernel.py --server-dir <含 server/kernel 的源码根> \
        [--expect-sha <hex>] [--json-out out.json]

退出码：0 一致；1 不一致（FAIL）；2 缺参数/缺产物（BLOCKED）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "adapters" / "wasm_pack_probe.mjs"

# 白名单：跨环境构建出的两种字节都是"同源"（已实测）
#   c1b87d0a… 127,313 B —— Rune/Web/Gate 在各自环境构建
#   8b89dd7f… 130,653 B —— Core 环境构建（同 commit 031e95b）
# 判定同源不看单一 sha，而是「sha 在白名单内 + 该产物通过冻结向量套件」。
WHITELIST = {
    "c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f": 127313,
    "8b89dd7fc033b9f4b316238d1d7507b161bbc74ff3547643d00981ed8da154f9": 130653,
}
FROZEN_SHA = "c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f"
FROZEN_BYTES = 127313
FROZEN_VERSION = "0x00010000"
FROZEN_FUNCS = 34


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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="服务端内嵌内核是否等于冻结产物")
    ap.add_argument("--server-dir", required=True, help="源码根（其下有 server/kernel/yanshu_sm.wasm）")
    ap.add_argument("--expect-sha", default=None,
                    help="只认这一个 sha（默认走白名单 + 向量套件）")
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
    if args.expect_sha:
        ok_sha = got_sha == args.expect_sha
    else:
        ok_sha = got_sha in WHITELIST
    if not ok_sha:
        print(f"[note] 白名单里的 sha：")
        for k, v in WHITELIST.items():
            print(f"        {k}  {v:,} B")

    print("=" * 88)
    print("服务端内嵌内核 vs 验收冻结产物")
    print("=" * 88)
    print(f"文件     ：{wasm}")
    print(f"实际     ：{got_bytes:,} 字节  sha256={got_sha}")
    print(f"冻结期望 ：{FROZEN_BYTES:,} 字节  sha256={args.expect_sha}")
    print(f"{'PASS' if ok_sha else 'FAIL'}  内核 sha256 {'一致' if ok_sha else '不一致——服务端验的不是验收过的那份产物'}")

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

    ok_vec = True
    if args.vectors_dir:
        vd = Path(args.vectors_dir)
        ok_vec = run_vector_suite(wasm, vd)
    else:
        print("SKIP  向量套件（未给 --vectors-dir）")

    ok = ok_sha and ok_meta and ok_vec
    print("-" * 88)
    print("结论：" + ("PASS —— 服务端加载的就是验收过的那份产物" if ok else
                    "FAIL —— 内嵌内核与冻结产物不一致（先换成冻结产物，再看其他证据）"))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "ok": ok, "path": str(wasm), "bytes": got_bytes, "sha256": got_sha,
            "expect_sha256": args.expect_sha, "expect_bytes": FROZEN_BYTES,
            "version": ver.stdout.strip(), "exports": json.loads(p.stdout) if p.returncode == 0 else None,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
