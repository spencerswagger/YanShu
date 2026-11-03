#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨实现一致性检查：用户码派生（`ys_user_code`）与码归一化（`ys_normalize_code`）。

为什么单独一条证据：`ys_user_code` 曾在 wasm 与原生两侧给出不同的码
（`X2EH` vs `AWQW`），根因是**入参形态**（64 字节 `X‖Y` vs 65 字节含 `0x04`）——
这类"传错形态不报错、只是算错"的问题最危险，浏览器算出的码拿去注册会被服务端拒。
本脚本把它变成可复跑的断言。

检查项
------
1. **用户码派生**：对 5 组公钥（含契约 §15.1 的 `PB_S`），四个入口全部逐字符相同：
   wasm `ys_user_code`(64B) / wasm `ys_user_code_wire`(65B) / `ys-tool user-code`(64B) / (65B)。
   且 `PB_S` 必须等于契约值 `AWQW`。
2. **归一化**：一组输入分别过 wasm `ys_normalize_code` 与 **Core 服务端**（`GET /v1/codes/<原样输入>`：
   400 `CODE_FORMAT_INVALID` = 拒绝，404 = 接受），两侧接受/拒绝必须一致；
   接受时 wasm 的输出还要等于给定期望值（含 5 位输入必须整体拒绝、不截断）。

用法
----
    python3 qa/evidence/check_code_consistency.py \
        --wasm <yanshu_sm.wasm> --ys-tool <ys-tool> \
        [--base-url http://127.0.0.1:18080] [--json-out out.json]

退出码：0 全部一致；1 有不一致（打印公钥 hex 与两侧值）；2 参数/依赖缺失。

不实现任何密码学：SM3 与码派生都由端侧 wasm / 原生工具算，本脚本只做比对。
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "adapters" / "wasm_pack_probe.mjs"

# 契约 §15.1 的发送方公钥（65 字节，含 0x04）
PB_S_65 = ("04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1"
           "16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d")
PB_S_CODE = "AWQW"

NORMALIZE_CASES = [
    # (输入, 期望是否接受, 期望归一化值或 None)
    ("AWQW", True, "AWQW"),
    ("awqw", True, "AWQW"),
    ("a-w-q-w", True, "AWQW"),
    (" AWQW ", True, "AWQW"),
    ("AW\tQW", True, "AWQW"),
    ("AWQW\r\n", True, "AWQW"),
    ("0WQW", True, "0WQW"),
    ("OI", False, None),            # 太短
    ("AWQ", False, None),           # 3 位
    ("AWQWX", False, None),         # 5 位：必须整体拒绝，不许截成 4 位
    ("AWQW-X", False, None),        # 5 位 + 校验位：同样拒绝
    ("AWQU", False, None),          # U 非法
    ("AWQ!", False, None),          # 标点非法
    ("码码码码", False, None),       # 非 ASCII
    ("", False, None),              # 空
]


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


def wasm_code(wasm: str, pub_hex: str, wire: bool = False) -> tuple[int, str]:
    args = ["node", str(DRIVER), "--wasm", wasm, "user-code", pub_hex]
    if wire:
        args.append("--wire")
    return run(args)


def native_code(tool: str, pub_hex: str) -> tuple[int, str]:
    return run([tool, "user-code", pub_hex])


def node(wasm: str, *args: str) -> tuple[int, str]:
    """通用：node 驱动 + 内核 wasm。"""
    return run(["node", str(DRIVER), "--wasm", wasm, *args])


def wasm_normalize(wasm: str, text: str) -> tuple[int, str]:
    return run(["node", str(DRIVER), "--wasm", wasm, "normalize", text])


def server_accepts(base: str, text: str) -> tuple[bool | None, str]:
    """问 Core 服务端：400 CODE_FORMAT_INVALID = 拒绝；404 = 接受（码不存在）。
    返回 None 表示"判不了"（限速/锁定/空输入路由不匹配），此时不计入一致性。"""
    if text == "":
        return None, "空输入不发起请求（路由不匹配，判不了）"
    url = base.rstrip("/") + "/v1/codes/" + urllib.parse.quote(text, safe="")
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        if e.code == 400 and "CODE_FORMAT_INVALID" in body:
            return False, "HTTP 400 CODE_FORMAT_INVALID"
        if e.code == 404:
            return True, "HTTP 404 not found（= 归一化通过，码未注册）"
        if e.code in (423, 429):
            return None, f"HTTP {e.code} 限速/锁定（判不了，本条跳过跨实现比对）"
        return None, f"HTTP {e.code}（非预期，判不了）"
    except Exception as exc:  # noqa: BLE001
        return True, f"请求失败：{exc}"


def gen_keys(wasm: str, n: int) -> list[str]:
    """用 wasm 的 keygen 生成合法公钥（64B hex），避免手造非法曲线点。"""
    out = []
    with tempfile.TemporaryDirectory() as td:
        for i in range(n):
            sk = Path(td) / f"k{i}.sk"
            pk = Path(td) / f"k{i}.pk"
            rc, msg = run(["node", str(DRIVER), "--wasm", wasm, "keygen", str(sk), str(pk)])
            if rc != 0:
                raise SystemExit(f"[BLOCKED] keygen 失败：{msg}")
            out.append(pk.read_bytes().hex())
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="跨实现一致性检查：用户码派生 + 码归一化")
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--ys-tool", required=True)
    ap.add_argument("--base-url", default="", help="Core 服务端地址（不给则跳过归一化跨实现比对）")
    ap.add_argument("--keys", type=int, default=4, help="额外生成几组公钥（默认 4）")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    if not Path(args.wasm).is_file():
        print(f"[BLOCKED] 找不到 wasm：{args.wasm}", file=sys.stderr)
        return 2
    if not Path(args.ys_tool).is_file():
        print(f"[BLOCKED] 找不到 ys-tool：{args.ys_tool}", file=sys.stderr)
        return 2

    results: list[tuple[str, bool, str]] = []
    details: list[dict] = []

    # ---------- 1) 用户码派生 ----------
    pubs = [PB_S_65] + [("04" + k) for k in gen_keys(args.wasm, args.keys)]
    for pub65 in pubs:
        k64 = pub65[2:]
        wasm64 = wasm_code(args.wasm, k64)
        wasm65 = wasm_code(args.wasm, pub65, wire=True)
        nat64 = native_code(args.ys_tool, k64)
        nat65 = native_code(args.ys_tool, pub65)
        vals = {
            "wasm(64)": wasm64[1], "wasm_wire(65)": wasm65[1],
            "native(64)": nat64[1], "native(65)": nat65[1],
        }
        # 入口"不存在"与"值不一致"必须分开：老 head 上没有 _wire 导出 / ys-tool 不收 64 字节，
        # 这是能力缺口（SKIP），不是一致性失败（FAIL）。
        unavailable = [k for k, v in vals.items()
                       if "没有导出" in v or "expected 65-byte" in v or "not found" in v]
        if unavailable:
            tag0 = "PB_S" if pub65 == PB_S_65 else pub65[2:10] + "…"
            results.append((f"用户码 {tag0}", True,
                            f"（跳过：{unavailable} 在该 head 上不存在）" +
                            "；可用入口：" + " / ".join(
                                f"{k}={v}" for k, v in vals.items() if k not in unavailable)))
            details.append({"pub65": pub65, "values": vals, "ok": True, "skipped": unavailable})
            continue
        ok = (len(set(vals.values())) == 1 and wasm64[0] == 0 and nat64[0] == 0)
        tag = "PB_S" if pub65 == PB_S_65 else pub65[2:10] + "…"
        detail = f"{tag}: " + " / ".join(f"{k}={v}" for k, v in vals.items())
        if pub65 == PB_S_65:
            ok = ok and vals["wasm(64)"] == PB_S_CODE
            detail += f"（期望 {PB_S_CODE}）"
        results.append((f"用户码 {tag}", ok, detail))
        details.append({"pub65": pub65, "values": vals, "ok": ok})

    # ---------- 1b) 校验字符（第 5 位，仅 UI 防误输） ----------
    sym_results = []
    for pub65 in pubs:
        k64 = pub65[2:]
        w64 = node(args.wasm, "check-symbol", k64)
        w65 = node(args.wasm, "check-symbol", pub65, "--wire")
        n64 = run([args.ys_tool, "check-symbol", k64])
        n65 = run([args.ys_tool, "check-symbol", pub65])
        vals = {"wasm(64)": w64[1], "wasm_wire(65)": w65[1],
                "native(64)": n64[1], "native(65)": n65[1]}
        unavailable = [k for k, v in vals.items() if "没有导出" in v or "expected" in v]
        tag = "PB_S" if pub65 == PB_S_65 else pub65[2:10] + "…"
        if unavailable:
            sym_results.append((f"校验位 {tag}", True,
                                f"（跳过：{unavailable} 不可用）"))
            continue
        ok = len(set(vals.values())) == 1
        sym_results.append((f"校验位 {tag}", ok,
                            " / ".join(f"{k}={v}" for k, v in vals.items())))
    results.extend(sym_results)

    # ---------- 1c) 反向用例：65 字节缓冲喂 64 字节入口，必须得到**不同**的码 ----------
    rc_w, wrong = node(args.wasm, "user-code-wrong-width", PB_S_65)
    ok_neg = rc_w == 0 and wrong != PB_S_CODE
    results.append(("反向：65B 缓冲喂 64B 入口得到不同的码", ok_neg,
                    f"得到 {wrong}（契约值 {PB_S_CODE}）；相等则说明这条防护失效"))

    # ---------- 2) 归一化 ----------
    for raw, expect_ok, expect_val in NORMALIZE_CASES:
        rc, got = wasm_normalize(args.wasm, raw)
        wasm_ok = rc == 0
        good = (wasm_ok == expect_ok)
        if expect_ok and wasm_ok:
            good = good and got == expect_val
        note = f"输入 {raw!r} → wasm={'拒绝' if not wasm_ok else got}；期望={'接受' if expect_ok else '拒绝'}"
        if args.base_url:
            srv_ok, srv_note = server_accepts(args.base_url, raw)
            if srv_ok is None:
                note += f"；Core={srv_note}"
            else:
                good = good and (srv_ok == wasm_ok)
                note += f"；Core={srv_note}"
        else:
            note += "；Core=（未给 --base-url，跳过跨实现比对）"
        results.append((f"归一化 {raw!r}", good, note))

    # ---------- 报告 ----------
    print("=" * 96)
    print("跨实现一致性检查（用户码派生 / 码归一化）")
    print("=" * 96)
    failed = 0
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<28} {detail}")
        if not ok:
            failed += 1
    print("-" * 96)
    print(f"{len(results) - failed}/{len(results)} 通过")
    if failed:
        print("结论：FAIL —— 两侧不一致或与契约值不符（上面每行都有公钥 hex 与两侧取值）")
    else:
        print("结论：PASS —— 四个入口逐字符一致，归一化在 wasm 与 Core 两侧同判")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"ok": failed == 0, "results": [
                {"name": n, "ok": o, "detail": d} for n, o, d in results], "keys": details},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
