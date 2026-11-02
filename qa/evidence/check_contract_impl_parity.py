#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""契约字面 vs 实现返回的**双向一致性核对**。

今晚错误名来回改了五次（`REVOKED`/`STALE`/`EXPIRED` 反复），根因就是"文档一套、实现另一套"。
这条做成常驻检查后，谁多写/漏写一个码，脚本直接判 FAIL，不需要人传话。

核对方式：
* **契约侧**：`git show <ref>:docs/API.md`（默认 `origin/docs/contract-clarify`，只读，不碰工作区）；
* **实现侧**：`server/internal/spec/errors.go` 里的字符串字面量（那是错误码的唯一来源）；
* 两侧都先剔除 **PURPOSE 名**（`REGISTER`/`NICKNAME_UPDATE`/`TRANSFER_CREATE`/`TRANSFER_REVOKE`/
  `INBOX_LIST`/`WS_HELLO`/`TRANSFER_ACK`/`UPLOAD_TOKEN_ISSUE`）——它们长得像码但不是码。

判定：
1. 契约有、实现无 → **FAIL**（契约描述了不存在的行为）；
2. 实现有、契约无 → **FAIL**（实现提供了未定义的行为）；
3. `AUTH_TOKEN_REVOKED` 出现在**任何一侧** → **FAIL**（终值不含该名）；
4. 与 `--expect` 白名单比对（默认就是当前的四码 + `AUTH_CODE_MISMATCH` + 三个 `TRANSFER_*`）。

退出码：0 完全一致；1 有差异；2 取不到契约/实现（BLOCKED）。
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

PURPOSES = {
    "REGISTER", "NICKNAME_UPDATE", "TRANSFER_CREATE", "TRANSFER_REVOKE",
    "INBOX_LIST", "WS_HELLO", "TRANSFER_ACK", "UPLOAD_TOKEN_ISSUE",
}
CODE_RE = re.compile(r"\b(AUTH_[A-Z_]+|TRANSFER_[A-Z_]+)\b")

# 非错误码的"长得像码"的标识（字段名 / 通知名 / 状态机名），两侧都不参与码比对。
NON_CODE = {"TRANSFER_ID", "TRANSFER_ID_ASCII", "TRANSFER_NOTICE", "TRANSFER_STATE"}

EXPECTED = {
    "AUTH_TOKEN_STALE", "AUTH_TOKEN_INVALID", "AUTH_TOKEN_EXPIRED",
    "AUTH_SIGNATURE_INVALID", "AUTH_CODE_MISMATCH",
    "TRANSFER_EXPIRED", "TRANSFER_CONSUMED", "TRANSFER_REVOKED",
}
FORBIDDEN = {"AUTH_TOKEN_REVOKED"}


def git_show(repo: Path, ref: str, path: str) -> str | None:
    p = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:{path}"],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def codes_from(text: str) -> set[str]:
    return {m for m in CODE_RE.findall(text) if m not in PURPOSES and m not in NON_CODE}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="/worktrees/YS-QA")
    ap.add_argument("--contract-ref", default="origin/docs/contract-clarify")
    ap.add_argument("--contract-path", default="docs/API.md")
    ap.add_argument("--impl-path", default="server/internal/spec/errors.go")
    ap.add_argument("--impl-ref", default="", help="实现侧取哪个 commit（空=工作区文件）")
    ap.add_argument("--expect", action="store_true",
                    help="额外按固定白名单判（默认只判「两侧一一对应 + 禁用名」）")
    args = ap.parse_args(argv)

    repo = Path(args.repo)
    contract = git_show(repo, args.contract_ref, args.contract_path)
    if contract is None:
        print(f"[BLOCKED] 取不到契约：{args.contract_ref}:{args.contract_path}", file=sys.stderr)
        return 2

    impl_path = repo / args.impl_path
    if args.impl_ref:
        impl = git_show(repo, args.impl_ref, args.impl_path)
    else:
        impl = impl_path.read_text(encoding="utf-8") if impl_path.is_file() else None
    if impl is None:
        print(f"[BLOCKED] 取不到实现：{args.impl_path}", file=sys.stderr)
        return 2

    c, i = codes_from(contract), codes_from(impl)
    print("=" * 88)
    print("契约字面 vs 实现返回：双向一致性核对")
    print("=" * 88)
    print(f"契约（{args.contract_ref}:{args.contract_path}）：{len(c)} 个 → {sorted(c)}")
    print(f"实现（{args.impl_path}）：{len(i)} 个 → {sorted(i)}")
    print("-" * 88)

    bad = 0
    only_c = sorted(c - i)
    only_i = sorted(i - c)
    if only_c:
        print(f"FAIL  契约有、实现无（契约描述了不存在的行为）：{only_c}")
        bad += 1
    else:
        print("PASS  契约里的每个码在实现里都能找到")
    if only_i:
        print(f"FAIL  实现有、契约无（实现提供了未定义的行为）：{only_i}")
        bad += 1
    else:
        print("PASS  实现返回的每个码在契约里都有定义")

    hit = sorted((c | i) & FORBIDDEN)
    if hit:
        print(f"FAIL  禁用名出现：{hit}（终值不含 AUTH_TOKEN_REVOKED）")
        bad += 1
    else:
        print("PASS  禁用名 AUTH_TOKEN_REVOKED 在两侧都不存在")

    all_codes = c | i
    extra = sorted(all_codes - EXPECTED)
    missing = sorted(EXPECTED - all_codes)
    if args.expect:
        if extra:
            print(f"FAIL  出现白名单之外的码：{extra}")
            bad += 1
        if missing:
            print(f"FAIL  白名单里的码缺失：{missing}")
            bad += 1
        if not extra and not missing:
            print("PASS  与期望白名单完全一致")
    else:
        print(f"INFO  两侧共有的码 {len(all_codes)} 个：{sorted(all_codes)}")
        if extra:
            print(f"INFO  白名单之外的码（两侧都有，属已定义已实现）：{extra}")
        if missing:
            print(f"INFO  白名单里但两侧都没有的码：{missing}")

    print("-" * 88)
    print("结论：" + ("PASS —— 契约与实现字面一一对应" if bad == 0 else "FAIL —— 两侧不一致，见上方逐条"))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
