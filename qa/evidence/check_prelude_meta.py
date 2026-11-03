#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prelude-only 元数据语义验收（"能看，但必须标明未校验"）。

背景：契约 §4.3 的 prelude = `HEADER‖SENDER_PUB‖WRAPPED_KEY‖MANIFEST_SEC‖SIG_SEC`，
清单与来源签名都在里面，所以**不必等块到齐**就能显示"谁发的、多大、什么名字"。
风险是"看起来成功、其实完整性没验"这种模糊态，因此内核给了两个入口：

* `ys_unpack_meta_prelude(pack≥prelude, priv)` → JSON `"scope":"prelude"` + **`"data_verified":false`**
* `ys_unpack_meta(_v1)(整包)` → prelude-only 输入**必须拒绝**（`CRYPTO_TRUNCATED`）

本脚本验三条：

1. **正向**：只给 prelude → 成功、`scope=="prelude"`、`data_verified==false`，
   且 `name/mime/size/chunk_size/chunk_count/sender_code` 与整包解出的元信息一致；
2. **反向**：同一份 prelude 喂 `ys_unpack_meta_v1`（与 7 参 `ys_unpack_meta`）→ 必须 `CRYPTO_TRUNCATED`；
3. **篡改联动**：改 `SENDER_PUB` 1 字节 / 改 `MANIFEST_SEC` 1 字节 → `_prelude` 必须失败
   （证明"未校验"≠"完全没校验"）。

用法：
    python3 qa/evidence/check_prelude_meta.py --wasm <wasm> --yspk <包> --recipient-sk <sk> \
        [--json-out out.json]
    # 没有现成包时：给 --wasm 与 --recipient-pk/--sender-sk，用内核现打一个

退出码：0 全 PASS；1 有 FAIL；2 参数缺失。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "adapters" / "wasm_pack_probe.mjs"
sys.path.insert(0, str(HERE))
from tamper_probe import parse_envelope  # noqa: E402


def node(wasm: str, *args: str) -> tuple[int, str]:
    p = subprocess.run(["node", str(DRIVER), "--wasm", wasm, *args],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip() or (p.stderr or "").strip()


def build_pack(wasm: str, work: Path) -> tuple[Path, Path]:
    """用内核现打一个 2 块包（含 prelude-only 需要的全部段）。"""
    sk, pk = work / "bob.sk", work / "bob.pk"
    ask = work / "alice.sk"
    rc, msg = node(wasm, "keygen", str(sk), str(pk))
    if rc != 0:
        raise SystemExit(f"[BLOCKED] keygen 失败：{msg}")
    rc, msg = node(wasm, "keygen", str(ask), str(work / "alice.pk"))
    if rc != 0:
        raise SystemExit(f"[BLOCKED] keygen 失败：{msg}")
    plain = work / "plain.bin"
    plain.write_bytes(os.urandom(1600) + "鸿雁".encode())
    pack = work / "p.yspk"
    rc, msg = node(wasm, "pack", str(plain), str(pack), "--recipient-pk", str(pk),
                   "--sender-sk", str(ask), "--name", "prelude-probe.txt",
                   "--mime", "text/plain", "--ext", "txt", "--chunk-size", "1024")
    if rc != 0:
        raise SystemExit(f"[BLOCKED] pack 失败：{msg}")
    return pack, sk


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="prelude-only 元数据语义验收")
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--yspk", help="现成包（不给则用内核现打一个）")
    ap.add_argument("--recipient-sk", help="收件人私钥文件（不给则现生成）")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    if not Path(args.wasm).is_file():
        print(f"[BLOCKED] 找不到 wasm：{args.wasm}", file=sys.stderr)
        return 2

    tmp = tempfile.mkdtemp(prefix="ys-prelude-")
    work = Path(tmp)
    if args.yspk and args.recipient_sk:
        pack, sk = Path(args.yspk), Path(args.recipient_sk)
    else:
        pack, sk = build_pack(args.wasm, work)

    raw = pack.read_bytes()
    env = parse_envelope(raw)
    prelude = raw[:env.prelude_len]
    prelude_path = work / "prelude.bin"
    prelude_path.write_bytes(prelude)

    results: list[tuple[str, bool, str]] = []

    # ---- 1) 正向：只给 prelude ----
    rc, out = node(args.wasm, "meta-prelude", str(prelude_path), "--recipient-sk", str(sk))
    ok_pos = rc == 0
    meta = {}
    if ok_pos:
        try:
            meta = json.loads(out)
        except json.JSONDecodeError:
            ok_pos = False
    detail = f"rc={rc}"
    if ok_pos:
        ok_pos = (meta.get("scope") == "prelude" and meta.get("data_verified") is False)
        detail = f"scope={meta.get('scope')} data_verified={meta.get('data_verified')} " \
                 f"name={meta.get('name')} size={meta.get('size')} " \
                 f"chunk_count={meta.get('chunk_count')} sender_code={meta.get('sender_code')}"
    else:
        detail += f" out={out[:120]}"
    results.append(("prelude-only 元信息可解且标注未校验", ok_pos, detail))

    # 与整包元信息比对
    rc_full, out_full = node(args.wasm, "meta", str(pack), "--recipient-sk", str(sk), "--v1")
    ok_same = False
    if rc_full == 0:
        try:
            full = json.loads(out_full)
        except json.JSONDecodeError:
            full = {}
        keys = ("name", "mime", "ext", "size", "chunk_size", "chunk_count", "sender_code")
        diff = {k: (meta.get(k), full.get(k)) for k in keys if meta.get(k) != full.get(k)}
        ok_same = (full.get("scope") == "full" and not diff)
        results.append(("prelude 元信息与整包一致", ok_same,
                        "字段一致" if ok_same else f"差异：{diff}；full.scope={full.get('scope')}"))
    else:
        results.append(("prelude 元信息与整包一致", False, f"整包 meta 失败：{out_full[:120]}"))

    # ---- 2) 反向：prelude 喂整包入口必须拒绝 ----
    for label, extra in (("_v1", ["--v1"]), ("7 参原型", [])):
        rc_n, out_n = node(args.wasm, "meta", str(prelude_path), "--recipient-sk", str(sk), *extra)
        rejected = rc_n != 0 and "CRYPTO_TRUNCATED" in out_n
        results.append((f"prelude-only 喂 ys_unpack_meta{label} 必须拒绝", rejected,
                        f"rc={rc_n} {out_n[:80]}"))

    # ---- 3) 篡改联动 ----
    def tampered(off: int, name: str) -> tuple[str, bool, str]:
        b = bytearray(prelude)
        b[off] ^= 0x01
        p = work / f"prelude-{name}.bin"
        p.write_bytes(bytes(b))
        rc_t, out_t = node(args.wasm, "meta-prelude", str(p), "--recipient-sk", str(sk))
        ok = rc_t != 0
        return (f"篡改 {name} 后 _prelude 必须失败", ok, f"rc={rc_t} {out_t[:80]}")

    results.append(tampered(112, "SENDER_PUB[0]"))            # SENDER_PUB 段首字节
    manifest_off = 112 + env_sender_pub_len(raw) + 129        # MANIFEST_SEC 首字节
    results.append(tampered(manifest_off, "MANIFEST_SEC[0]"))

    print("=" * 96)
    print("prelude-only 元数据语义（能看，但必须标明未校验）")
    print("=" * 96)
    failed = 0
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<42} {detail}")
        if not ok:
            failed += 1
    print("-" * 96)
    print(f"{len(results) - failed}/{len(results)} 通过")
    print("结论：PASS —— prelude-only 能读元信息且显式标注未校验；整包入口拒绝半包"
          if failed == 0 else "结论：FAIL")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"ok": failed == 0, "results": [{"name": n, "ok": o, "detail": d} for n, o, d in results]},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if failed == 0 else 1


def env_sender_pub_len(raw: bytes) -> int:
    """从 HEADER 里取 SENDER_PUB_LEN（offset 52, u32be），默认 65。"""
    import struct
    return struct.unpack_from(">I", raw, 52)[0] or 65


if __name__ == "__main__":
    sys.exit(main())
