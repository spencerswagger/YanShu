#!/usr/bin/env python3
"""雁书 YanShu · 测试向量比对

比对 `testdata/vectors.json`（本实现产出）与"对照值"。对照值有两个来源：

  1. **本机 GmSSL**（可选）：`gmssl` 命令行 + 链接 `libgmssl.a` 的 oracle，
     逐字节重算；SM2 通过覆盖 rand_bytes 固定 k，所以密文/签名也能逐字节比。
  2. **宿主侧对照值**：`testdata/gmssl-expected.json`（结构见 `--emit-template`）。
     文件不存在或字段为空 → 该条打印 `SKIP 待宿主对照`，**不算 FAIL**。

两个来源都没有时，脚本仍然跑完并给出 SKIP 汇总，退出码 0 —— 这样宿主值一到
直接落文件再跑，不用改代码。

退出码：0 = 无 FAIL（可能全是 SKIP）；1 = 有 FAIL；2 = 环境/文件缺失。

用法见同目录 run.sh 头部注释。
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

GMSSL_BIN = os.environ.get("GMSSL_BIN", "gmssl")
GMSSL_ORACLE = os.environ.get("GMSSL_ORACLE", "")
YS_TOOL = os.environ.get("YS_TOOL", "")

LOCAL = False
EXT = None

PASS = 0
FAIL = 0
SKIP = 0
FAILURES = []


# ---------------------------------------------------------------- 结果统计


def ok(label):
    global PASS
    PASS += 1
    print(f"  PASS  {label}")


def bad(label, detail=""):
    global FAIL
    FAIL += 1
    FAILURES.append((label, detail))
    print(f"  FAIL  {label}" + (f"  ({detail})" if detail else ""))


def skip(label, why="待宿主对照"):
    global SKIP
    SKIP += 1
    print(f"  SKIP  {label}  ({why})")


def first_diff(a: str, b: str):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return n
    return -1


def cmp_text(label, ours, theirs):
    if ours == theirs:
        ok(label)
    else:
        d = first_diff(ours, theirs)
        bad(
            label,
            f"first diff at {d}; ours={ours[max(0, d - 8): d + 24]!r} "
            f"theirs={theirs[max(0, d - 8): d + 24]!r}",
        )


def compare(label, ours, local_fn=None, ext_val=None):
    """本地 GmSSL 与宿主对照值，有几个比几个；都没有就 SKIP。"""
    ran = 0
    if LOCAL and local_fn is not None:
        cmp_text(label, ours, local_fn())
        ran += 1
    if ext_val is not None:
        cmp_text("ext/" + label, ours, ext_val)
        ran += 1
    if ran == 0:
        skip(label)


def ext_get(*path):
    node = EXT
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    if node is None or node == "":
        return None
    if isinstance(node, bool):
        return None
    if isinstance(node, int):
        return str(node)
    if not isinstance(node, str):
        return None
    return node


# ---------------------------------------------------------------- 外部命令


def run(cmd, stdin=None):
    p = subprocess.run(cmd, input=stdin, capture_output=True)
    return p.returncode, p.stdout, p.stderr


def oracle(*args):
    rc, out, err = run([GMSSL_ORACLE, *args])
    if rc != 0:
        raise RuntimeError(f"oracle {' '.join(args[:2])} failed: {err.decode(errors='replace')}")
    return out.decode().strip()


def cli(*args, stdin=b""):
    rc, out, err = run([GMSSL_BIN, *args], stdin=stdin)
    if rc != 0:
        raise RuntimeError(f"gmssl {' '.join(args)} failed: {err.decode(errors='replace')}")
    return out


def ystool(*args):
    rc, out, err = run([YS_TOOL, *args])
    return rc, out.decode().strip(), err.decode(errors="replace")


def memo(fn):
    box = {}

    def inner():
        if "v" not in box:
            box["v"] = fn()
        return box["v"]

    return inner


# ---------------------------------------------------------------- Crockford Base32

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def crockford_first4(digest: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in digest)
    return "".join(ALPHABET[int(bits[i * 5 : i * 5 + 5], 2)] for i in range(4))


def normalize_code(s: str) -> str:
    out = []
    for ch in s:
        if ch in "- \t\r\n":
            continue
        c = ch.upper()
        c = {"O": "0", "I": "1", "L": "1"}.get(c, c)
        if c not in ALPHABET:
            raise ValueError(f"invalid symbol {ch!r}")
        out.append(c)
    if len(out) != 4:
        raise ValueError("length must be 4")
    return "".join(out)


# ---------------------------------------------------------------- 加密包格式（按锚点重拼）

MAGIC = b"YSPK"
VERSION = 1
SUITE = 1
FLAGS = 1
HEADER_LEN = 40
TAG_LEN = 16
KEY_REC_KIND = 1
SIG_REC_KIND = 2
BLOCK_FLAG_LAST = 1
MANIFEST_NONCE = bytes([0xFF] * 8 + [0x80, 0, 0, 0])
SALT_BLOCK = b"YanShu/v1/block"
SALT_MANIFEST = b"YanShu/v1/manifest"


def block_nonce(index: int, is_last: bool) -> bytes:
    return (
        index.to_bytes(4, "big")
        + b"\x00\x00\x00\x00"
        + bytes([1 if is_last else 0])
        + b"\x00\x00\x00"
    )


def header_bytes(file_id, block_size, block_count, plain_size) -> bytes:
    return (
        MAGIC
        + bytes([VERSION, SUITE, FLAGS, 0])
        + file_id
        + block_size.to_bytes(4, "big")
        + block_count.to_bytes(4, "big")
        + plain_size.to_bytes(8, "big")
    )


def expected_block_count(plain_size, block_size):
    return 1 if plain_size == 0 else (plain_size + block_size - 1) // block_size


def block_plain_len(plain_size, block_size, index):
    count = expected_block_count(plain_size, block_size)
    if index + 1 < count:
        return block_size
    return plain_size - (count - 1) * block_size


def hkdf(salt, ikm, info, length):
    return bytes.fromhex(oracle("hkdf", salt.hex(), ikm.hex(), info.hex(), str(length)))


def gcm_enc(key, nonce, aad, pt):
    out = bytes.fromhex(oracle("gcm-enc", key.hex(), nonce.hex(), aad.hex(), pt.hex()))
    return out[:-TAG_LEN], out[-TAG_LEN:]


def sm3(data):
    return bytes.fromhex(oracle("sm3", data.hex()))


def rebuild_pack(v) -> bytes:
    data = bytes.fromhex(v["data"])
    file_id = bytes.fromhex(v["file_id"])
    dk = bytes.fromhex(v["dk"])
    block_size = v["block_size"]
    plain_size = len(data)
    block_count = expected_block_count(plain_size, block_size)
    header = header_bytes(file_id, block_size, block_count, plain_size)

    block_key = hkdf(SALT_BLOCK, dk, file_id, 16)
    manifest_key = hkdf(SALT_MANIFEST, dk, file_id, 16)

    blocks = []
    digests = []
    for i in range(block_count):
        start = i * block_size
        ln = block_plain_len(plain_size, block_size, i)
        pt = data[start : start + ln]
        is_last = i + 1 == block_count
        ct, tag = gcm_enc(block_key, block_nonce(i, is_last), header, pt)
        digests.append(sm3(ct + tag))
        blocks.append((i, BLOCK_FLAG_LAST if is_last else 0, ct, tag))

    name = v["file_name"].encode()
    mime = v["mime"].encode()
    manifest_plain = (
        len(name).to_bytes(2, "big")
        + name
        + len(mime).to_bytes(2, "big")
        + mime
        + block_size.to_bytes(4, "big")
        + block_count.to_bytes(4, "big")
        + plain_size.to_bytes(8, "big")
        + len(digests).to_bytes(4, "big")
        + b"".join(digests)
    )

    sig = bytes.fromhex(
        oracle("sm2-sign", v["sender_priv"], v["k_sign"], (header + manifest_plain).hex())
    )
    wrapped = bytes.fromhex(oracle("sm2-enc", v["recipient_pub"], v["k_wrap"], dk.hex()))
    man_ct, man_tag = gcm_enc(manifest_key, MANIFEST_NONCE, header, manifest_plain)

    out = bytearray()
    out += header
    out += bytes([KEY_REC_KIND]) + len(wrapped).to_bytes(4, "big") + wrapped
    out += bytes([SIG_REC_KIND]) + len(sig).to_bytes(4, "big") + sig
    out += len(man_ct).to_bytes(4, "big") + man_ct + man_tag
    for i, flags, ct, tag in blocks:
        out += i.to_bytes(4, "big") + bytes([flags]) + len(ct).to_bytes(4, "big") + ct + tag
    return bytes(out)


# ---------------------------------------------------------------- 模板


def emit_template(vectors, path):
    """生成宿主侧对照值模板：填满 expected 字段后另存为 gmssl-expected.json。"""
    t = {
        "meta": {
            "how": "用 GmSSL 3.1.1 按 vectors.json 的 conventions 复算，把空字符串填上；"
            "填不出的留空即可（脚本会 SKIP 该条）。",
            "suite": vectors["meta"]["suite"],
        },
        "sm3": {},
        "hmac_sm3": {},
        "hkdf_sm3": {},
        "sm4_gcm": {},
        "sm2": {"keys": {}, "encrypt": {}, "sign": {}},
        "user_codes": {},
        "pack": {},
    }
    for c in vectors["sm3"]:
        t["sm3"][c["name"]] = {"msg": c["msg"], "digest": ""}
    for c in vectors["hmac_sm3"]:
        t["hmac_sm3"][c["name"]] = {"key": c["key"], "msg": c["msg"], "tag": ""}
    for c in vectors["hkdf_sm3"]:
        t["hkdf_sm3"][c["name"]] = {
            "salt": c["salt"],
            "ikm": c["ikm"],
            "info": c["info"],
            "len": c["len"],
            "okm": "",
        }
    for c in vectors["sm4_gcm"]:
        t["sm4_gcm"][c["name"]] = {
            "key": c["key"],
            "nonce": c["nonce"],
            "aad": c["aad"],
            "plaintext": c["plaintext"],
            "ciphertext": "",
            "tag": "",
        }
    for k in vectors["sm2"]["keys"]:
        t["sm2"]["keys"][k["name"]] = {"priv": k["priv"], "pub": "", "za": ""}
    for c in vectors["sm2"]["encrypt"]:
        t["sm2"]["encrypt"][c["name"]] = {
            "pub": c["pub"],
            "k": c["k"],
            "plaintext": c["plaintext"],
            "ciphertext": "",
        }
    for c in vectors["sm2"]["sign"]:
        t["sm2"]["sign"][c["name"]] = {
            "priv": c["priv"],
            "pub": c["pub"],
            "k": c["k"],
            "msg": c["msg"],
            "sig": "",
        }
    for c in vectors["user_codes"]:
        t["user_codes"][c["name"]] = {"pub": c["pub"], "code": ""}
    for v in vectors["pack"]:
        t["pack"][v["name"]] = {
            "recipient_pub": v["recipient_pub"],
            "sender_priv": v["sender_priv"],
            "sender_pub": v["sender_pub"],
            "dk": v["dk"],
            "file_id": v["file_id"],
            "k_wrap": v["k_wrap"],
            "k_sign": v["k_sign"],
            "block_size": v["block_size"],
            "file_name": v["file_name"],
            "mime": v["mime"],
            "data": v["data"],
            "pack": "",
        }
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(t, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"模板已写入 {path}；填满空字符串后作为 --expected 传入（默认 testdata/gmssl-expected.json）。")


# ---------------------------------------------------------------- 主流程


def main():
    global LOCAL, EXT

    ap = argparse.ArgumentParser(description="雁书测试向量比对")
    ap.add_argument("--vectors", default=os.path.join(ROOT, "testdata", "vectors.json"))
    ap.add_argument("--expected", default=os.path.join(ROOT, "testdata", "gmssl-expected.json"))
    ap.add_argument("--emit-template", metavar="PATH", help="生成宿主侧对照值模板后退出")
    ap.add_argument("--no-local", action="store_true", help="忽略本机 GmSSL，只用外部对照值")
    args = ap.parse_args()

    if not os.path.exists(args.vectors):
        print(f"向量文件缺失：{args.vectors}", file=sys.stderr)
        return 2
    vectors = json.load(open(args.vectors, encoding="utf-8"))

    if args.emit_template:
        emit_template(vectors, args.emit_template)
        return 0

    local_ready = (
        not args.no_local
        and bool(GMSSL_ORACLE)
        and os.path.exists(GMSSL_ORACLE)
        and bool(GMSSL_BIN)
        and os.path.exists(GMSSL_BIN)
    )
    LOCAL = local_ready
    if os.path.exists(args.expected):
        EXT = json.load(open(args.expected, encoding="utf-8"))
        ext_desc = args.expected
    else:
        EXT = None
        ext_desc = f"{args.expected}（不存在）"

    print(f"vectors : {args.vectors}")
    print(f"对照源1 : {'本机 GmSSL' if LOCAL else '不可用'}"
          f"{'  ' + GMSSL_BIN if LOCAL else ''}")
    print(f"对照源2 : {ext_desc}")

    if not LOCAL and EXT is None:
        print(
            "\n没有任何对照源：本实现自身的一致性由 `cargo test` 覆盖；"
            "逐字节对照待宿主提供 testdata/gmssl-expected.json 后即可跑（无需改代码）。"
        )

    # ---- A1. SM3
    print("\n[A1] SM3")
    for c in vectors["sm3"]:
        compare(
            f"sm3/{c['name']}",
            c["digest"],
            local_fn=lambda c=c: cli("sm3", stdin=bytes.fromhex(c["msg"])).decode().strip(),
            ext_val=ext_get("sm3", c["name"], "digest"),
        )

    # ---- A2. HMAC-SM3 / HKDF-SM3
    print("\n[A2] HMAC-SM3 / HKDF-SM3")
    for c in vectors["hmac_sm3"]:
        compare(
            f"hmac-sm3/{c['name']}",
            c["tag"],
            local_fn=lambda c=c: oracle("hmac-sm3", c["key"], c["msg"]),
            ext_val=ext_get("hmac_sm3", c["name"], "tag"),
        )
    for c in vectors["hkdf_sm3"]:
        compare(
            f"hkdf/{c['name']}",
            c["okm"],
            local_fn=lambda c=c: oracle("hkdf", c["salt"], c["ikm"], c["info"], str(c["len"])),
            ext_val=ext_get("hkdf_sm3", c["name"], "okm"),
        )

    # ---- A3. SM4-GCM
    print("\n[A3] SM4-GCM")
    for c in vectors["sm4_gcm"]:
        def _local(c=c):
            a = ["sm4", "-gcm", "-encrypt", "-key", c["key"], "-iv", c["nonce"]]
            if c["aad"]:
                a += ["-aad_hex", c["aad"]]
            return cli(*a, stdin=bytes.fromhex(c["plaintext"])).hex()

        combined = memo(_local) if LOCAL else None
        compare(
            f"sm4-gcm/{c['name']}/ct",
            c["ciphertext"],
            local_fn=(lambda f=combined: f()[:-32]) if LOCAL else None,
            ext_val=ext_get("sm4_gcm", c["name"], "ciphertext"),
        )
        compare(
            f"sm4-gcm/{c['name']}/tag",
            c["tag"],
            local_fn=(lambda f=combined: f()[-32:]) if LOCAL else None,
            ext_val=ext_get("sm4_gcm", c["name"], "tag"),
        )
        # 反向：GmSSL 输出 → 本实现解密（只有本机有 GmSSL 才能做）
        if LOCAL:
            ct, tag = combined()[:-32], combined()[-32:]
            rc, out, err = ystool("gcm-dec", c["key"], c["nonce"], c["aad"], ct, tag)
            if rc == 0 and out == c["plaintext"]:
                ok(f"reverse/sm4-gcm/{c['name']}")
            else:
                bad(f"reverse/sm4-gcm/{c['name']}", f"rc={rc} {err[:80]}")
        else:
            skip(f"reverse/sm4-gcm/{c['name']}", "需要本机 GmSSL")

    # ---- A4. SM2
    print("\n[A4] SM2")
    for k in vectors["sm2"]["keys"]:
        compare(
            f"sm2/{k['name']}/pubkey",
            k["pub"],
            local_fn=lambda k=k: oracle("sm2-pub", k["priv"]),
            ext_val=ext_get("sm2", "keys", k["name"], "pub"),
        )
        compare(
            f"sm2/{k['name']}/ZA",
            k["za"],
            local_fn=lambda k=k: oracle("sm2-za", k["pub"]),
            ext_val=ext_get("sm2", "keys", k["name"], "za"),
        )

    for c in vectors["sm2"]["encrypt"]:
        compare(
            f"sm2-encrypt/{c['name']}/C1C3C2",
            c["ciphertext"],
            local_fn=lambda c=c: oracle("sm2-enc", c["pub"], c["k"], c["plaintext"]),
            ext_val=ext_get("sm2", "encrypt", c["name"], "ciphertext"),
        )
        if LOCAL:
            pt = oracle("sm2-dec", c["priv"], c["ciphertext"])
            cmp_text(f"reverse/sm2-encrypt/{c['name']}/gmssl-decrypt", c["plaintext"], pt)
        else:
            skip(f"reverse/sm2-encrypt/{c['name']}/gmssl-decrypt", "需要本机 GmSSL")

    for c in vectors["sm2"]["sign"]:
        compare(
            f"sm2-sign/{c['name']}/r||s",
            c["sig"],
            local_fn=lambda c=c: oracle("sm2-sign", c["priv"], c["k"], c["msg"]),
            ext_val=ext_get("sm2", "sign", c["name"], "sig"),
        )
        if LOCAL:
            res = oracle("sm2-verify", c["pub"], c["msg"], c["sig"])
            if res == "OK":
                ok(f"reverse/sm2-sign/{c['name']}/gmssl-verify")
            else:
                bad(f"reverse/sm2-sign/{c['name']}/gmssl-verify", res)
        else:
            skip(f"reverse/sm2-sign/{c['name']}/gmssl-verify", "需要本机 GmSSL")

    # ---- A5. 用户码
    print("\n[A5] 用户码")
    for c in vectors["user_codes"]:
        compare(
            f"user-code/{c['name']}/4 位码",
            c["code"],
            local_fn=lambda c=c: crockford_first4(
                bytes.fromhex(cli("sm3", stdin=bytes.fromhex(c["pub"])).decode().strip())
            ),
            ext_val=ext_get("user_codes", c["name"], "code"),
        )
        for n in c["normalize"]:
            try:
                got = normalize_code(n["in"])
            except ValueError as e:
                bad(f"user-code/{c['name']}/normalize({n['in']})", str(e))
                continue
            cmp_text(f"user-code/{c['name']}/normalize({n['in']})", n["out"], got)

    # ---- B. 加密包
    print("\n[B] 加密包（整包字节）")
    for v in vectors["pack"]:
        compare(
            f"pack/{v['name']}/full-bytes",
            v["pack"],
            local_fn=lambda v=v: rebuild_pack(v).hex(),
            ext_val=ext_get("pack", v["name"], "pack"),
        )
        if LOCAL:
            rc, out, err = ystool("pack-unpack", v["pack"], v["recipient_priv"], v["sender_pub"])
            if rc == 0 and out == v["data"]:
                ok(f"reverse/pack/{v['name']}/本实现解包")
            else:
                bad(f"reverse/pack/{v['name']}/本实现解包", f"rc={rc} {err[:120]}")

            tampered = bytearray(bytes.fromhex(v["pack"]))
            tampered[8] ^= 0x01
            rc, out, _ = ystool(
                "pack-unpack", tampered.hex(), v["recipient_priv"], v["sender_pub"]
            )
            if rc != 0:
                ok(f"reverse/pack/{v['name']}/篡改包头被拒")
            else:
                bad(f"reverse/pack/{v['name']}/篡改包头被拒", "竟然解包成功")
        else:
            skip(f"reverse/pack/{v['name']}", "需要本机 GmSSL")

    # ---- C. 反向：GmSSL 真随机 → 本实现
    print("\n[C] 反向：GmSSL 随机输出 → 本实现解密/验签")
    if LOCAL:
        for k in vectors["sm2"]["keys"]:
            msg = bytes(range(32))
            ct = oracle("sm2-enc-rand", k["pub"], msg.hex())
            rc, out, err = ystool("sm2-decrypt", k["priv"], ct)
            if rc == 0 and out == msg.hex():
                ok(f"reverse/{k['name']}/GmSSL 随机加密 → 本实现解密")
            else:
                bad(f"reverse/{k['name']}/GmSSL 随机加密 → 本实现解密", f"rc={rc}")

            sig = oracle("sm2-sign-rand", k["priv"], msg.hex())
            rc, out, err = ystool("sm2-verify", k["pub"], msg.hex(), sig)
            if rc == 0 and out == "OK":
                ok(f"reverse/{k['name']}/GmSSL 随机签名 → 本实现验签")
            else:
                bad(f"reverse/{k['name']}/GmSSL 随机签名 → 本实现验签", f"rc={rc} out={out}")
    else:
        skip("reverse/GmSSL 随机加密/签名", "需要本机 GmSSL")

    # ---- 汇总
    print("\n================ 汇总 ================")
    print(f"PASS {PASS} / FAIL {FAIL} / SKIP {SKIP}")
    if FAIL:
        for label, detail in FAILURES:
            print(f"  - {label}: {detail}")
        return 1
    if SKIP:
        print("SKIP 的是本机跑不了、等宿主对照值的条目；拿到 testdata/gmssl-expected.json 再跑即可。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
