#!/usr/bin/env python3
"""雁书 YanShu · 测试向量比对（契约 YSPK/1.0）

比对本实现产出的 `testdata/vectors.json` 与外部对照值。对照值两个来源，有几个比几个：

  1. **本机 GmSSL**（可选）：`gmssl` 命令行 + 链接 `libgmssl.a` 的 oracle。
  2. **宿主侧对照值**：`testdata/gmssl-expected.json`（模板由 `--emit-template` 生成）。
     文件缺失或字段为空 → 该条打印 `SKIP 待宿主对照`，**不算 FAIL**。

退出码：0 = 无 FAIL（可能全是 SKIP）；1 = 有 FAIL；2 = 环境/文件缺失。
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

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CHECK_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"


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


def first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n if len(a) != len(b) else -1


def cmp_text(label, ours, theirs):
    if ours == theirs:
        ok(label)
        return
    d = first_diff(ours, theirs)
    bad(
        label,
        f"first diff at {d}; ours={ours[max(0, d - 8): d + 24]!r} theirs={theirs[max(0, d - 8): d + 24]!r}",
    )


def compare(label, ours, local_fn=None, ext_val=None):
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
    if node is None or node == "" or isinstance(node, bool):
        return None
    if isinstance(node, int):
        return str(node)
    return node if isinstance(node, str) else None


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


# ---------------------------------------------------------------- Crockford / DER


def crockford_code(pub65_hex):
    digest = bytes.fromhex(cli("sm3", stdin=bytes.fromhex(pub65_hex)).decode().strip())
    bits = "".join(f"{b:08b}" for b in digest)
    code = "".join(ALPHABET[int(bits[i * 5 : i * 5 + 5], 2)] for i in range(4))
    value = int(bits[:20], 2)
    return code, CHECK_ALPHABET[value % 37]


def normalize_code(s):
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


def der_int(b32: bytes) -> bytes:
    i = 0
    while i < 31 and b32[i] == 0:
        i += 1
    body = b32[i:]
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def der_sig(raw64_hex: str) -> str:
    raw = bytes.fromhex(raw64_hex)
    body = der_int(raw[:32]) + der_int(raw[32:])
    return (b"\x30" + bytes([len(body)]) + body).hex()


# ---------------------------------------------------------------- 契约 YSPK/1.0 重拼

MAGIC = b"YSPK"
VER = bytes([1, 0])
CHUNK_HDR = 16
TAG = 16


def header_bytes(flags, chunk_size, chunk_count, plaintext_size, manifest_len,
                 manifest_pt_len, salt, sig_len):
    return (
        MAGIC + VER + (112).to_bytes(2, "big") + flags.to_bytes(4, "big")
        + bytes([1, 1, 1, 1])
        + chunk_size.to_bytes(4, "big") + chunk_count.to_bytes(4, "big")
        + plaintext_size.to_bytes(8, "big")
        + (129).to_bytes(8, "big") + manifest_len.to_bytes(8, "big")
        + manifest_pt_len.to_bytes(4, "big") + (65).to_bytes(4, "big")
        + salt + sig_len.to_bytes(8, "big")
        + b"\x00" * 32
    )


def chunk_nonce(i, last):
    return i.to_bytes(8, "big") + b"\x00\x00\x00" + bytes([1 if last else 0])


def aad_chunk(chunk_size, chunk_count, plaintext_size, i, last, pt_len):
    return (
        bytes([1]) + MAGIC + VER
        + chunk_size.to_bytes(4, "big") + chunk_count.to_bytes(4, "big")
        + plaintext_size.to_bytes(8, "big") + i.to_bytes(4, "big")
        + bytes([1 if last else 0]) + pt_len.to_bytes(4, "big")
    )


def aad_manifest(flags, chunk_size, chunk_count, plaintext_size, manifest_pt_len):
    return (
        bytes([2]) + MAGIC + VER + flags.to_bytes(4, "big")
        + chunk_size.to_bytes(4, "big") + chunk_count.to_bytes(4, "big")
        + plaintext_size.to_bytes(8, "big") + manifest_pt_len.to_bytes(4, "big")
    )


def hkdf(salt, ikm, info, length):
    return bytes.fromhex(oracle("hkdf", salt.hex(), ikm.hex(), info.hex(), str(length)))


def gcm_enc(key, nonce, aad, pt):
    out = bytes.fromhex(oracle("gcm-enc", key.hex(), nonce.hex(), aad.hex(), pt.hex()))
    return out[:-TAG], out[-TAG:]


def sm3(data):
    return bytes.fromhex(oracle("sm3", data.hex()))


def chunk_count_of(size, chunk_size):
    return 1 if size == 0 else (size + chunk_size - 1) // chunk_size


def chunk_pt_len(size, chunk_size, count, i):
    return chunk_size if i + 1 < count else size - chunk_size * (count - 1)


def rebuild_pack(v) -> bytes:
    data = bytes.fromhex(v["data"])
    dk = bytes.fromhex(v["dk"])
    salt = bytes.fromhex(v["kdf_salt"])
    recipient_pub = bytes.fromhex(v["recipient_pub"])
    sender_priv = bytes.fromhex(v["sender_priv"])
    assert recipient_pub[0] == 0x04
    sender_pub = bytes([0x04]) + bytes.fromhex(oracle("sm2-pub", v["sender_priv"]))

    chunk_size = v["chunk_size"]
    size = len(data)
    count = chunk_count_of(size, chunk_size)
    flags = 2  # SENDER_SIGNED

    kek_c = hkdf(salt, dk, b"YANSHU/v1/chunk-key", 16)
    kek_m = hkdf(salt, dk, b"YANSHU/v1/manifest-key", 16)

    chunks = []
    digests = []
    for i in range(count):
        pt_len = chunk_pt_len(size, chunk_size, count, i)
        pt = data[i * chunk_size : i * chunk_size + pt_len]
        last = i + 1 == count
        ct, tag = gcm_enc(kek_c, chunk_nonce(i, last),
                          aad_chunk(chunk_size, count, size, i, last, pt_len), pt)
        digests.append(sm3(pt))
        chunks.append(
            i.to_bytes(4, "big") + pt_len.to_bytes(4, "big") + pt_len.to_bytes(4, "big")
            + bytes([1 if last else 0, 0]) + b"\x00\x00" + ct + tag
        )

    name = v["file_name"].encode()
    mime = v["mime"].encode()
    ext = v["ext"].encode()
    manifest_pt = (
        b"YSM1" + bytes([1, 0, 1, 32])
        + size.to_bytes(8, "big") + chunk_size.to_bytes(4, "big") + count.to_bytes(4, "big")
        + v["created_at_ms"].to_bytes(8, "big")
        + len(name).to_bytes(2, "big") + name
        + len(mime).to_bytes(2, "big") + mime
        + len(ext).to_bytes(2, "big") + ext
        + (count * 32).to_bytes(4, "big") + b"".join(digests)
    )
    man_ct, man_tag = gcm_enc(
        kek_m, bytes.fromhex("ffffffffffffffff00000001"),
        aad_manifest(flags, chunk_size, count, size, len(manifest_pt)), manifest_pt,
    )
    manifest_sec = man_ct + man_tag

    hdr_stub = header_bytes(flags, chunk_size, count, size, len(manifest_sec),
                            len(manifest_pt), salt, 70)
    sig_input = b"YSSIG1" + VER + hdr_stub[:72] + sender_pub + manifest_sec
    raw_sig = oracle("sm2-sign", v["sender_priv"], v["k_sig"], sig_input.hex())
    sig_der = bytes.fromhex(der_sig(raw_sig))

    wrapped = bytes([0x04]) + bytes.fromhex(
        oracle("sm2-enc", recipient_pub[1:].hex(), v["k_enc"], dk.hex())
    )
    assert len(wrapped) == 129, len(wrapped)

    header = header_bytes(flags, chunk_size, count, size, len(manifest_sec),
                          len(manifest_pt), salt, len(sig_der))
    return header + sender_pub + wrapped + manifest_sec + sig_der + b"".join(chunks)


# ---------------------------------------------------------------- 模板


def emit_template(vectors, path):
    t = {
        "meta": {
            "how": "用 OpenSSL/GmSSL 按 vectors.json 的 conventions 复算，把空字符串填上；"
            "填不出的留空（脚本会 SKIP 该条）。",
            "pack_version": vectors["meta"]["pack_version"],
        },
        "sm3": {}, "hmac_sm3": {}, "hkdf_sm3": {}, "sm4_gcm": {},
        "sm2": {"keys": {}, "encrypt": {}, "sign": {}},
        "user_codes": {}, "pack": {},
    }
    for c in vectors["sm3"]:
        t["sm3"][c["name"]] = {"msg": c.get("msg"), "msg_len": c.get("msg_len"), "digest": ""}
    for c in vectors["hmac_sm3"]:
        t["hmac_sm3"][c["name"]] = {"key": c["key"], "msg": c["msg"], "tag": ""}
    for c in vectors["hkdf_sm3"]:
        t["hkdf_sm3"][c["name"]] = {
            "salt": c["salt"], "ikm": c["ikm"], "info": c["info"], "len": c["len"], "okm": "",
        }
    for c in vectors["sm4_gcm"]:
        t["sm4_gcm"][c["name"]] = {
            "key": c["key"], "nonce": c["nonce"], "aad": c["aad"],
            "plaintext": c["plaintext"], "ciphertext": "", "tag": "",
        }
    for k in vectors["sm2"]["keys"]:
        t["sm2"]["keys"][k["name"]] = {"priv": k["priv"], "pub": "", "pub65": "", "za": ""}
    for c in vectors["sm2"]["encrypt"]:
        t["sm2"]["encrypt"][c["name"]] = {
            "pub": c["pub"], "k": c["k"], "plaintext": c["plaintext"], "ciphertext": "",
        }
    for c in vectors["sm2"]["sign"]:
        t["sm2"]["sign"][c["name"]] = {
            "priv": c["priv"], "pub": c["pub"], "k": c["k"], "msg": c["msg"],
            "sig_raw": "", "sig_der": "",
        }
    for c in vectors["user_codes"]:
        t["user_codes"][c["name"]] = {"pub65": c["pub65"], "code": "", "check": ""}
    for v in vectors["pack"]:
        t["pack"][v["name"]] = {
            "recipient_pub": v["recipient_pub"], "sender_priv": v["sender_priv"],
            "sender_pub": v["sender_pub"], "recipient_priv": v["recipient_priv"],
            "dk": v["dk"], "kdf_salt": v["kdf_salt"], "k_enc": v["k_enc"],
            "k_sig": v["k_sig"], "created_at_ms": v["created_at_ms"],
            "chunk_size": v["chunk_size"], "file_name": v["file_name"],
            "mime": v["mime"], "ext": v["ext"], "data": v["data"], "pack": "",
        }
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(t, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"模板已写入 {path}；填满空字符串后作为 --expected 传入。")


# ---------------------------------------------------------------- 主流程


def main():
    global LOCAL, EXT

    ap = argparse.ArgumentParser(description="雁书测试向量比对")
    ap.add_argument("--vectors", default=os.path.join(ROOT, "testdata", "vectors.json"))
    ap.add_argument("--expected", default=os.path.join(ROOT, "testdata", "gmssl-expected.json"))
    ap.add_argument("--emit-template", metavar="PATH")
    ap.add_argument("--no-local", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.vectors):
        print(f"向量文件缺失：{args.vectors}", file=sys.stderr)
        return 2
    vectors = json.load(open(args.vectors, encoding="utf-8"))

    if args.emit_template:
        emit_template(vectors, args.emit_template)
        return 0

    LOCAL = (
        not args.no_local
        and bool(GMSSL_ORACLE) and os.path.exists(GMSSL_ORACLE)
        and bool(GMSSL_BIN) and os.path.exists(GMSSL_BIN)
    )
    EXT = json.load(open(args.expected, encoding="utf-8")) if os.path.exists(args.expected) else None

    print(f"vectors : {args.vectors}")
    print(f"对照源1 : {'本机 GmSSL' if LOCAL else '不可用'}")
    print(f"对照源2 : {args.expected}{'' if EXT else '（不存在）'}")
    if not LOCAL and EXT is None:
        print("\n没有对照源：自洽性由 cargo test 覆盖；待宿主提供对照值后重跑（无需改代码）。")

    # A1 SM3
    print("\n[A1] SM3")
    for c in vectors["sm3"]:
        def local(c=c):
            if c.get("msg") is not None:
                data = bytes.fromhex(c["msg"])
            else:
                n = c["msg_len"]
                data = bytes(((i * 31 + 7) & 0xFF) for i in range(n))
            return cli("sm3", stdin=data).decode().strip()

        compare(f"sm3/{c['name']}", c["digest"], local_fn=local,
                ext_val=ext_get("sm3", c["name"], "digest"))

    # A2 HMAC / HKDF
    print("\n[A2] HMAC-SM3 / HKDF-SM3")
    for c in vectors["hmac_sm3"]:
        compare(f"hmac-sm3/{c['name']}", c["tag"],
                local_fn=lambda c=c: oracle("hmac-sm3", c["key"], c["msg"]),
                ext_val=ext_get("hmac_sm3", c["name"], "tag"))
    for c in vectors["hkdf_sm3"]:
        compare(f"hkdf/{c['name']}", c["okm"],
                local_fn=lambda c=c: oracle("hkdf", c["salt"], c["ikm"], c["info"], str(c["len"])),
                ext_val=ext_get("hkdf_sm3", c["name"], "okm"))

    # A3 SM4-GCM
    print("\n[A3] SM4-GCM")
    for c in vectors["sm4_gcm"]:
        def local(c=c):
            a = ["sm4", "-gcm", "-encrypt", "-key", c["key"], "-iv", c["nonce"]]
            if c["aad"]:
                a += ["-aad_hex", c["aad"]]
            return cli(*a, stdin=bytes.fromhex(c["plaintext"])).hex()

        combined = memo(local) if LOCAL else None
        compare(f"sm4-gcm/{c['name']}/ct", c["ciphertext"],
                local_fn=(lambda f=combined: f()[:-32]) if LOCAL else None,
                ext_val=ext_get("sm4_gcm", c["name"], "ciphertext"))
        compare(f"sm4-gcm/{c['name']}/tag", c["tag"],
                local_fn=(lambda f=combined: f()[-32:]) if LOCAL else None,
                ext_val=ext_get("sm4_gcm", c["name"], "tag"))
        if LOCAL:
            ct, tag = combined()[:-32], combined()[-32:]
            rc, out, err = ystool("gcm-dec", c["key"], c["nonce"], c["aad"], ct, tag)
            if rc == 0 and out == c["plaintext"]:
                ok(f"reverse/sm4-gcm/{c['name']}")
            else:
                bad(f"reverse/sm4-gcm/{c['name']}", f"rc={rc} {err[:80]}")
        else:
            skip(f"reverse/sm4-gcm/{c['name']}", "需要本机 GmSSL")

    # A4 SM2
    print("\n[A4] SM2")
    for k in vectors["sm2"]["keys"]:
        compare(f"sm2/{k['name']}/pub", k["pub"],
                local_fn=lambda k=k: oracle("sm2-pub", k["priv"]),
                ext_val=ext_get("sm2", "keys", k["name"], "pub"))
        compare(f"sm2/{k['name']}/ZA", k["za"],
                local_fn=lambda k=k: oracle("sm2-za", k["pub65"]),
                ext_val=ext_get("sm2", "keys", k["name"], "za"))
    for c in vectors["sm2"]["encrypt"]:
        compare(f"sm2-encrypt/{c['name']}/C1C3C2", c["ciphertext"],
                local_fn=lambda c=c: oracle("sm2-enc", c["pub"], c["k"], c["plaintext"]),
                ext_val=ext_get("sm2", "encrypt", c["name"], "ciphertext"))
        if LOCAL:
            pt = oracle("sm2-dec", c["priv"], c["ciphertext"])
            cmp_text(f"reverse/sm2-encrypt/{c['name']}/gmssl-decrypt", c["plaintext"], pt)
        else:
            skip(f"reverse/sm2-encrypt/{c['name']}", "需要本机 GmSSL")
    for c in vectors["sm2"]["sign"]:
        compare(f"sm2-sign/{c['name']}/r||s", c["sig_raw"],
                local_fn=lambda c=c: oracle("sm2-sign", c["priv"], c["k"], c["msg"]),
                ext_val=ext_get("sm2", "sign", c["name"], "sig_raw"))
        compare(f"sm2-sign/{c['name']}/DER", c["sig_der"],
                local_fn=lambda c=c: der_sig(oracle("sm2-sign", c["priv"], c["k"], c["msg"])),
                ext_val=ext_get("sm2", "sign", c["name"], "sig_der"))
        if LOCAL:
            res = oracle("sm2-verify", "04" + c["pub"], c["msg"], c["sig_raw"])
            if res == "OK":
                ok(f"reverse/sm2-sign/{c['name']}/gmssl-verify")
            else:
                bad(f"reverse/sm2-sign/{c['name']}/gmssl-verify", res)
        else:
            skip(f"reverse/sm2-sign/{c['name']}", "需要本机 GmSSL")

    # A5 用户码
    print("\n[A5] 用户码")
    for c in vectors["user_codes"]:
        compare(f"user-code/{c['name']}/code", c["code"],
                local_fn=lambda c=c: crockford_code(c["pub65"])[0],
                ext_val=ext_get("user_codes", c["name"], "code"))
        compare(f"user-code/{c['name']}/check", c["check"],
                local_fn=lambda c=c: crockford_code(c["pub65"])[1],
                ext_val=ext_get("user_codes", c["name"], "check"))
        for n in c["normalize"]:
            try:
                got = normalize_code(n["in"])
            except ValueError as e:
                bad(f"user-code/{c['name']}/normalize({n['in']})", str(e))
                continue
            cmp_text(f"user-code/{c['name']}/normalize({n['in']})", n["out"], got)

    # B 加密包
    print("\n[B] 加密包 YSPK/1.0（整包字节）")
    for v in vectors["pack"]:
        compare(f"pack/{v['name']}/full-bytes", v["pack"],
                local_fn=lambda v=v: rebuild_pack(v).hex(),
                ext_val=ext_get("pack", v["name"], "pack"))
        if LOCAL:
            rc, out, err = ystool("pack-unpack", v["pack"], v["recipient_priv"])
            if rc == 0 and out == v["data"]:
                ok(f"reverse/pack/{v['name']}/本实现解包")
            else:
                bad(f"reverse/pack/{v['name']}/本实现解包", f"rc={rc} {err[:120]}")
            tampered = bytearray(bytes.fromhex(v["pack"]))
            tampered[8] ^= 0x01
            rc, out, _ = ystool("pack-unpack", tampered.hex(), v["recipient_priv"])
            if rc != 0:
                ok(f"reverse/pack/{v['name']}/篡改头部被拒")
            else:
                bad(f"reverse/pack/{v['name']}/篡改头部被拒", "竟然解包成功")
        else:
            skip(f"reverse/pack/{v['name']}", "需要本机 GmSSL")

    # C 反向随机
    print("\n[C] 反向：GmSSL 随机输出 → 本实现")
    if LOCAL:
        for k in vectors["sm2"]["keys"]:
            msg = bytes(range(32))
            ct = oracle("sm2-enc-rand", k["pub"], msg.hex())
            rc, out, err = ystool("sm2-decrypt", k["priv"], ct)
            if rc == 0 and out == msg.hex():
                ok(f"reverse/{k['name']}/随机加密→解密")
            else:
                bad(f"reverse/{k['name']}/随机加密→解密", f"rc={rc}")
            sig = oracle("sm2-sign-rand", k["priv"], msg.hex())
            rc, out, err = ystool("sm2-verify-raw", k["pub"], msg.hex(), sig)
            if rc == 0 and out == "OK":
                ok(f"reverse/{k['name']}/随机签名→验签")
            else:
                bad(f"reverse/{k['name']}/随机签名→验签", f"rc={rc} out={out}")
    else:
        skip("reverse/GmSSL 随机加密/签名", "需要本机 GmSSL")

    print("\n================ 汇总 ================")
    print(f"PASS {PASS} / FAIL {FAIL} / SKIP {SKIP}")
    if FAIL:
        for label, detail in FAILURES:
            print(f"  - {label}: {detail}")
        return 1
    if SKIP:
        print("SKIP 的是本机跑不了、等宿主对照值的条目。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
