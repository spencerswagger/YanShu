#!/usr/bin/env python3
"""雁书 YanShu · GmSSL 逐字节交叉验证

做的事（全部真实执行，不做任何"跳过即通过"）：

  A. 用 GmSSL 命令行/库重算 testdata/vectors.json 里的每一条向量，与本实现输出逐字节比对
     - SM3 / SM4-GCM：GmSSL 命令行（gmssl sm3 / gmssl sm4 -gcm）
     - HMAC-SM3 / HKDF-SM3 / SM2：链接 libgmssl.a 的 oracle（固定 k，因此 SM2 也能逐字节比）
  B. 用 GmSSL 原语在 Python 里**重新拼出加密包**，与 Rust 侧产出的包逐字节比对
  C. 反向验证：GmSSL 用真随机生成 SM2 密文/签名 → 交给本实现解密/验签
  D. 用户码：用 GmSSL 算 SM3(公钥)，再按 Crockford Base32 规则重算 4 位码

退出码 0 = 全部 PASS；非 0 = 有 FAIL（会打印第一处差异的字节偏移）。

用法见同目录 run.sh 头部注释。
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
VECTORS = os.path.join(ROOT, "testdata", "vectors.json")

GMSSL_BIN = os.environ.get("GMSSL_BIN", "gmssl")
GMSSL_ORACLE = os.environ.get("GMSSL_ORACLE", "")
YS_TOOL = os.environ.get("YS_TOOL", "")

PASS = 0
FAIL = 0
FAILURES = []


def ok(label):
    global PASS
    PASS += 1
    print(f"  PASS  {label}")


def bad(label, detail=""):
    global FAIL
    FAIL += 1
    FAILURES.append((label, detail))
    print(f"  FAIL  {label}" + (f"  ({detail})" if detail else ""))


def run(cmd, stdin=None):
    r = subprocess.run(cmd, input=stdin, capture_output=True)
    return r.returncode, r.stdout, r.stderr


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


def first_diff(a: str, b: str):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return n
    return -1


def cmp_hex(label, ours, theirs):
    if ours == theirs:
        ok(label)
    else:
        d = first_diff(ours, theirs)
        bad(
            label,
            f"first diff at hex char {d} (byte {d // 2}); ours={ours[max(0, d - 8): d + 24]!r} gmssl={theirs[max(0, d - 8): d + 24]!r}",
        )


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


# ---------------------------------------------------------------- 加密包格式（按 docs 锚点重拼）

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
    return index.to_bytes(4, "big") + b"\x00\x00\x00\x00" + bytes([1 if is_last else 0]) + b"\x00\x00\x00"


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
    wrapped = bytes.fromhex(
        oracle("sm2-enc", v["recipient_pub"], v["k_wrap"], dk.hex())
    )
    man_ct, man_tag = gcm_enc(manifest_key, MANIFEST_NONCE, header, manifest_plain)

    out = bytearray()
    out += header
    out += bytes([KEY_REC_KIND]) + len(wrapped).to_bytes(4, "big") + wrapped
    out += bytes([SIG_REC_KIND]) + len(sig).to_bytes(4, "big") + sig
    out += len(man_ct).to_bytes(4, "big") + man_ct + man_tag
    for i, flags, ct, tag in blocks:
        out += i.to_bytes(4, "big") + bytes([flags]) + len(ct).to_bytes(4, "big") + ct + tag
    return bytes(out)


# ---------------------------------------------------------------- 主流程


def main():
    if not os.path.exists(VECTORS):
        print(f"vectors file missing: {VECTORS}", file=sys.stderr)
        return 2
    if not GMSSL_ORACLE or not os.path.exists(GMSSL_ORACLE):
        print("GMSSL_ORACLE not set/not found", file=sys.stderr)
        return 2
    if not YS_TOOL or not os.path.exists(YS_TOOL):
        print("YS_TOOL not set/not found", file=sys.stderr)
        return 2

    vectors = json.load(open(VECTORS, encoding="utf-8"))
    print(f"vectors: {VECTORS}")
    print(f"gmssl  : {GMSSL_BIN}")
    print(f"oracle : {GMSSL_ORACLE}")
    print(f"ys-tool: {YS_TOOL}")

    # ---- A1. SM3（GmSSL 命令行）
    print("\n[A1] SM3（gmssl sm3 命令行）")
    for c in vectors["sm3"]:
        out = cli("sm3", stdin=bytes.fromhex(c["msg"])).decode().strip()
        cmp_hex(f"sm3/{c['name']}", c["digest"], out)

    # ---- A2. HMAC-SM3 / HKDF-SM3（libgmssl）
    print("\n[A2] HMAC-SM3 / HKDF-SM3（libgmssl）")
    for c in vectors["hmac_sm3"]:
        out = oracle("hmac-sm3", c["key"], c["msg"])
        cmp_hex(f"hmac-sm3/{c['name']}", c["tag"], out)
    for c in vectors["hkdf_sm3"]:
        out = oracle("hkdf", c["salt"], c["ikm"], c["info"], str(c["len"]))
        cmp_hex(f"hkdf/{c['name']}", c["okm"], out)

    # ---- A3. SM4-GCM（命令行加密 + libgmssl 解密回环）
    print("\n[A3] SM4-GCM（gmssl sm4 -gcm 命令行）")
    for c in vectors["sm4_gcm"]:
        args = ["sm4", "-gcm", "-encrypt", "-key", c["key"], "-iv", c["nonce"]]
        if c["aad"]:
            args += ["-aad_hex", c["aad"]]
        out = cli(*args, stdin=bytes.fromhex(c["plaintext"])).hex()
        cmp_hex(f"sm4-gcm/{c['name']}/ct+tag", c["ciphertext"] + c["tag"], out)
        pt = oracle("gcm-dec", c["key"], c["nonce"], c["aad"], c["ciphertext"], c["tag"])
        cmp_hex(f"sm4-gcm/{c['name']}/decrypt", c["plaintext"], pt)

    # ---- A4. SM2 公钥 / ZA / 加密 / 签名
    print("\n[A4] SM2（libgmssl，固定 k 逐字节）")
    for k in vectors["sm2"]["keys"]:
        cmp_hex(f"sm2/{k['name']}/pubkey", k["pub"], oracle("sm2-pub", k["priv"]))
        cmp_hex(f"sm2/{k['name']}/ZA", k["za"], oracle("sm2-za", k["pub"]))

    for c in vectors["sm2"]["encrypt"]:
        out = oracle("sm2-enc", c["pub"], c["k"], c["plaintext"])
        cmp_hex(f"sm2-encrypt/{c['name']}/C1C3C2", c["ciphertext"], out)
        pt = oracle("sm2-dec", c["priv"], c["ciphertext"])
        cmp_hex(f"sm2-encrypt/{c['name']}/gmssl-decrypt", c["plaintext"], pt)

    for c in vectors["sm2"]["sign"]:
        out = oracle("sm2-sign", c["priv"], c["k"], c["msg"])
        cmp_hex(f"sm2-sign/{c['name']}/r||s", c["sig"], out)
        res = oracle("sm2-verify", c["pub"], c["msg"], c["sig"])
        if res == "OK":
            ok(f"sm2-sign/{c['name']}/gmssl-verify")
        else:
            bad(f"sm2-sign/{c['name']}/gmssl-verify", res)

    # ---- A5. 用户码
    print("\n[A5] 用户码（GmSSL SM3 + Crockford 规则重算）")
    for c in vectors["user_codes"]:
        digest = bytes.fromhex(cli("sm3", stdin=bytes.fromhex(c["pub"])).decode().strip())
        expect = crockford_first4(digest)
        cmp_hex(f"user-code/{c['name']}/4 位码", c["code"], expect)
        for n in c["normalize"]:
            try:
                got = normalize_code(n["in"])
            except ValueError as e:
                bad(f"user-code/{c['name']}/normalize({n['in']})", str(e))
                continue
            cmp_hex(f"user-code/{c['name']}/normalize({n['in']})", n["out"], got)

    # ---- B. 加密包重拼
    print("\n[B] 加密包逐字节（GmSSL 原语在 Python 里重拼）")
    for v in vectors["pack"]:
        rebuilt = rebuild_pack(v).hex()
        cmp_hex(f"pack/{v['name']}/full-bytes", v["pack"], rebuilt)

    # ---- C. 反向：GmSSL 随机生成 → 本实现验收
    print("\n[C] 反向验证（GmSSL 真随机 → ys-tool 解密/验签/解包）")
    for k in vectors["sm2"]["keys"]:
        msg = bytes(range(32))
        ct = oracle("sm2-enc-rand", k["pub"], msg.hex())
        rc, out, err = ystool("sm2-decrypt", k["priv"], ct)
        if rc == 0 and out == msg.hex():
            ok(f"reverse/{k['name']}/GmSSL 随机加密 → 本实现解密")
        else:
            bad(f"reverse/{k['name']}/GmSSL 随机加密 → 本实现解密", f"rc={rc} out={out[:32]} {err[:80]}")

        sig = oracle("sm2-sign-rand", k["priv"], msg.hex())
        rc, out, err = ystool("sm2-verify", k["pub"], msg.hex(), sig)
        if rc == 0 and out == "OK":
            ok(f"reverse/{k['name']}/GmSSL 随机签名 → 本实现验签")
        else:
            bad(f"reverse/{k['name']}/GmSSL 随机签名 → 本实现验签", f"rc={rc} out={out}")

    for v in vectors["pack"]:
        rc, out, err = ystool("pack-unpack", v["pack"], v["recipient_priv"], v["sender_pub"])
        if rc == 0 and out == v["data"]:
            ok(f"reverse/pack/{v['name']}/本实现解包")
        else:
            bad(f"reverse/pack/{v['name']}/本实现解包", f"rc={rc} {err[:120]}")

        # 篡改必须被拒（改包头一个字节）
        tampered = bytearray(bytes.fromhex(v["pack"]))
        tampered[8] ^= 0x01
        rc, out, _ = ystool("pack-unpack", tampered.hex(), v["recipient_priv"], v["sender_pub"])
        if rc != 0:
            ok(f"reverse/pack/{v['name']}/篡改包头被拒")
        else:
            bad(f"reverse/pack/{v['name']}/篡改包头被拒", "竟然解包成功")

    # ---- D. 反向：GmSSL 命令行 GCM → 本实现解密
    print("\n[D] 反向：gmssl sm4 -gcm 命令行 → ys-tool 解密")
    for c in vectors["sm4_gcm"]:
        args = ["sm4", "-gcm", "-encrypt", "-key", c["key"], "-iv", c["nonce"]]
        if c["aad"]:
            args += ["-aad_hex", c["aad"]]
        combined = cli(*args, stdin=bytes.fromhex(c["plaintext"])).hex()
        ct, tag = combined[:-32], combined[-32:]
        rc, out, err = ystool("gcm-dec", c["key"], c["nonce"], c["aad"], ct, tag)
        if rc == 0 and out == c["plaintext"]:
            ok(f"reverse/sm4-gcm/{c['name']}")
        else:
            bad(f"reverse/sm4-gcm/{c['name']}", f"rc={rc} {err[:80]}")

    # ---- 汇总
    print("\n================ 汇总 ================")
    print(f"PASS {PASS} / FAIL {FAIL}")
    if FAIL:
        for label, detail in FAILURES:
            print(f"  - {label}: {detail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
