# 测试向量比对（GmSSL / 宿主对照值）

本目录负责一件事：把 `testdata/vectors.json`（本实现产出）与**外部对照值**逐字节比对。
对照值有两个来源，**有几个比几个**：

| 来源 | 怎么来 | 用途 |
|---|---|---|
| ① 本机 GmSSL 3.1.1 | 编译好的 GmSSL 源码树 + `oracle.c`（链接 `libgmssl.a`） | 全部条目（含 SM2 逐字节） |
| ② 宿主侧对照值 | `testdata/gmssl-expected.json`（模板由 `--emit-template` 生成） | 本机装不了 GmSSL 时用 |

两个都没有时，脚本仍会跑完：相关条目打印 `SKIP 待宿主对照`，**不算 FAIL**，退出码 0。
宿主把对照值填进 `testdata/gmssl-expected.json` 后直接重跑，**不用改代码**。

## 用法

```sh
scripts/crosscheck/run.sh                      # 有 GmSSL 就本地比，没有就等宿主值
scripts/crosscheck/run.sh --emit-template /tmp/gmssl-expected.json   # 生成模板
scripts/crosscheck/run.sh --no-local           # 只用 testdata/gmssl-expected.json
```

前置（按需）：

- 本机 GmSSL：`include/gmssl/*.h` + `build/bin/libgmssl.a` + `build/bin/gmssl`，
  路径用 `GMSSL_DIR` 指定；查找顺序 `$GMSSL_DIR` → `/.cache/ys/GmSSL-3.1.1` →
  `../GmSSL-3.1.1` → `/opt/GmSSL-3.1.1`。没有也能跑（降级为 SKIP）。
  `GMSSL_AUTOBUILD=1` 可自动下载 v3.1.1 并编译（需 cmake）。
- Rust 工具链 + `python3` + `gcc`（编 oracle）。

自己编 GmSSL：

```sh
curl -L -o gmssl.tar.gz https://codeload.github.com/guanzhi/GmSSL/tar.gz/refs/tags/v3.1.1
tar xzf gmssl.tar.gz && cd GmSSL-3.1.1
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF && make -j"$(nproc)"
```

## 宿主怎么填对照值

1. `scripts/crosscheck/run.sh --emit-template testdata/gmssl-expected.json`
   会把**每条向量的输入**（key/nonce/AAD/明文/k/DK/file_id…）和**待填空字符串**一起写出来。
2. 用 GmSSL 3.1.1 按 `vectors.json` 里的 `conventions` 复算，把空字符串填上
   （填不出的留空，脚本对该条 SKIP）。
3. `scripts/crosscheck/run.sh --no-local`，直接看 PASS/FAIL；FAIL 会打印第一处差异的偏移。

### 模板结构

```jsonc
{
  "sm3":        { "<case>": { "msg": "…", "digest": "…" } },
  "hmac_sm3":   { "<case>": { "key": "…", "msg": "…", "tag": "…" } },
  "hkdf_sm3":   { "<case>": { "salt": "…", "ikm": "…", "info": "…", "len": 32, "okm": "…" } },
  "sm4_gcm":    { "<case>": { "key": "…", "nonce": "…", "aad": "…", "plaintext": "…",
                              "ciphertext": "…", "tag": "…" } },
  "sm2": {
    "keys":    { "<case>": { "priv": "…", "pub": "…", "za": "…" } },
    "encrypt": { "<case>": { "pub": "…", "k": "…", "plaintext": "…", "ciphertext": "…" } },
    "sign":    { "<case>": { "priv": "…", "pub": "…", "k": "…", "msg": "…", "sig": "…" } }
  },
  "user_codes": { "<case>": { "pub": "…", "code": "ABCD" } },
  "pack":       { "<case>": { "recipient_pub": "…", "sender_priv": "…", "sender_pub": "…",
                              "dk": "…", "file_id": "…", "k_wrap": "…", "k_sign": "…",
                              "block_size": 16, "file_name": "…", "mime": "…",
                              "data": "…", "pack": "…" } }
}
```

## 口径（务必按这个复算）

完整版在 `testdata/vectors.json` 的 `conventions` 字段里，要点：

- 所有整数/hex 都是大端，hex 小写无前缀。
- **SM2 公钥**：64 字节 `X‖Y`，未压缩、**不带 0x04**。
- **SM2 密文**：`C1C3C2` 平文拼接，`C1.x(32)‖C1.y(32)‖C3(32)‖C2(len)`，无 DER。
- **SM2 签名**：`R‖S`（32+32），**不是 DER**；ID = `1234567812345678`，`e = SM3(ZA‖M)`。
- **SM2 的 k**：每条向量显式给了 `k`。GmSSL 命令行没法定 k，需要用库并在
  `rand_bytes` 处固定（见下），否则只能比"解密/验签通过"。
- **SM4-GCM**：key 16B、tag 16B、nonce 见 `nonce_len`（固定 12）；`gmssl sm4 -gcm`
  的输出是 `ct‖tag` 连写，**tag 是末尾 16 字节**。
- **HKDF-SM3**：RFC 5869 结构，PRF 用 HMAC-SM3；salt 为空时按 32 字节 0x00。
- **用户码**：`CrockfordBase32(SM3(公钥))` 前 4 位（摘要前 20 bit，大端位序、5 bit/符号）。
- **加密包**：布局与 nonce/AAD/派生规则见 `docs/crypto-pack-v1-draft.md`。

### 为什么 SM2 也能"逐字节"比

GmSSL 的 `sm2_do_encrypt` / `sm2_sign` 内部调 `rand_bytes()`。`oracle.c` **自己实现了
`rand_bytes`**，链接时优先于 `libgmssl.a` 里的 `rand.o`，于是固定 k 后 GmSSL 的 SM2 输出
就是确定性的。`sm2_bn_rand_range` 是"取 32 字节、`< n` 才收"，所以合法 k 一次就中。

## 脚本做了什么

| 阶段 | 内容 | 对照源①（本机） | 对照源②（宿主文件） |
|---|---|---|---|
| A1 | SM3 摘要 | `gmssl sm3` | `sm3.<case>.digest` |
| A2 | HMAC-SM3 / HKDF-SM3 | `libgmssl`（oracle） | `hmac_sm3.*.tag` / `hkdf_sm3.*.okm` |
| A3 | SM4-GCM 密文 + tag | `gmssl sm4 -gcm` | `sm4_gcm.<case>.ciphertext/tag` |
| A4 | SM2 公钥/ZA/加密/签名 | `libgmssl` 固定 k | `sm2.*` |
| A5 | 4 位用户码 | `gmssl sm3` + Python Crockford | `user_codes.<case>.code` |
| B | **整个加密包字节** | Python 用 GmSSL 原语重拼 | `pack.<case>.pack` |
| C | 反向：GmSSL 随机加密/签名 → 本实现 | 仅本机 | 不支持（需本机随机） |
| D | 反向：`gmssl sm4 -gcm` 密文 → 本实现解密 | 仅本机 | 不支持 |

## 实测（GmSSL 3.1.1 / Rust 1.99.1）

```text
本地 GmSSL 全开：PASS 84 / FAIL 0 / SKIP 0
仅宿主对照值：  只跑「宿主能给的值」，反向项 SKIP（退出码 0）
两个都没有：    全部 SKIP + 自洽类检查，退出码 0
```

> 宿主侧要填的对照值清单见仓库根目录 `vectors/host-crosscheck.json`（+ `.md` 表格），
> 条目覆盖 SM3 / HMAC-SM3 / HKDF-SM3 / SM4-GCM / SM2 加密 / SM2 签名（`YSAUTH1` 与 `YSSIG1`）/
> 两个完整 `YSPK/1.0` 包。

## 文件

| 文件 | 作用 |
|---|---|
| `run.sh` | 一键：定位 GmSSL（可缺）→ 编 oracle → 编 ys-tool → 跑比对 |
| `oracle.c` | 链接 `libgmssl.a` 的对照实现（含 `rand_bytes` 覆盖） |
| `crosscheck.py` | 读向量 + 两个对照源、逐字节比、打印第一处差异、支持 `--emit-template` |

产物落在 `tmp/crosscheck/`（已 gitignore）。
