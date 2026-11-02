# 端侧内核 C ABI（wasm32）· 最终版

> 适用于 `feat/endcrypto-wasm`（PR #4）。格式只有一种：`docs/CRYPTO-PACK.md` `YSPK/1.0`。
> 头文件：**`crypto/include/yanshu_sm.h`**（与本文件同步维护，代码为准）。

- 模块导出：`memory` + **30 个函数**，**0 个 import**。
- 长度参数 `size_t`（wasm32 = 4 字节）；指针 = 线性内存偏移；`u64` 参数在 JS 里是 BigInt。
- 返回 `0` = 成功，负数 = 错误码（见 §4）；缓冲区不足返回 `-2` 且把所需长度写进 `out_len`。
- `ys_alloc(n)` ↔ `ys_free(p, n)` 成对、长度一致。

---

## 1. `ys_unpack`（解包，7 参；首版原型保留）

```c
int32_t ys_unpack(const uint8_t *pack, size_t pack_len,
                  const uint8_t *recipient_private,      /* 32 字节 */
                  const uint8_t *sender_public_or_null,  /* 64 字节 X‖Y，可传 0 */
                  uint8_t *out, size_t out_cap, size_t *out_len);
```

| 入参 | 含义 |
|---|---|
| `pack` / `pack_len` | 完整 `.yspk` 字节（`YSPK/1.0`） |
| `recipient_private` | 收件人 SM2 私钥，32 字节裸标量 |
| `sender_public_or_null` | **可选**。传 `0`/NULL 表示不比对；非空时与包内 `SENDER_PUB` 比对，不一致返回 `-33`。验签**始终**用包内公钥，不依赖这个入参 |
| `out` / `out_cap` | 明文输出缓冲；不够时返回 `-2`，`*out_len` 给出所需长度，重试一次即可 |
| `out_len` | 实际明文长度 |

**返回结构**（C ABI 没有结构体，全部从出参取）：

| 要什么 | 从哪取 |
|---|---|
| 明文 | `out[0..*out_len]` |
| 元数据（文件名/MIME/大小/块数/发送方码） | 另调 `ys_unpack_meta`（不解密数据块，便宜） |
| 发送方公钥 | **只看 meta**：JSON 的 `sender_pub`（65 字节 hex，含 `0x04`）。`ys_unpack` 本身不回传公钥 |
| 发送方 4 位码 | **只看 meta**：JSON 的 `sender_code`，由包内 `SENDER_PUB` 派生（`SM3(65 字节) → Crockford 前 4 位`） |

错误名集合：`CRYPTO_*` 全部可能（见 §4），解包路径最常见：
`MAGIC_MISMATCH / VERSION_UNSUPPORTED / HEADER_INVALID / ALG_UNSUPPORTED / FLAGS_UNKNOWN /
UNSIGNED / LENGTH_INCONSISTENT / KEY_UNWRAP_FAILED / MANIFEST_AUTH_FAILED / MANIFEST_INVALID /
SIGNATURE_INVALID / SENDER_MISMATCH / CHUNK_ORDER / CHUNK_MISSING / CHUNK_AUTH_FAILED /
DIGEST_MISMATCH / TRUNCATED`。

## 2. `ys_unpack_meta`（只解清单，7 参）

```c
int32_t ys_unpack_meta(const uint8_t *pack, size_t pack_len,
                       const uint8_t *recipient_private,
                       const uint8_t *sender_public_or_null, /* 可传 0 */
                       uint8_t *out, size_t out_cap, size_t *out_len);
```

* 只解 `HEADER → SENDER_PUB → WRAPPED_KEY → MANIFEST_SEC → SIG_SEC` 并**验签**，不解数据块。
* `out` 是 UTF-8 JSON（不含结尾 `\0`），`*out_len` 为字节数：

```json
{"version":"YSPK/1.0","name":"报告.pdf","mime":"application/pdf","ext":"pdf",
 "size":5242880,"chunk_size":1048576,"chunk_count":5,"created_at_ms":1767225600000,
 "sender_code":"AWQW","sender_pub":"04bfd9…","kdf_salt":"000102…"}
```

* 元数据里的 `sender_code` 就是契约 §13 #18 要比对的码；`sender_pub` 是包内公钥原文。

## 3. `ys_unpack_v1` / `ys_unpack_meta_v1`（6 参，新代码建议用）

> `_v1` 后缀表示**契约大版本 `YSPK/1.0`**（与 `ys_pack_v1` 同族），不是"第二套布局"。
> 发布构建里**没有** `ys_set_layout` / `ys_layout_of` 之类的切换或探测入口。

```c
int32_t ys_unpack_v1(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                     uint8_t *out, size_t out_cap, size_t *out_len);
int32_t ys_unpack_meta_v1(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                          uint8_t *out, size_t out_cap, size_t *out_len);
```

与上面 7 参版**语义完全相同**（同一份实现），只是去掉了发送方公钥入参（来源由包内
`SENDER_PUB` 自证）。7 参版是**兼容别名**：第 4 参只做"是不是同一个人"的比对，
验签始终用包内公钥；两者都**只接受 `YSPK/1.0`**，旧 rune-v1 布局的字节会以
`-5 CRYPTO_VERSION_UNSUPPORTED` 被拒，不会解出明文。

> ⚠️ 用 `_v2` 时必须真的少传一个参数。wasm 调函数时多余实参会被**静默丢弃**并整体错位，
> 不是编译错。

## 4. 错误码（数值稳定）

- `-4 … -23` 与首版**完全一致**（老映射表照旧命中）；`-24` 起是新增细粒度。
- `ys_error_name(code)` 返回**首版旧名**（`BAD_MAGIC` 等，Web 现有表用它）；
  `ys_error_name_v1(code)` 返回**契约名**（`CRYPTO_*`，Gate 探针/日志用它）。

| code | `ys_error_name_v1` | `ys_error_name` | 含义 |
|---:|---|---|---|
| -1 | `CRYPTO_BAD_ARGUMENT` | `BAD_ARGUMENT` | 参数非法 |
| -2 | `CRYPTO_BUFFER_TOO_SMALL` | `BUFFER_TOO_SMALL` | 缓冲区不足（`*out_len` 给所需长度） |
| -3 | `CRYPTO_RNG_FAILED` | `RNG` | 随机源失败 / **同一 seed 复用** |
| -4 | `CRYPTO_MAGIC_MISMATCH` | `BAD_MAGIC` | 魔数不是 `YSPK` |
| -5 | `CRYPTO_VERSION_UNSUPPORTED` | `UNSUPPORTED_VERSION` | 版本/算法 ID 不认识 |
| -6 | `CRYPTO_FLAGS_UNKNOWN` | `BAD_FLAGS` | FLAGS 保留位 / RESERVED 非 0 |
| -7 | `CRYPTO_LENGTH_INCONSISTENT` | `TRUNCATED` | 截断 / 长度不符 |
| -8 | `CRYPTO_KEY_UNWRAP_FAILED` | `BAD_KEY_RECORD` | DK 解封失败 |
| -9 | `CRYPTO_SIGNATURE_INVALID` | `BAD_SIGNATURE_RECORD` | 签名记录/DER 非法 |
| -10 | `CRYPTO_MANIFEST_INVALID` | `BAD_MANIFEST_RECORD` | 清单结构非法 |
| -11 | `CRYPTO_CHUNK_ORDER` | `BLOCK_SEQUENCE` | 块序错 |
| -12 | `CRYPTO_CHUNK_ORDER` | `DUPLICATE_BLOCK` | 重复块 |
| -13 | `CRYPTO_CHUNK_MISSING` | `MISSING_BLOCK` | 缺块 |
| -14 | `CRYPTO_CHUNK_ORDER` | `LAST_FLAG_MISMATCH` | 末块标志不符 |
| -15 | `CRYPTO_CHUNK_AUTH_FAILED` | `TAG_MISMATCH` | 块 GCM 认证失败 |
| -16 | `CRYPTO_MANIFEST_AUTH_FAILED` | `MANIFEST_MISMATCH` | 清单认证/一致性 |
| -17 | `CRYPTO_SIGNATURE_INVALID` | `SIGNATURE_MISMATCH` | 验签失败 |
| -18 | `CRYPTO_LENGTH_INCONSISTENT` | `TRAILING_BYTES` | 尾部多余字节 |
| -19 | `CRYPTO_CURVE_INVALID` | `BAD_POINT` | 曲线点非法 |
| -20 | `CRYPTO_CIPHERTEXT_INVALID` | `BAD_KDF` | KDF/密文非法 |
| -21 | `CRYPTO_CODE_INVALID` | `BAD_CODE` | 用户码非法 |
| -22 | `CRYPTO_CODE_EXHAUSTED` | `CODE_EXHAUSTED` | 撞码重试耗尽 |
| -23 | `CRYPTO_CIPHERTEXT_INVALID` | `BAD_CIPHERTEXT` | 密文非法 |
| **-24** | `CRYPTO_HEADER_INVALID` | `BAD_FLAGS` | 头部字段非法 |
| **-25** | `CRYPTO_ALG_UNSUPPORTED` | `UNSUPPORTED_VERSION` | 未知算法 ID |
| **-26** | `CRYPTO_UNSIGNED` | `BAD_SIGNATURE_RECORD` | `SENDER_SIGNED=0` |
| **-27** | `CRYPTO_LENGTH_INCONSISTENT` | `TRUNCATED` | 长度不自洽 |
| **-28** | `CRYPTO_CHUNK_ORDER` | `BLOCK_SEQUENCE` | 块号/末块标志不符 |
| **-29** | `CRYPTO_CHUNK_AUTH_FAILED` | `TAG_MISMATCH` | 块 AEAD 失败 |
| **-30** | `CRYPTO_CHUNK_MISSING` | `MISSING_BLOCK` | 缺块 |
| **-31** | `CRYPTO_MANIFEST_AUTH_FAILED` | `MANIFEST_MISMATCH` | 清单 AEAD 失败 |
| **-32** | `CRYPTO_DIGEST_MISMATCH` | `MANIFEST_MISMATCH` | 明文摘要与清单不符 |
| **-33** | `CRYPTO_SENDER_MISMATCH` | `SIGNATURE_MISMATCH` | 调用方给的公钥与包内不符 |
| -99 | `CRYPTO_INTERNAL` | `INTERNAL` | 内部错误 |

## 5. 导出清单（30 个函数 + `memory`）

**首版 24 个（全部保留，无删除、无改名）**：
`ys_alloc` `ys_free` `ys_version` `ys_error_name` `ys_sm3` `ys_hmac_sm3` `ys_hkdf_sm3`
`ys_sm4_encrypt_block` `ys_sm4_decrypt_block` `ys_sm4_gcm_encrypt` `ys_sm4_gcm_decrypt`
`ys_sm2_keygen` `ys_sm2_pubkey` `ys_sm2_encrypt` `ys_sm2_decrypt` `ys_sm2_sign` `ys_sm2_verify`
`ys_user_code` `ys_normalize_code` `ys_pack` `ys_unpack` `ys_unpack_meta`
`ys_header_len` `ys_default_block_size`

**新增 6 个**：`ys_pack_v1`（清单 `ext`/`created_at_ms`）、`ys_sm2_sign_der`（DER 签名）、
`ys_check_symbol`（第 5 位校验字符）、`ys_error_name_v1`（契约错误名）、
`ys_unpack_v1` / `ys_unpack_meta_v1`（6 参解包）。

**语义变化 3 处**（签名都没变）：
1. `ys_unpack` / `ys_unpack_meta`：第 4 参发送方公钥变**可选**；验签改用包内公钥。
2. `ys_user_code`：入参仍是 64 字节 `X‖Y`，但**算法口径改为契约口径**——内部补 `0x04`
   后对 65 字节做 SM3，与契约 §15.1 的 `AWQW` 一致。前端传 64 字节不用改。
3. `ys_pack`：产出 `YSPK/1.0`（清单 `ext=""`、`created_at_ms=0`）；要完整清单字段用 `ys_pack_v1`。

## 6. 迁移说明（给前端 / 测试）

**什么都不用改**：`ys_unpack` / `ys_unpack_meta` 的原型与参数位没变，旧调用点照旧能跑；
传过去的发送方公钥会被拿去和包内公钥比对（一致就过，不一致返回 `-33`
`CRYPTO_SENDER_MISMATCH`，`ys_error_name` 看到的是 `SIGNATURE_MISMATCH`）。

要迁到新原型时：

```diff
- ys_unpack(packPtr, packLen, privPtr, senderPubPtr, outPtr, cap, lenPtr)
+ ys_unpack_v1(packPtr, packLen, privPtr, outPtr, cap, lenPtr)
- ys_unpack_meta(packPtr, packLen, privPtr, senderPubPtr, outPtr, cap, lenPtr)
+ ys_unpack_meta_v1(packPtr, packLen, privPtr, outPtr, cap, lenPtr)
```

测试驱动同理：把 `unpack` 调用里的 `--sender-pk` / 公钥参数去掉即可（Gate 的探针已经这么做了，
一行未改就能编译跑通）。**不要**在 `_v2` 上继续多传一个参数——wasm 会静默错位（内存踩踏），
不是编译错。

## 7. 用户码归一化（`ys_normalize_code`）与校验字符

**一句可核对的定义**：输入按 UTF-8 解码后逐字符处理——先**丢弃** `-`、空格、TAB、CR、LF
这五种分隔符；其余字符转 ASCII 大写后按 Crockford 映射 `O→0`、`I→1`、`L→1`；映射结果必须
落在 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`（`U`、标点、非 ASCII **一律拒绝**），且总数必须
**恰好 4 个**（不足不补齐、超过不截断、不做任何猜测性纠错）；成功返回 4 个大写符号，
失败返回 `-21 CRYPTO_CODE_INVALID`；该函数**幂等**：`f(f(x)) == f(x)`。

- 向量：`testdata/normalize-vectors.json`（**20 组**：13 组接受 + 7 组拒绝），
  与 `crypto/sm/src/code.rs::NORMALIZE_VECTORS` 同源（`cargo run --bin gen-code-vectors` 生成）。
- 合法字符会被**丢弃**的只有那五种分隔符；其它一切非法字符都是**拒绝**，绝不"猜一个最像的码"。
- `ys_check_symbol`（第 5 位校验字符）**只是本地防误输的辅助**：不参与码的构成、
  不参与归一化、不作为服务端判定依据。

## 8. 布局判别（没有独立探针函数）

发布构建只认 `YSPK/1.0`，所以判别就是"能不能解"：

```js
const rc = ys_unpack_meta_v1(packPtr, packLen, privPtr, outPtr, cap, lenPtr);
// rc === 0            → 'YSPK/1.0'
// rc === -5 / -4 / -6 → 不是契约包（旧 rune-v1 字节在这里被拒，不会静默解出明文）
// 其它负值            → 契约包但内容有问题，用 ys_error_name_v1(rc) 取名字
```

## 9. 排期（未实现）

- `MAX_BLOCK_SIZE`（产品级单文件上限）与流式分块接口：只在 `crypto/README.md` 的
  "已知限制"里登记，代码里没有任何半成品接口。
