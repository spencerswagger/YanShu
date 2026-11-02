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

## 2.5 只凭 prelude 看元信息（`ys_unpack_meta_prelude`）

**契约允许**：`prelude = HEADER ‖ SENDER_PUB ‖ WRAPPED_KEY ‖ MANIFEST_SEC ‖ SIG_SEC`（§4.3），
清单在 `MANIFEST_SEC` 里（§8.1），签名 `SIG_INPUT` 覆盖 `HDR_CORE ‖ SENDER_PUB ‖ MANIFEST_SEC`（§10.2）——
**这些全都在 prelude 内**，所以"块还没下完就先显示发件人码 / 文件名 / 大小 / 块数"是可以的。

```c
int32_t ys_unpack_meta_prelude(const uint8_t *pack, size_t pack_len,
                               const uint8_t *recipient_private, uint8_t *out, size_t out_cap,
                               size_t *out_len);
```

- 要求 `pack_len >= PRELUDE_LEN`（`112+65+129+MANIFEST_LEN+SIG_LEN`；不足 → `CRYPTO_TRUNCATED`）。
- JSON 里固定带两个字段，避免"看起来成功但完整性未验证"：
  `"scope":"prelude"` 与 **`"data_verified":false`**。
- **prelude 阶段已校验**：魔数/版本/算法 ID/头部字段、`SENDER_PUB` 派生码、SM2 解封 DK、
  清单认证与结构、签名（来源自证）。
- **prelude 阶段未校验**：块 AEAD（tag）与每块明文摘要——它们要等块到齐。
  数据完整性只认 `ys_unpack` / `ys_unpack_v1` **成功返回**（成功即代表所有块 tag + 摘要都过）。
- `ys_unpack_meta` / `ys_unpack_meta_v1` 仍是**整包**语义（`ENVELOPE_LEN` 必须一致），
  JSON 里 `"scope":"full"`、`"data_verified":false`（它同样不解块，只是长度自洽）。

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

## 3.4 SM2 验签（服务端/Core 用）

```c
int32_t ys_sm2_verify_der(const uint8_t *public_key /* 64 = X‖Y */,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig_der, size_t sig_len);
// 1 = 通过，0 = 不通过，负数 = 参数/DER/曲线错误
```

- 固定 `userID = 1234567812345678`（ENTL = 0x0080），`e = SM3(ZA ‖ msg)`；MID = 默认 ID。
- 签名只接受**规范 DER**（最短 INTEGER、无尾随字节）；非规范直接 `CRYPTO_SIGNATURE_INVALID`。
- 供给包：`vectors/sm2-verify-vectors.json`
  - `sig_input_samples`：3 组 `SIG_INPUT`（REGISTER / NICKNAME_UPDATE / TRANSFER_CREATE）
    的完整 hex 与长度，标明 `CODE(4)`、`u16be` 昵称前缀的位置；
  - `verify_vectors`：5 组（正常 / 签名改 1 字节 / 消息被改 / userID 不同 / 公钥不符），
    每组给 `pub65`、`msg`、`za`、`digest_e`、`sig_der`、`expect_verify`；
  - `fixtures`：私钥与两把公钥（含"另一把"用于公钥不符）。
- 注意：ABI 固定默认 userID；`different_user_id` 那条用于验证 ZA 口径（应用层用该 ID 复算）。
- **wazero（Go 纯 Go wasm 运行时）实测**：0 import 直接 `Instantiate`，32 个函数可见，
  `ys_version()=0x00010000`，`ys_sm2_verify_der` 对上述向量 4/4 结果符合预期
  （正常 1；签名改字节/消息改/公钥不符均 0）。Core 可直接用同一份 `.wasm`。

## 3.45 验签口径（前端 / 测试 / 服务端唯一依据）

- **userID**：固定国标默认串 **`1234567812345678`**（16 字节 ASCII，`ENTL = 0x0080`）。
  不用空串、不用业务自定义串；`ys_sm2_sign` / `ys_sm2_verify` / `ys_sm2_sign_der` /
  `ys_sm2_verify_der` 全部写死这一个。
- **ZA**：**参与**，算法为
  `ZA = SM3( ENTL(2 字节，= 128) ‖ ID(16) ‖ a(32) ‖ b(32) ‖ Gx(32) ‖ Gy(32) ‖ Px(32) ‖ Py(32) )`
  （全部大端；`a/b/Gx/Gy` 是 SM2 推荐曲线常量，`P` 是签名者公钥）。
- **签名摘要**：`e = SM3( ZA ‖ M )`，其中 **`M` 就是 `SIG_INPUT` 的原始字节**。
  调用方**不要把 `SIG_INPUT` 先算一遍 SM3 再传**——`ys_sm2_sign/verify` 内部做
  `SM3(ZA‖msg)`；传进去的 `msg` 必须是 `SIG_INPUT` 原文（服务端同理）。
- **`SIG_INPUT` 构造**（契约 `docs/API.md §1.3`）：
  `"YSAUTH1"(7) ‖ PURPOSE(1) ‖ NONCE(32) ‖ <用途字段串>`，整数一律大端；
  字段串第一位都是 `CODE(4 ASCII)`（`TRANSFER_ACK` 用接收方码），昵称带 `u16be` 长度前缀。
- **服务端顺序**：先验签（`ys_sm2_verify_der`），再把 `X-YS-Code` 与 `SIG_INPUT` 里的
  `CODE(4)` 逐字节比对（不符 → `AUTH_CODE_MISMATCH`）；密码学失败 → `CRYPTO_SIGNATURE_INVALID`。
- **供给包**：`vectors/sm2-verify-vectors.json` —— 7 种 `PURPOSE` 各一条正例（含逐字段
  拆解与完整 hex）+ 8 条负例，共 15 条：其中 5 条密码学失败（消息改字节 / 签名改字节 /
  换公钥 / 长度前缀写错 / userID 不同）、3 条服务端策略拒绝（CODE 与请求头不一致 →
  `AUTH_CODE_MISMATCH`、空输入、超长输入 → `BAD_INPUT`）。每条给 `za`、`digest_e`、
  `sig_der`、`expect_verify`（密码学）与 `expect_server`（服务端策略）。
- **GmSSL 交叉验证用的 ID 与上面一致**（默认 `1234567812345678`）：oracle 里
  `sm2_compute_z(..., SM2_DEFAULT_ID, ...)`，所以"GmSSL 签 ↔ 我验"与"我签 ↔ GmSSL 验"
  双向逐字节成立。

## 3.5 版本判定（前端做标签用）

`ys_version()` 返回的是 **`uint32_t` 编号 `0x00010000`，不是字符串**。

```js
const isContract = ys_version() === 0x00010000 && ys_header_len() === 112
// true  → 契约布局内核（YSPK/1.0）
// false → 未就绪/不是这个内核，不要当契约实现用
```

要"字符串形态"的版本号，从 `ys_unpack_meta` 的 JSON 里取 `version`（值为 `"YSPK/1.0"`），
或直接用常量 `YSPK/1.0`——发布构建只有这一种格式。

## 4. 错误码（数值稳定）

- `-4 … -23` 与首版**完全一致**（老映射表照旧命中）；`-24` 起是新增细粒度。
- `ys_error_name(code)` 与 `ys_error_name_v1(code)` **返回同一套 `CRYPTO_*`**
  （与 Rust `Error::name()` 逐字一致）；首版 `BAD_MAGIC` 等旧名不再返回，
  避免 wasm 与 Rust 两套自由格式。

| code | `CRYPTO_*`（唯一权威） | 含义 | 首版别名（仅解析） |
|---:|---|---|---|
| -1 | `CRYPTO_BAD_ARGUMENT` | 参数非法 | |
| -2 | `CRYPTO_BUFFER_TOO_SMALL` | 缓冲区不足（`*out_len` 给所需长度） | |
| -3 | `CRYPTO_RNG_FAILED` | 随机源失败 / 同一 seed 复用 | |
| -4 | `CRYPTO_MAGIC_MISMATCH` | 魔数不是 `YSPK` | |
| -5 | `CRYPTO_VERSION_UNSUPPORTED` | 版本 / 算法 ID 不认识 | |
| -6 | `CRYPTO_FLAGS_UNKNOWN` | FLAGS 保留位 / RESERVED 非 0 | |
| -7 | `CRYPTO_TRUNCATED` | **截断**（包长不足） | |
| -8 | `CRYPTO_KEY_UNWRAP_FAILED` | DK 解封失败 | |
| -9 | `CRYPTO_SIGNATURE_INVALID` | 签名记录 / DER 非法 | |
| -10 | `CRYPTO_MANIFEST_INVALID` | 清单结构非法 | |
| -17 | `CRYPTO_SIGNATURE_INVALID` | 验签失败 | |
| -18 | `CRYPTO_TRAILING_BYTES` | **尾随字节**（包长超出） | |
| -19 | `CRYPTO_CIPHERTEXT_INVALID` | 密文 / KDF / 曲线外点密文 | -20, -23 |
| -21 | `CRYPTO_CODE_INVALID` | 用户码非法 | |
| -22 | `CRYPTO_CODE_EXHAUSTED` | 撞码重试耗尽 | |
| -24 | `CRYPTO_HEADER_INVALID` | 头部字段非法 | |
| -25 | `CRYPTO_ALG_UNSUPPORTED` | 未知算法 ID | |
| -26 | `CRYPTO_UNSIGNED` | `SENDER_SIGNED=0` | |
| -27 | `CRYPTO_LENGTH_INCONSISTENT` | **声明互相矛盾**（非截断/非尾随） | |
| -28 | `CRYPTO_CHUNK_ORDER` | 块序 / 重复块 / 末块标志不符 | -11, -12, -14 |
| -29 | `CRYPTO_CHUNK_AUTH_FAILED` | 块 AEAD 失败 | -15 |
| -30 | `CRYPTO_CHUNK_MISSING` | 缺块 | -13 |
| -31 | `CRYPTO_MANIFEST_AUTH_FAILED` | 清单 AEAD / 一致性 | -16 |
| -32 | `CRYPTO_DIGEST_MISMATCH` | 明文摘要与清单不符 | |
| -33 | `CRYPTO_SENDER_MISMATCH` | 调用方给的公钥与包内不符 | |
| -34 | `CRYPTO_CURVE_INVALID` | 曲线点非法（`-19` 已归密文） | |
| -99 | `CRYPTO_INTERNAL` | 内部错误 | |

> **名字是唯一权威**（契约 §13.1）：判定、日志、测试一律用 `CRYPTO_*`；首版重复数值
> 只用于解析旧输入，实现不再产出。三个"长度类"必须分清：
> `-7 TRUNCATED`（包短了）/ `-18 TRAILING_BYTES`（包长了）/ `-27 LENGTH_INCONSISTENT`
> （长度字段互相矛盾，例如 `CHUNK_COUNT` 与 `PLAINTEXT_SIZE` 对不上）。

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

## 5.4 入参/出参字节数表与两个 pack 函数的关系

| 函数 | 入参关键长度 | 出参 |
|---|---|---|
| `ys_sm2_keygen` | seed ≥16 | priv 32、**pub 64**（`X‖Y`） |
| `ys_sm2_pubkey` | priv 32 | **pub 64** |
| `ys_sm2_encrypt` / `ys_sm2_verify` / `ys_user_code` / `ys_check_symbol` / `ys_pack` / `ys_pack_v1` | **pub 64** | — |
| `ys_sm2_sign` / `ys_sm2_verify` | sig raw `R‖S` 64 | — |
| `ys_sm2_sign_der` / `ys_sm2_verify_der` | sig DER 70..72 | — |
| `ys_unpack` / `ys_unpack_meta` | `sender_pub_or_0` = **64 或 0** | 明文 / JSON |
| `ys_unpack_v1` / `ys_unpack_meta_v1` / `ys_unpack_meta_prelude` | — | 明文 / JSON |

**65 字节含 `0x04` 只出现在输出/包内**：包内 `SENDER_PUB`、`WRAPPED_KEY` 的 C1、
`ys_unpack_meta*` JSON 的 `sender_pub`。其余**所有入参公钥都是 64 字节 `X‖Y`**。

**`ys_pack` 与 `ys_pack_v1` 的关系**：除 `ext`、`created_at_ms`、`chunk_size` 三个参数外
**完全等价**——`ys_pack(...)` ≡ `ys_pack_v1(..., ext="", created_at_ms=0,
chunk_size=block_size)`，两者产出同一套 `YSPK/1.0` 字节、公钥入参同为 64 字节。
清单里要写真实 `ext`/`created_at` 就用 `_v1`。

## 5.5 命名与构建约定

- **`_v1` 后缀只表示契约大版本 `YSPK/1.0`**（`ys_pack_v1` / `ys_unpack_v1` /
  `ys_unpack_meta_v1` 同族），不存在 `_v2`；后续契约小改仍走 `_v1` 语义。
- **发布构建不含任何布局切换入口**：`ys_set_layout` / `ys_get_layout` / `ys_layout_of`
  已删除；旧 rune-v1 布局实现也已删除，只有 `YSPK/1.0`（契约 §2.2 规则 7）。
- 构建 wasm 时**不要设全局 `RUSTFLAGS`/`CC` 覆盖 linker**（会给 wasm32 套 host linker）；
  只为 x86_64 host target 设 `CARGO_TARGET_X86_64_…_LINKER=gcc`。

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
