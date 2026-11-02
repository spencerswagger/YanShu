# 加密包 v1 实现对照说明（Rune 端）

> 格式以 **`docs/CRYPTO-PACK.md` v1（`YSPK/1.0`）** 为准，本文只记录实现如何映射到契约章节、
> 以及哪些字节做过逐字节核对。**本文不是契约**，冲突时以契约与 ADR 为准。

## 1. 实现位置

| 契约 | 代码 | 说明 |
|---|---|---|
| §2 版本策略 | `pack::v1` + `Header::decode` | 版本/算法 ID/保留位/FLAGS 全部强校验，未知值拒绝 |
| §4 段表 | `pack::pack_with` / `pack::open` | 五段 + 块区，长度用 `total_envelope_len()` 计算后比对 |
| §5 HEADER(112) | `pack::Header` | 字段偏移见 `pack::v1::OFF_*` |
| §6 分块 + nonce | `pack::chunk_nonce` / `chunk_plain_len` | nonce = `u64be(index) ‖ 00 00 00 ‖ last` |
| §7 AAD | `pack::aad_chunk` / `aad_manifest` | 32 / 31 字节，纯字节拼接 |
| §8 清单 | `pack::Manifest` | `YSM1` 明文结构 + 每块 `SM3(明文)` |
| §9 SM2 封装 | `sm2::encrypt` + 0x04 前缀 | C1C3C2、未压缩点、129 字节 |
| §10 签名 | `sm2::sign_with_k` + `der` | `SIG_INPUT` 按 §10.2 拼；DER 严格最短编码 |
| §11 KDF | `hkdf::hkdf_sm3` | salt=`KDF_SALT`，info=`YANSHU/v1/{chunk,manifest}-key` |
| §13 校验清单 | `pack::open` + `pack::unpack` | 按顺序执行；错误名见 `error::Error::name()` |

## 2. 与契约样例的逐字节核对

`crypto/sm/tests/contract_samples.rs` 里固化了契约 §15 的样例字节（常量由文档抽取生成），
`cargo test` 会校验：

| 样例 | 断言 |
|---|---|
| §15.2 最小单块包 | 完整包 522 字节逐字节相等；HEADER / MANIFEST_SEC / SIG_SEC / 块记录分段相等 |
| §15.3 多块包（CHUNK_SIZE=32，3 块） | 完整包 743 字节逐字节相等；HEADER / MANIFEST_SEC / SIG_SEC / 三条块记录分别相等 |
| §15.4 SM2 封装样例 | 129 字节 WRAPPED_KEY 相等 |
| §15.5 签名样例 | 70 字节 DER 相等；`PB_S` 验签通过；`PB_S` 派生码 `AWQW` + 校验字符 `X` |

同时 `scripts/crosscheck/` 用 GmSSL 3.1.1（命令行 + libgmssl，固定 k）重算每个字节，
当前 **84 项 PASS / 0 FAIL**。

## 3. 两个容易踩的"口径坑"

1. **公钥长度有两种口径**：
   - 契约层（包内 `SENDER_PUB`、`WRAPPED_KEY` 的 C1、用户码派生）：**65 字节，带 `0x04`**。
   - 原语层（`sm2::encrypt/decrypt/verify` 的入参、测试向量里的 `pub` 字段）：**64 字节 `X‖Y`，不带前缀**。
     `pack` 层负责加/去前缀；Web 侧只用 65 字节版本。
2. **签名编码**：
   - 契约层（包内 `SIG_SEC`、API `X-YS-Signature`）：**DER**（70..72 字节）。
   - 原语层：`R‖S` 64 字节（便于与 GmSSL 的 `sm2_do_sign` 逐字节比）。
3. **用户码是对 65 字节公钥做 SM3**（不是 64 字节）。契约 §15.1 的 `AWQW` 只有在 65 字节口径下才对得上。

## 4. 错误码映射（端侧 → 契约 §13）

| 场景 | `Error` | 名字 | 数值 |
|---|---|---|---|
| 魔数 | `MagicMismatch` | `CRYPTO_MAGIC_MISMATCH` | -4 |
| 版本 / 未知算法 | `VersionUnsupported` / `AlgUnsupported` | `CRYPTO_VERSION_UNSUPPORTED` / `CRYPTO_ALG_UNSUPPORTED` | -5 / -8 |
| 头部字段 | `HeaderInvalid` | `CRYPTO_HEADER_INVALID` | -6 |
| 长度不自洽 / 尾随字节 | `LengthInconsistent` | `CRYPTO_LENGTH_INCONSISTENT` | -7 |
| FLAGS 保留位 | `FlagsUnknown` | `CRYPTO_FLAGS_UNKNOWN` | -9 |
| `SENDER_SIGNED=0` | `Unsigned` | `CRYPTO_UNSIGNED` | -10 |
| DK 解封 | `KeyUnwrapFailed` | `CRYPTO_KEY_UNWRAP_FAILED` | -11 |
| 清单认证 | `ManifestAuthFailed` | `CRYPTO_MANIFEST_AUTH_FAILED` | -12 |
| 清单结构 | `ManifestInvalid` | `CRYPTO_MANIFEST_INVALID` | -13 |
| 签名 | `SignatureInvalid` | `CRYPTO_SIGNATURE_INVALID` | -14 |
| 发送方码不符 | `SenderMismatch` | `CRYPTO_SENDER_MISMATCH` | -15 |
| 块序 / 末块标志 | `ChunkOrder` | `CRYPTO_CHUNK_ORDER` | -16 |
| 块认证 | `ChunkAuthFailed` | `CRYPTO_CHUNK_AUTH_FAILED` | -17 |
| 缺块 | `ChunkMissing` | `CRYPTO_CHUNK_MISSING` | -18 |
| 明文摘要不符 | `DigestMismatch` | `CRYPTO_DIGEST_MISMATCH` | -19 |

注意：**直接删掉一个块记录的字节**会先命中 `CRYPTO_LENGTH_INCONSISTENT`（§13 #12 的整包长度校验），
"缺块报明确索引"只发生在记录存在但 `CHUNK_INDEX` 跳号时。两者都是拒绝，语义不同。

## 5. 未做 / 待定

- 流式接口（`prelude` 与块切片分批处理）未做，当前 `ys_pack/ys_unpack` 是整包内存 API。
- `FLAGS.NAME_OBFUSCATED`（`NAME_MODE=0x01`）只做解析接受，未做产品侧交互。
- 不做性能极致优化（SM4-GCM ≈56 MB/s，见 `crypto/README.md`）。


## 6. §13 的 22 条校验与反例测试

`crypto/sm/tests/section13_matrix.rs` 里 **每条一个测试**（`check_01_…` … `check_22_…`），
都是"构造一个违反该项的包 → 断言具体错误名"，没有任何"尽力恢复"路径。

| # | 校验 | 错误名 | 测试 |
|---:|---|---|---|
| 1 | 总长度 ≥ 最小包 | `CRYPTO_LENGTH_INCONSISTENT` | `check_01_minimum_length` |
| 2 | `MAGIC == YSPK` | `CRYPTO_MAGIC_MISMATCH` | `check_02_magic` |
| 3 | 版本 1.0 | `CRYPTO_VERSION_UNSUPPORTED` | `check_03_version` |
| 4 | `HEADER_LEN == 112` | `CRYPTO_HEADER_INVALID` | `check_04_header_len` |
| 5 | 四个算法 ID | `CRYPTO_ALG_UNSUPPORTED` | `check_05_algorithm_ids` |
| 6 | FLAGS 保留位 / `SENDER_SIGNED=1` | `CRYPTO_FLAGS_UNKNOWN` / `CRYPTO_UNSIGNED` | `check_06_flags` |
| 7 | `RESERVED[80..112)` 全 0 | `CRYPTO_HEADER_INVALID` | `check_07_reserved` |
| 8 | `16 ≤ CHUNK_SIZE ≤ 1048576` | `CRYPTO_HEADER_INVALID` | `check_08_chunk_size_range` |
| 9 | `CHUNK_COUNT == ceil(S/C)` | `CRYPTO_LENGTH_INCONSISTENT` | `check_09_chunk_count` |
| 10 | `WRAPPED_KEY_LEN/SENDER_PUB_LEN/MANIFEST_LEN` | `CRYPTO_LENGTH_INCONSISTENT` | `check_10_length_fields` |
| 11 | `SIG_LEN == DER 自述长度` | `CRYPTO_HEADER_INVALID` | `check_11_sig_len_vs_der` |
| 12 | `ENVELOPE_LEN` 无尾随 | `CRYPTO_LENGTH_INCONSISTENT` | `check_12_envelope_length` |
| 13 | SM2 解封 | `CRYPTO_KEY_UNWRAP_FAILED` | `check_13_key_unwrap` |
| 14 | 清单 GCM | `CRYPTO_MANIFEST_AUTH_FAILED` | `check_14_manifest_auth` |
| 15 | 清单头字段（YSM1/版本/算法） | `CRYPTO_MANIFEST_INVALID` | `check_15_manifest_header` |
| 16 | 清单↔包头 / 摘要表长度 | `CRYPTO_LENGTH_INCONSISTENT` | `check_16_manifest_cross_check` |
| 17 | 签名 | `CRYPTO_SIGNATURE_INVALID` | `check_17_signature` |
| 18 | 发送方码 | `CRYPTO_SENDER_MISMATCH` | `check_18_sender_code` |
| 19 | 块头自洽 | `CRYPTO_CHUNK_ORDER` / `CRYPTO_LENGTH_INCONSISTENT` / `CRYPTO_HEADER_INVALID` | `check_19_chunk_header` |
| 20 | 块 GCM | `CRYPTO_CHUNK_AUTH_FAILED` | `check_20_chunk_auth` |
| 21 | 明文摘要 | `CRYPTO_DIGEST_MISMATCH` | `check_21_digest_mismatch` |
| 22 | 末块标志唯一且 `INDEX == COUNT-1` | `CRYPTO_CHUNK_MISSING` / `CRYPTO_CHUNK_ORDER` | `check_22_missing_chunk` |

补充：
- §3.3 的 **NFC 归一化由调用方保证**：本实现不引 unicode 归一化依赖，只校验 UTF-8、
  字符集与长度（文件名禁止 `/`、`\`、控制字符；MIME 必须 ASCII 小写且含单个 `/`；
  扩展名 ASCII 小写）。Web 侧应在传文件名前做 `String.prototype.normalize("NFC")`。
- **§3.3 字符串规则**（文件名 basename、MIME 小写字符集、扩展名小写）在打包侧返回
  `CRYPTO_BAD_ARGUMENT`、解包侧返回 `CRYPTO_MANIFEST_INVALID`，测试 `section_3_3_string_rules`。
- §13 #16 与 #21 需要在"签名仍然有效"的前提下构造（否则先被 #17 拦下）；测试里用
  `resign()` 用同一 `k_sig` 重签，专门验证"签名有效但内容不一致"的路径。
- §13 #11 的判定放在验签之前：先比 `SIG_LEN` 与 DER 自述长度，再解 DER、再验签。

## 7. C ABI 与首版 25 个导出的差异（本轮已上报）

出于契约要求（65 字节未压缩公钥、DER 签名、清单含 `created_at`/`ext`、发送方码校验），
以下导出**签名发生了破坏性变更**（不是静默改，已在上报里逐条列出）：

| 导出 | 首版 | 现在 | 契约依据 |
|---|---|---|---|
| `ys_sm2_keygen` / `ys_sm2_pubkey` | 公钥 64 字节 | 公钥 65 字节（`0x04‖X‖Y`） | §3.4 / §10.3 |
| `ys_sm2_encrypt` | 入参公钥 64；输出无前缀 | 入参 65；输出 `0x04‖C1C3C2` | §9.1 |
| `ys_sm2_decrypt` | 输入无前缀 | 输入 `0x04‖C1C3C2` | §9.1 |
| `ys_sm2_sign` | 输出裸 `R‖S`(64) | 输出 DER + `(cap, len)` | §10.4 |
| `ys_sm2_verify` | 裸 `R‖S`(64) | DER + `len` | §10.4 |
| `ys_user_code` | 公钥 64 | 公钥 65（SM3 覆盖 65 字节） | §3.4 |
| `ys_pack` | `(…, block_size, seed, …)` | `(…, ext, created_at_ms, chunk_size, seed, …)` | §8.2 |
| `ys_unpack` / `ys_unpack_meta` | 传发送方公钥 | 传**期望发送方码**（包内已带 `SENDER_PUB`） | §10.3 / §13 #18 |
| `ys_default_block_size` | 存在 | **保留**（新增 `ys_default_chunk_size` 同值别名） | — |

新增导出：`ys_check_symbol`（校验字符，仅供 UI 防误输入）、`ys_default_chunk_size`（别名）。
当前 wasm 导出 **27 个**、0 import。

> 若 Web/Gate 需要"零破坏"，我可以再加一层 `*_legacy64` 兼容导出（旧签名转调新实现）；
> 但两套 API 并存会增加用错的风险，默认只保留契约口径这一套。
