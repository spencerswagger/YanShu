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

## 7. 布局可插拔：契约是默认，rune-v1 只作兼容

| 布局 | 默认？ | 头长 | 签名 | 清单摘要 | 谁在用 |
|---|---|---:|---|---|---|
| `YSPK/1.0`（`crate::pack`） | ✅ 默认 | 112 | DER | `SM3(明文块)` | 产品、Web、契约验收 |
| `rune-v1`（`crate::pack_rune_v1`） | ❌ 需显式 `ys_set_layout(1)` | 40 | 裸 `R‖S` | `SM3(密文‖tag)` | Gate 的历史证据（非契约） |

- **不会混**：一个产物的字节只属于一种布局；`ys_layout_of()` 用 `HEADER[4..8]` 判别
  （契约 `01 00 00 70` vs rune-v1 `01 01 …`）。
- Gate 的探针（`qa/evidence/adapters/ys_pack_probe.rs`）**不改一行**就能编译，默认产契约包；
  要看 rune-v1 只需在驱动侧调 `ys_set_layout(1)`（或直接用 `pack_rune_v1` 模块）。
- 已实测：探针 keygen→pack→unpack 往返一致，包 `HEADER_LEN=112`；篡改必失败。

## 8. 错误码与名字：数值向后兼容，名字两套

* **数值**：`-4..-23` 与首版**完全一致**（Web 的 `ERROR_CODES` 表照旧命中），
  新语义从 `-24` 起（`HEADER_INVALID`、`CHUNK_ORDER`、`CHUNK_AUTH_FAILED`、
  `CHUNK_MISSING`、`MANIFEST_AUTH_FAILED`、`DIGEST_MISMATCH`、`SENDER_MISMATCH`…）。
* **名字**：
  - `Error::name()` / `ys_error_name_v1()` → 契约口径 `CRYPTO_*`（Gate 探针的正则、日志用）；
  - `ys_error_name()` → 首版 `BAD_MAGIC` 等旧名（Web 映射表按旧名查，仍能落到有意义的 `CRYPTO_*`）。
* 能区分的要求已满足：块序 → `BLOCK_SEQUENCE`/`CHUNK_ORDER`，清单 → `MANIFEST_MISMATCH`/
  `MANIFEST_AUTH_FAILED`，截断 → `TRUNCATED`/`LENGTH_INCONSISTENT`，缺块 → `MISSING_BLOCK`/
  `CHUNK_MISSING`，版本 → `UNSUPPORTED_VERSION`，tag → `TAG_MISMATCH`/`CHUNK_AUTH_FAILED`。

## 9. 两层篡改防线（Gate 实测结论已写进测试）

* **AEAD 层**：AAD 绑 `CHUNK_INDEX / LAST_FLAG / CHUNK_COUNT / CHUNK_SIZE / PLAINTEXT_SIZE / PT_LEN`
  （契约 §7.2），直接改密文或 tag → `CRYPTO_CHUNK_AUTH_FAILED`（`check_20`）。
* **序号绑定层**：换两块 / 重复块 / 跳号 / 末块标志被改 → `CRYPTO_CHUNK_ORDER` /
  `CRYPTO_CHUNK_MISSING`（`check_19`、`check_22`），不需要等清单摘要兜底。
* **预期现象**：在 **rune-v1** 布局里，清单摘要是对 `密文‖tag` 算的且先于 GCM 校验，
  所以改密文会被 `MANIFEST_MISMATCH` 先拦住、`TAG_MISMATCH` 端到端取不到 —— 这是设计，
  不是缺陷（`pack_rune_v1::layered_tamper_tests` 固化）。
  契约布局反过来：GCM 先校验，`CHUNK_AUTH_FAILED` 可稳定触发。
* **清单摘要层**：清单被改但签名有效（发送方自己签错）→ `CRYPTO_DIGEST_MISMATCH`（`check_21`）。

## 10. §15 样例的可重算性

契约若要改 AAD（例如把 `CHUNK_INDEX` 再显式加进块 AAD 之外的域），§15 的样例字节会重算。
本仓库的样例常量**不是手抄**：`crypto/sm/tests/contract_samples.rs` 由脚本从
`docs/CRYPTO-PACK.md` 抽取生成，契约一更新就重生成再跑测试，不会"悄悄钉死"。
