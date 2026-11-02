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

## 7. 只有一种格式：YSPK/1.0

`pack_rune_v1`（首版 40 字节头 / 裸 R‖S / 密文摘要）已**删除**。仓库里只存在
`docs/CRYPTO-PACK.md` 的 `YSPK/1.0`：HEADER 112、SENDER_PUB 65、WRAPPED_KEY 129（C1 带 0x04）、
清单 `YSM1`、签名 DER、块记录 16 字节头 + 密文 + tag、块 nonce `u64be(index)‖000000‖last`、
清单 nonce `ff*8‖00000001`、块 AAD 32 字节 / 清单 AAD 31 字节、HKDF salt=`KDF_SALT`、
info=`YANSHU/v1/{chunk,manifest}-key`。不再有第二套格式，也不会混淆 `YSPK`。

## 8. C ABI 变更（Owl 授权的 P1）

| 导出 | 首版 | 现在 |
|---|---|---|
| `ys_unpack` | `(pack, len, priv, sender_pub, out, cap, out_len)` | 同原型，第 4 参**可选**（NULL = 不传；非空则与包内比对） |
| `ys_unpack_meta` | `(pack, len, priv, sender_pub, out, cap, out_len)` | 同原型，第 4 参可选 |
| `ys_unpack_v1` | — | **新增** `(pack, len, priv, out, cap, out_len)` |
| `ys_unpack_meta_v1` | — | **新增** `(pack, len, priv, out, cap, out_len)` |

选这个形状的原因：wasm 调函数时**多余的实参会被静默丢弃**——如果直接把 7 参改成 6 参，
旧调用会整体错位一位（`out` 收到公钥指针、`out_len` 收到一个容量数字），是内存踩踏而不是
编译错。保留 7 参原型 + 可选入参，旧调用点原样能跑；新代码用 6 参的 `ys_unpack_v1` /
`ys_unpack_meta_v1`（`_v1` 只表示契约大版本 `YSPK/1.0`，与 `ys_pack_v1` 同族）。

其余 23 个导出签名未变。相对首版共**新增 6 个**导出：`ys_pack_v1`（清单 `ext`/`created_at`）、
`ys_sm2_sign_der`（契约 DER 签名）、`ys_check_symbol`（第 5 位校验字符，仅 UI 防误）、
`ys_error_name_v1`（契约 `CRYPTO_*` 错误名）、`ys_unpack_v1` / `ys_unpack_meta_v1`（6 参解包）。
当前 wasm 共 **31 个导出 = 30 个函数 + `memory`**，0 import。

**版本判定**：`ys_version()` 返回 **u32 `0x00010000`**（不是字符串）；字符串 `YSPK/1.0`
出现在 `ys_unpack_meta` 的 JSON `version` 字段，也等于常量
`pack::v1::VERSION_STRING`。发布构建只有这一种格式，因此
`ys_version()==0x00010000 && ys_header_len()==112` 即可判定"契约布局内核"。

**P1 效果**：`ys_unpack` / `ys_unpack_meta` 只给收件人私钥即可——验签用包内
`SENDER_PUB`，发送方 4 位码也由它派生（契约 §10.3）；换掉包内公钥任一字节即验签失败。
`ys_unpack_meta` 的 JSON 直接带 `sender_code` / `sender_pub`。
Rust 侧 API 为 `pack::unpack(pack, recipient_sk, Option<&str>)`（第三个参数是可选的
"期望发送方码"比对，不是公钥）；Gate 的探针一行未改即可编译并跑通离线解包。

## 9. 错误码与名字：数值向后兼容，名字两套

* 数值 `-4..-23` 与首版完全一致；新语义从 `-24` 起。
* `Error::name()` / `ys_error_name_v1()` → 契约 `CRYPTO_*`；
  `ys_error_name()` → 首版 `BAD_MAGIC` 等旧名（Web 映射表按旧名查）。
* 能区分：块序 `CHUNK_ORDER` / 清单 `MANIFEST_MISMATCH`·`MANIFEST_AUTH_FAILED` /
  截断 `TRUNCATED`·`LENGTH_INCONSISTENT` / 缺块 `CHUNK_MISSING`·`MISSING_BLOCK` /
  版本 `UNSUPPORTED_VERSION` / tag `TAG_MISMATCH`·`CHUNK_AUTH_FAILED`。

## 9.4 AAD 的字节级证明

`contract_samples.rs::aad_bytes_match_contract_section_7` 直接断言：

* `AAD_CHUNK(0, last=1, pt_len=5)` == 契约 §15.2 的 32 字节 hex
  `015953504b010000100000000000010000000000000005000000000100000005`；
* `AAD_MANIFEST` == 契约 §15.3 的 31 字节 hex
  `025953504b010000000002001000000000000100000000000000050000005d`；
* 六个绑定字段（`CHUNK_INDEX / CHUNK_COUNT / CHUNK_SIZE / PLAINTEXT_SIZE / LAST_FLAG / PT_LEN`）
  各改动一处，AAD 必变——少绑一个都会断言失败。
* `digest_is_over_plaintext_block`：清单摘要 == `SM3(明文块)`（不是密文、不是 tag）。

## 9.5 评审要求的五类反例

`crypto/sm/tests/review_counterexamples.rs` 按"评审给的五种攻击"各一条，断言到具体错误名：

| 攻击 | 结果 |
|---|---|
| 改块头 1 字节（`PT_LEN`） | `CRYPTO_LENGTH_INCONSISTENT` |
| 改数据区 1 字节（密文） | `CRYPTO_CHUNK_AUTH_FAILED` |
| 删中间块（连同块头/tag） | `CRYPTO_LENGTH_INCONSISTENT`（包长先对不上） |
| 删块但保留长度（只改块号） | `CRYPTO_CHUNK_ORDER`（重复块号） |
| 换两块顺序 | `CRYPTO_CHUNK_MISSING`（首条块号 1、期望 0） |
| **搬入别的包里的合法块** | `CRYPTO_CHUNK_AUTH_FAILED`（DK 不同 + AAD 绑块号/总块数/长度） |
| 截断（尾部 / 头部中间 / 空） | `CRYPTO_LENGTH_INCONSISTENT` |

## 10. 两层篡改防线

* **AEAD 层**：AAD 绑 `CHUNK_INDEX / LAST_FLAG / CHUNK_COUNT / CHUNK_SIZE / PLAINTEXT_SIZE / PT_LEN`，
  改密文或 tag → `CRYPTO_CHUNK_AUTH_FAILED`（`check_20`）。
* **序号绑定层**：换序 / 重复 / 跳号 / 末块标志被改 → `CRYPTO_CHUNK_ORDER` / `CRYPTO_CHUNK_MISSING`
  （`check_19`、`check_22`）。
* **清单摘要层**：签名有效但摘要不符 → `CRYPTO_DIGEST_MISMATCH`（`check_21`）。
* 三种"搬块"（把别的包的合法块搬进来）也会因 AAD 里的 `CHUNK_COUNT/CHUNK_SIZE/PLAINTEXT_SIZE`
  不一致而失败。

## 11. P2 / P3 状态

* **P2-①**：块头存明文长度 —— 已满足（块记录 offset 4 的 `PT_LEN`，§6.2），
  `check_19` 覆盖 PT_LEN/CT_LEN 篡改。
* **P2-②**：同一 seed 二次使用 —— 已实现：`ys_*` 随机接口记住最近 64 个 seed 的 SM3 指纹，
  命中直接返回 `-3 CRYPTO_RNG_FAILED`，不再静默混计数器续用。
  另：`ys_pack*` 的"先问大小"用 `pack_bound()` 算上界，**不消耗随机数**，所以
  "探针 + 重试"不会误触 seed 复用。
* **P3**（只登记不实现）：产品级 `MAX_BLOCK_SIZE`（单文件总量上限）与流式接口
  （prelude/块切片分批处理），已在 `crypto/README.md` 的"已知限制"里排期。
