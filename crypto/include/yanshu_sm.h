/*
 * yanshu_sm.h — 雁书 YanShu 端侧国密内核 C ABI（wasm32-unknown-unknown）
 *
 * 由 Rust `crypto/sm` 导出（`#[no_mangle] extern "C"`，不用 wasm-bindgen）。
 * wasm 模块导出 `memory` 与下列函数，**没有任何 import**。
 *
 * ## 只有一种包格式
 * 全库只实现 `docs/CRYPTO-PACK.md` 的 `YSPK/1.0`：HEADER 112 字节、SENDER_PUB 65、
 * WRAPPED_KEY 129（C1 带 0x04）、清单 `YSM1`、签名 DER、块记录 16 字节头 + 密文 + tag。
 * 不再保留任何第二套格式。
 *
 * ## ABI 变更（Owl 授权的 P1）
 * 只有两个导出改了签名（来源改为包内自证）：
 * 没有破坏性变更：ys_unpack / ys_unpack_meta 的 7 参原型保留，第 4 个入参（发送方公钥）
 * 变成**可选**（NULL 表示不传）；新增 6 参的 ys_unpack_v1 / ys_unpack_meta_v1 供新代码用。
 * `_v1` 后缀只表示契约大版本 `YSPK/1.0`（与 ys_pack_v1 同族），不是"第二套布局"。
 * 发布构建**没有任何布局切换入口**（旧布局实现已删除，只有 YSPK/1.0）。
 * 其余 23 个导出签名未变。新增：ys_pack_v1 / ys_sm2_sign_der / ys_check_symbol /
 * ys_error_name_v1。
 *
 * ## 通用约定
 * - 长度参数 size_t（wasm32 = 4 字节）；指针 = 线性内存偏移；u64 参数在 JS 里是 BigInt。
 * - 返回 0 = 成功，负数 = 错误码；-4..-23 与首版一致，新增从 -24 起。
 * - `out_len`：缓冲区不足时写所需长度并返回 -2；`ys_pack*` 返回的是**上界**
 *   （DER 签名按 72 算），按它分配再调用一次即可成功，且**不会消耗随机数**。
 * - 需要随机的接口都传 `seed`（JS 用 crypto.getRandomValues 现取，>=16 字节）。
 *   **同一 seed 二次使用会返回 -3（RNG）**，不再静默复用。
 * - `ys_alloc(n)` ↔ `ys_free(p, n)` 成对、长度一致。
 *
 * ## 入参/出参字节数表（一行一个函数，别再猜）
 *
 * 记法：`in/out` 均为字节；`&n` 是 `size_t *out_len`。整表只有两处出现 65 字节，
 * 都在**输出/包内**：`SENDER_PUB` 段与 `ys_unpack_meta*` 的 JSON `sender_pub`。
 *
 * | 函数 | 入参关键长度 | 出参 |
 * |---|---|---|
 * | `ys_alloc` / `ys_free` | `len` | 内存指针 |
 * | `ys_version` / `ys_header_len` / `ys_default_block_size` | — | u32 |
 * | `ys_error_name` / `ys_error_name_v1` | `code` | ASCII 名（`CRYPTO_*`） |
 * | `ys_sm3` | in 任意 | 32 |
 * | `ys_hmac_sm3` | key 任意、msg 任意 | 32 |
 * | `ys_hkdf_sm3` | ikm/salt/info 任意 | `out_len` |
 * | `ys_sm4_encrypt_block` / `_decrypt_block` | key 16、in 16 | 16 |
 * | `ys_sm4_gcm_encrypt` | key 16、nonce 12、aad 任意、in 任意 | ct = in 长度、tag 16 |
 * | `ys_sm4_gcm_decrypt` | key 16、nonce 12、in 任意、tag 16 | pt = in 长度 |
 * | `ys_sm2_keygen` | seed ≥16 | priv 32、**pub 64**（`X‖Y`） |
 * | `ys_sm2_pubkey` | priv 32 | **pub 64** |
 * | `ys_sm2_encrypt` | **pub 64**、seed、明文 1..255 | C1C3C2 = 96+明文（无 `0x04`） |
 * | `ys_sm2_decrypt` | priv 32、密文 96+len | 明文 |
 * | `ys_sm2_sign` | **priv 32**、seed、msg 任意 | raw `R‖S` 64 |
 * | `ys_sm2_verify` | **pub 64**、msg、sig 64 | 1/0/负 |
 * | `ys_sm2_sign_der` | priv 32、seed、msg | DER 70..72 |
 * | `ys_sm2_verify_der` | **pub 64**、msg、DER | 1/0/负 |
 * | `ys_user_code` / `ys_check_symbol` | **pub 64**（`X‖Y`） | 4 / 1 ASCII |
 * | `ys_user_code_wire` / `ys_check_symbol_wire` | **pub 65**（`0x04‖X‖Y`） | 4 / 1 ASCII |
 * | `ys_normalize_code` | 任意文本 | 4 ASCII |
 * | `ys_pack` | **recipient_pub 64**、sender_priv 32、name/mime/block_size/seed/data | 包（上界见 `out_len`） |
 * | `ys_pack_v1` | 同上 + `ext` + `created_at_ms` + `chunk_size` | 包 |
 * | `ys_unpack` | pack、priv 32、`sender_pub_or_0`（**64 或 0**） | 明文 |
 * | `ys_unpack_meta` | 同上 | JSON |
 * | `ys_unpack_v1` / `ys_unpack_meta_v1` | pack、priv 32 | 明文 / JSON |
 * | `ys_unpack_meta_prelude` | pack（≥ prelude）、priv 32 | JSON（`scope=prelude`） |
 *
 * **一句话**：`ys_sm2_keygen` 与 `ys_sm2_pubkey` 的输出都是 **64 字节 `X‖Y`（不含 `0x04`）**；
 * 65 字节含 `0x04` 只出现在三处**包内/元数据**位置——`SENDER_PUB` 段、`WRAPPED_KEY` 的 C1、
 * `ys_unpack_meta*` JSON 的 `sender_pub`，`0x04` 前缀**由内核在打包/解包时补或去**，
 * 调用方不参与。所有入参公钥也一律 64 字节 `X‖Y`（`ys_pack_v1` 与 `ys_pack` 相同）。
 *
 * ## 错误名（唯一格式）
 * `ys_error_name()` 与 `ys_error_name_v1()` 都返回 **`CRYPTO_*`**（与 Rust 侧
 * `Error::name()` 逐字一致）；不再返回 `BAD_MAGIC` 等旧名。例：
 * `-4 → CRYPTO_MAGIC_MISMATCH`、`-29 → CRYPTO_CHUNK_AUTH_FAILED`、
 * `-33 → CRYPTO_SENDER_MISMATCH`。
 */

#ifndef YANSHU_SM_H
#define YANSHU_SM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- 内存 / 元信息 */

uint8_t *ys_alloc(size_t len);
void ys_free(uint8_t *ptr, size_t len);
uint32_t ys_version(void);            /* 0x0001_0000 */
uint32_t ys_default_block_size(void); /* 1 MiB */
uint32_t ys_header_len(void);         /* 112（YSPK/1.0） */

/* 错误名，唯一格式 CRYPTO_*（与 Rust `Error::name()` 一致） */
int32_t ys_error_name(int32_t code, uint8_t *out, size_t cap, size_t *out_len);
/* `ys_error_name` 的别名，输出相同 */
int32_t ys_error_name_v1(int32_t code, uint8_t *out, size_t cap, size_t *out_len);

/* ---------------------------------------------------------------- SM3 / HMAC / HKDF */

int32_t ys_sm3(const uint8_t *input, size_t input_len, uint8_t *out /* 32 */);
int32_t ys_hmac_sm3(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t *out /* 32 */);
int32_t ys_hkdf_sm3(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/* ---------------------------------------------------------------- SM4 / GCM */

int32_t ys_sm4_encrypt_block(const uint8_t *key /* 16 */, const uint8_t *input /* 16 */,
                             uint8_t *out /* 16 */);
int32_t ys_sm4_decrypt_block(const uint8_t *key /* 16 */, const uint8_t *input /* 16 */,
                             uint8_t *out /* 16 */);

int32_t ys_sm4_gcm_encrypt(const uint8_t *key /* 16 */, const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
                           uint8_t *out, uint8_t *tag_out /* 16 */);
/* tag 失败返回 -15（TAG_MISMATCH） */
int32_t ys_sm4_gcm_decrypt(const uint8_t *key /* 16 */, const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
                           const uint8_t *tag /* 16 */, uint8_t *out);

/* ---------------------------------------------------------------- SM2（64 字节公钥 / 裸 R‖S） */

int32_t ys_sm2_keygen(const uint8_t *seed, size_t seed_len, uint8_t *priv_out /* 32 */,
                      uint8_t *pub_out /* 64 = X‖Y */);
int32_t ys_sm2_pubkey(const uint8_t *priv_key /* 32 */, uint8_t *pub_out /* 64 */);

/* 输出裸 C1C3C2（不带 0x04），长度 = 96 + 明文长度 */
int32_t ys_sm2_encrypt(const uint8_t *public_key /* 64 */, const uint8_t *seed, size_t seed_len,
                       const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap,
                       size_t *out_len);
int32_t ys_sm2_decrypt(const uint8_t *priv_key /* 32 */, const uint8_t *input, size_t input_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* 输出裸 R‖S（64 字节） */
int32_t ys_sm2_sign(const uint8_t *priv_key /* 32 */, const uint8_t *seed, size_t seed_len,
                    const uint8_t *msg, size_t msg_len, uint8_t *sig_out /* 64 */);
int32_t ys_sm2_verify(const uint8_t *public_key /* 64 */, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig /* 64 */);

/* 契约口径签名（DER 70..72 字节），新增 */
int32_t ys_sm2_sign_der(const uint8_t *priv_key /* 32 */, const uint8_t *seed, size_t seed_len,
                        const uint8_t *msg, size_t msg_len, uint8_t *sig_out, size_t sig_cap,
                        size_t *sig_len_out);

/* 契约口径验签：公钥 64B X‖Y + DER 签名；1 通过 / 0 不通过 / 负数错误。
 * 固定 userID = 1234567812345678，e = SM3(ZA‖msg)。服务端校验 X-YS-Signature 用这个。 */
int32_t ys_sm2_verify_der(const uint8_t *public_key /* 64 */, const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig_der, size_t sig_len);

/* ---------------------------------------------------------------- 用户码（4 位，不加长） */

/* 入参 64 字节公钥；内核补 0x04 后按契约（SM3 覆盖 65 字节）派生 4 位码 */
int32_t ys_user_code(const uint8_t *public_key /* 64 */, uint8_t *out /* 4 ASCII */);
/* 第 5 位校验字符：仅 UI 防误输入，**不是用户码的一部分** */
int32_t ys_check_symbol(const uint8_t *public_key /* 64 */, uint8_t *out /* 1 ASCII */);
/*
 * 归一化（一句定义）：丢弃 `-`、空格、TAB、CR、LF；其余转 ASCII 大写后 O→0、I→1、L→1；
 * 结果必须全在 0123456789ABCDEFGHJKMNPQRSTVWXYZ 且**恰好 4 位**（不足不补齐、超过不截断、
 * 不做任何猜测性纠错）；失败返回 -21 CRYPTO_CODE_INVALID；**幂等** f(f(x))==f(x)。
 * 向量：testdata/normalize-vectors.json（20 组：13 接受 + 7 拒绝）。
 */
int32_t ys_normalize_code(const uint8_t *input, size_t input_len, uint8_t *out /* 4 ASCII */);

/* ---------------------------------------------------------------- 加密包 YSPK/1.0 */

/*
 * 打包：name(UTF-8) / mime(ASCII 小写) / block_size(0 = 1 MiB)。
 * 清单里 ext 为空、created_at = 0；需要它们用 ys_pack_v1。
 */
int32_t ys_pack(const uint8_t *recipient_public /* 64 */, const uint8_t *sender_private /* 32 */,
                const uint8_t *name, size_t name_len, const uint8_t *mime, size_t mime_len,
                uint32_t block_size, const uint8_t *seed, size_t seed_len, const uint8_t *data,
                size_t data_len, uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * 解包（首版 7 参原型，保留）。sender_public 可选：传 NULL/0 表示不比对；
 * 非空则与包内 SENDER_PUB 比对（不一致 → -33 CRYPTO_SENDER_MISMATCH）。
 * 验签始终用包内公钥，调用方**不再需要**提供公钥。
 */
int32_t ys_unpack(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private /* 32 */,
                  const uint8_t *sender_public_or_null /* 64，可传 0 */, uint8_t *out,
                  size_t out_cap, size_t *out_len);

/* 只解清单（同上，sender_public 可选），JSON 含 sender_code / sender_pub（来自包内） */
int32_t ys_unpack_meta(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                       const uint8_t *sender_public_or_null, uint8_t *out, size_t out_cap,
                       size_t *out_len);

/* P1 新原型（6 参）：来源完全由包内 SENDER_PUB 自证，不给公钥。新代码建议用这两个。 */
int32_t ys_unpack_v1(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                     uint8_t *out, size_t out_cap, size_t *out_len);
/* 整包：要求 ENVELOPE_LEN 完全一致；JSON 里 "scope":"full" */
int32_t ys_unpack_meta_v1(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * 只凭 prelude 解元信息（允许整包未到齐）。契约允许：清单与签名都在 prelude 内
 * （§4.3 prelude 定义、§8.1 MANIFEST_SEC、§10.2 SIG_INPUT 覆盖 HDR_CORE/SENDER_PUB/MANIFEST_SEC）。
 * 需要 pack_len >= PRELUDE_LEN = 112+65+129+MANIFEST_LEN+SIG_LEN。
 * JSON 里 "scope":"prelude"、**"data_verified":false**：来源与清单已校验，
 * 块摘要 / 块 AEAD 尚未校验 —— 不能据此宣称数据完整；完整性只认 ys_unpack(_v1) 成功。
 */
int32_t ys_unpack_meta_prelude(const uint8_t *pack, size_t pack_len,
                               const uint8_t *recipient_private, uint8_t *out, size_t out_cap,
                               size_t *out_len);

/* 打包（完整参数）：多一个 ext 与 created_at_ms（u64）。公钥 64 字节 X‖Y。 */
int32_t ys_pack_v1(const uint8_t *recipient_public /* 64 = X‖Y */, const uint8_t *sender_private,
                   const uint8_t *name, size_t name_len, const uint8_t *mime, size_t mime_len,
                   const uint8_t *ext, size_t ext_len, uint64_t created_at_ms, uint32_t chunk_size,
                   const uint8_t *seed, size_t seed_len, const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_cap, size_t *out_len);

/* ---------------------------------------------------------------- 错误码（稳定） */

#define YS_OK 0
#define YS_ERR_BAD_ARGUMENT (-1)
#define YS_ERR_BUFFER_TOO_SMALL (-2)
#define YS_ERR_RNG (-3)
#define YS_ERR_BAD_MAGIC (-4)
#define YS_ERR_UNSUPPORTED_VERSION (-5)
#define YS_ERR_BAD_FLAGS (-6)
#define YS_ERR_TRUNCATED (-7)            /* CRYPTO_TRUNCATED（首版 -7 正名） */
#define YS_ERR_BAD_KEY_RECORD (-8)
#define YS_ERR_BAD_SIGNATURE_RECORD (-9)
#define YS_ERR_BAD_MANIFEST_RECORD (-10)
#define YS_ERR_BAD_SIGNATURE (-17)       /* 验签失败，同 CRYPTO_SIGNATURE_INVALID */
#define YS_ERR_TRAILING_BYTES (-18)
#define YS_ERR_CIPHERTEXT_INVALID (-19)  /* 首版 -20/-23 是它的别名 */
#define YS_ERR_BAD_CODE (-21)
#define YS_ERR_CODE_EXHAUSTED (-22)
#define YS_ERR_HEADER_INVALID (-24)
#define YS_ERR_ALG_UNSUPPORTED (-25)
#define YS_ERR_UNSIGNED (-26)
#define YS_ERR_LENGTH_INCONSISTENT (-27) /* 声明互相矛盾（≠ 截断 ≠ 尾随字节） */
#define YS_ERR_CHUNK_ORDER (-28)         /* 首版 -11/-12/-14 的别名目标 */
#define YS_ERR_CHUNK_AUTH_FAILED (-29)   /* 首版 -15 的别名目标 */
#define YS_ERR_CHUNK_MISSING (-30)       /* 首版 -13 的别名目标 */
#define YS_ERR_MANIFEST_AUTH_FAILED (-31) /* 首版 -16 的别名目标 */
#define YS_ERR_DIGEST_MISMATCH (-32)
#define YS_ERR_SENDER_MISMATCH (-33)
#define YS_ERR_CURVE_INVALID (-34)
#define YS_ERR_INTERNAL (-99)

/*
 * 首版重复数值只作**解析别名**，实现不再产出（`ys_error_name` 仍能识别）：
 *   -11 / -12 / -14 → -28 CHUNK_ORDER；-13 → -30 CHUNK_MISSING；
 *   -15 → -29 CHUNK_AUTH_FAILED；-16 → -31 MANIFEST_AUTH_FAILED；
 *   -20 / -23 → -19 CIPHERTEXT_INVALID。
 * 判定、日志、测试一律用**名字**（`CRYPTO_*`），数值只作兼容。
 */

#endif /* YANSHU_SM_H */
