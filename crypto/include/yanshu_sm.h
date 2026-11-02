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
 * ## 公钥口径（一张表，别再猜）
 *
 * | 导出 | 公钥入参/出参 | 长度 | 含 0x04 |
 * |---|---|---:|---|
 * | `ys_sm2_keygen` | out `pub_out` | 64 | 否（`X‖Y`） |
 * | `ys_sm2_pubkey` | out `pub_out` | 64 | 否 |
 * | `ys_sm2_encrypt` | in `public_key` | 64 | 否 |
 * | `ys_sm2_decrypt` | 密文 `input`（C1C3C2） | 96+len | 否 |
 * | `ys_sm2_verify` | in `public_key` | 64 | 否 |
 * | `ys_user_code` / `ys_check_symbol` | in `public_key` | 64 | 否 |
 * | `ys_pack` / `ys_pack_v1` | in `recipient_public` | 64 | 否 |
 * | `ys_sm2_sign_der` | 私钥 32 | — | — |
 *
 * **ABI 层一律 64 字节 `X‖Y`，不带 `0x04`**；契约要求的 `0x04‖X‖Y`（包内
 * `SENDER_PUB`、`WRAPPED_KEY` 的 C1）由内核内部补/去。传出包里的 `sender_pub`
 * （`ys_unpack_meta` 的 JSON）是 **65 字节含 `0x04`**，因为那就是包内原文。
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
int32_t ys_unpack_meta_v1(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                          uint8_t *out, size_t out_cap, size_t *out_len);

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
#define YS_ERR_TRUNCATED (-7)
#define YS_ERR_BAD_KEY_RECORD (-8)
#define YS_ERR_BAD_SIGNATURE_RECORD (-9)
#define YS_ERR_BAD_MANIFEST_RECORD (-10)
#define YS_ERR_BLOCK_SEQUENCE (-11)
#define YS_ERR_DUPLICATE_BLOCK (-12)
#define YS_ERR_MISSING_BLOCK (-13)
#define YS_ERR_LAST_FLAG_MISMATCH (-14)
#define YS_ERR_TAG_MISMATCH (-15)
#define YS_ERR_MANIFEST_MISMATCH (-16)
#define YS_ERR_SIGNATURE_MISMATCH (-17)
#define YS_ERR_TRAILING_BYTES (-18)
#define YS_ERR_BAD_POINT (-19)
#define YS_ERR_BAD_KDF (-20)
#define YS_ERR_BAD_CODE (-21)
#define YS_ERR_CODE_EXHAUSTED (-22)
#define YS_ERR_BAD_CIPHERTEXT (-23)
/* 新增（契约细粒度） */
#define YS_ERR_HEADER_INVALID (-24)
#define YS_ERR_ALG_UNSUPPORTED (-25)
#define YS_ERR_UNSIGNED (-26)
#define YS_ERR_LENGTH_INCONSISTENT (-27)
#define YS_ERR_CHUNK_ORDER (-28)
#define YS_ERR_CHUNK_AUTH_FAILED (-29)
#define YS_ERR_CHUNK_MISSING (-30)
#define YS_ERR_MANIFEST_AUTH_FAILED (-31)
#define YS_ERR_DIGEST_MISMATCH (-32)
#define YS_ERR_SENDER_MISMATCH (-33)
#define YS_ERR_INTERNAL (-99)

#ifdef __cplusplus
}
#endif

#endif /* YANSHU_SM_H */
