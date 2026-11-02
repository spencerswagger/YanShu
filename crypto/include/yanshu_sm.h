/*
 * yanshu_sm.h — 雁书 YanShu 端侧国密内核 C ABI（wasm32-unknown-unknown）
 *
 * 由 Rust `crypto/sm` 导出（`#[no_mangle] extern "C"`，不用 wasm-bindgen）。
 * wasm 模块导出 `memory` 与下列函数，**没有任何 import**。
 *
 * 通用约定：
 *   - 长度参数为 size_t（wasm32 = 4 字节）；指针是线性内存偏移。
 *   - u64 参数在 JS 里是 BigInt（例如 created_at_ms）。
 *   - 返回值 0 = 成功，负数为错误码（命名对齐 docs/CRYPTO-PACK.md §13）。
 *   - `out_len` 指针：成功写实际长度；缓冲区不足时也写所需长度并返回 -2。
 *   - 需要随机的接口都要传 `seed`（JS 用 crypto.getRandomValues 现取，>=16 字节）。
 *     内核再混入进程内计数器展开为 SM3-DRBG；**同一份 seed 不要复用**。
 *   - `ys_alloc(n)` ↔ `ys_free(p, n)` 必须成对、长度一致。
 *
 * 公钥口径：契约层（包内 / 用户码 / 这些 ABI）一律 **65 字节 = 0x04‖X‖Y**；
 *            内部原语（Rust API）用 64 字节 X‖Y，不由 ABI 暴露。
 * 签名口径：ABI 只出/只收 **DER**（70..72 字节，SEQUENCE{r,s}）。
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
uint32_t ys_version(void);              /* 0x0001_0000 = 1.0 */
uint32_t ys_default_chunk_size(void);   /* 1 MiB */
uint32_t ys_default_block_size(void);   /* 同上，兼容早期命名的别名 */
uint32_t ys_header_len(void);           /* 112（YSPK/1.0 HEADER） */
int32_t ys_error_name(int32_t code, uint8_t *out, size_t cap, size_t *out_len);

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

/* out 与明文等长；tag_out 16 字节 */
int32_t ys_sm4_gcm_encrypt(const uint8_t *key /* 16 */, const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
                           uint8_t *out, uint8_t *tag_out /* 16 */);

/* tag 校验失败返回 -17 CRYPTO_CHUNK_AUTH_FAILED */
int32_t ys_sm4_gcm_decrypt(const uint8_t *key /* 16 */, const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
                           const uint8_t *tag /* 16 */, uint8_t *out);

/* ---------------------------------------------------------------- SM2 */

/* priv 32，pub 65（0x04‖X‖Y） */
int32_t ys_sm2_keygen(const uint8_t *seed, size_t seed_len, uint8_t *priv_out /* 32 */,
                      uint8_t *pub_out /* 65 */);
int32_t ys_sm2_pubkey(const uint8_t *priv_key /* 32 */, uint8_t *pub_out /* 65 */);

/* 密文 = 0x04‖C1.x(32)‖C1.y(32)‖C3(32)‖C2(len)，总长 97+明文长度 */
int32_t ys_sm2_encrypt(const uint8_t *public_key /* 65 */, const uint8_t *seed, size_t seed_len,
                       const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap,
                       size_t *out_len);
int32_t ys_sm2_decrypt(const uint8_t *priv_key /* 32 */, const uint8_t *input, size_t input_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* 签名输出 DER（70..72 字节），对任意消息字节做 SM3(ZA‖msg) */
int32_t ys_sm2_sign(const uint8_t *priv_key /* 32 */, const uint8_t *seed, size_t seed_len,
                    const uint8_t *msg, size_t msg_len, uint8_t *sig_out, size_t sig_cap,
                    size_t *sig_len_out);

/* 1 = 验签通过，0 = 不通过，负数 = 参数/曲线错误 */
int32_t ys_sm2_verify(const uint8_t *public_key /* 65 */, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig_der, size_t sig_len);

/* ---------------------------------------------------------------- 用户码（契约 §3.4） */

/* 4 位码；pub65 派生（SM3 覆盖 65 字节） */
int32_t ys_user_code(const uint8_t *public_key /* 65 */, uint8_t *out /* 4 ASCII */);
/* 校验字符（第 5 位，展示为 CODE-CHECK），out 1 字节 */
int32_t ys_check_symbol(const uint8_t *public_key /* 65 */, uint8_t *out /* 1 ASCII */);
int32_t ys_normalize_code(const uint8_t *input, size_t input_len, uint8_t *out /* 4 ASCII */);

/* ---------------------------------------------------------------- 加密包 YSPK/1.0 */

/*
 * 打包：
 *   recipient_pub 65 | sender_priv 32 | name(UTF-8) | mime(ASCII) | ext(ASCII) |
 *   created_at_ms(u64) | chunk_size(0 = 默认 1 MiB) | seed | data
 *
 * 注意：DER 签名长度 70..72 随随机 k 浮动，`out_len` 在缓冲区不足时返回的是**上界**
 * （实际长度 + 2）。按返回值分配内存在重试时一定成功。
 */
int32_t ys_pack(const uint8_t *recipient_public, const uint8_t *sender_private, const uint8_t *name,
                size_t name_len, const uint8_t *mime, size_t mime_len, const uint8_t *ext,
                size_t ext_len, uint64_t created_at_ms, uint32_t chunk_size, const uint8_t *seed,
                size_t seed_len, const uint8_t *data, size_t data_len, uint8_t *out,
                size_t out_cap, size_t *out_len);

/*
 * 只解清单（不解数据块），输出 JSON：
 *   {"version":"YSPK/1.0","name":…,"mime":…,"ext":…,"size":…,"chunk_size":…,
 *    "chunk_count":…,"created_at_ms":…,"sender_code":"AWQW","sender_pub":"04…","kdf_salt":"…"}
 * expected_sender_code 传 NULL/0 表示不校验；给了就做 §13 #18 比对。
 */
int32_t ys_unpack_meta(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                       const uint8_t *expected_sender_code, size_t expected_sender_code_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* 完整解包（严格模式），输出明文 */
int32_t ys_unpack(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                  const uint8_t *expected_sender_code, size_t expected_sender_code_len,
                  uint8_t *out, size_t out_cap, size_t *out_len);

/* ---------------------------------------------------------------- 错误码（稳定契约） */

#define YS_OK 0
#define YS_ERR_BAD_ARGUMENT (-1)
#define YS_ERR_BUFFER_TOO_SMALL (-2)
#define YS_ERR_RNG_FAILED (-3)
#define YS_ERR_MAGIC_MISMATCH (-4)
#define YS_ERR_VERSION_UNSUPPORTED (-5)
#define YS_ERR_HEADER_INVALID (-6)
#define YS_ERR_LENGTH_INCONSISTENT (-7)
#define YS_ERR_ALG_UNSUPPORTED (-8)
#define YS_ERR_FLAGS_UNKNOWN (-9)
#define YS_ERR_UNSIGNED (-10)
#define YS_ERR_KEY_UNWRAP_FAILED (-11)
#define YS_ERR_MANIFEST_AUTH_FAILED (-12)
#define YS_ERR_MANIFEST_INVALID (-13)
#define YS_ERR_SIGNATURE_INVALID (-14)
#define YS_ERR_SENDER_MISMATCH (-15)
#define YS_ERR_CHUNK_ORDER (-16)
#define YS_ERR_CHUNK_AUTH_FAILED (-17)
#define YS_ERR_CHUNK_MISSING (-18)
#define YS_ERR_DIGEST_MISMATCH (-19)
#define YS_ERR_CODE_INVALID (-20)
#define YS_ERR_CODE_EXHAUSTED (-21)
#define YS_ERR_CURVE_INVALID (-22)
#define YS_ERR_CIPHERTEXT_INVALID (-23)
#define YS_ERR_INTERNAL (-99)

#ifdef __cplusplus
}
#endif

#endif /* YANSHU_SM_H */
