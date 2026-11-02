/*
 * yanshu_sm.h — 雁书 YanShu 端侧国密内核 C ABI（wasm32-unknown-unknown）
 *
 * 由 Rust `crypto/sm` 导出（`#[no_mangle] extern "C"`，不用 wasm-bindgen）。
 * wasm 模块导出 `memory` 与下列函数，**没有任何 import**。
 *
 * 通用约定：
 *   - 长度参数为 size_t（wasm32 = 4 字节，对应 JS 的 number / u32）。
 *   - 指针是线性内存偏移；JS 侧先用 `ys_alloc` 申请、写完数据再调用。
 *   - 返回值 0 = 成功，负数为错误码（见文件末尾）。
 *   - `out_len` 指针：成功写实际长度；缓冲区不足时也写所需长度并返回 -2。
 *   - 需要随机的接口都要传 `seed`（JS 用 crypto.getRandomValues 现取，>=16 字节）。
 *     内核再混入进程内计数器展开为 SM3-DRBG；**同一份 seed 不要复用**。
 *   - 所有长度必须与申请时一致：`ys_alloc(n)` ↔ `ys_free(p, n)`。
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
uint32_t ys_version(void);            /* 0x0001_0000 = 1.0 */
uint32_t ys_default_block_size(void); /* 1 MiB */
uint32_t ys_header_len(void);         /* 40 */
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

/* tag 校验失败返回 -15 */
int32_t ys_sm4_gcm_decrypt(const uint8_t *key /* 16 */, const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
                           const uint8_t *tag /* 16 */, uint8_t *out);

/* ---------------------------------------------------------------- SM2 */

int32_t ys_sm2_keygen(const uint8_t *seed, size_t seed_len, uint8_t *priv_out /* 32 */,
                      uint8_t *pub_out /* 64 */);
int32_t ys_sm2_pubkey(const uint8_t *priv_key /* 32 */, uint8_t *pub_out /* 64 */);

/* C1C3C2 平文拼接；密文长度 = 96 + 明文长度 */
int32_t ys_sm2_encrypt(const uint8_t *public_key /* 64 */, const uint8_t *seed, size_t seed_len,
                       const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap,
                       size_t *out_len);

int32_t ys_sm2_decrypt(const uint8_t *priv_key /* 32 */, const uint8_t *input, size_t input_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* 签名输出 r||s（64 字节，非 DER） */
int32_t ys_sm2_sign(const uint8_t *priv_key /* 32 */, const uint8_t *seed, size_t seed_len,
                    const uint8_t *msg, size_t msg_len, uint8_t *sig_out /* 64 */);

/* 1 = 验签通过，0 = 不通过，负数 = 参数/曲线错误 */
int32_t ys_sm2_verify(const uint8_t *public_key /* 64 */, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig /* 64 */);

/* ---------------------------------------------------------------- 用户码（4 位 Crockford Base32） */

int32_t ys_user_code(const uint8_t *public_key /* 64 */, uint8_t *out /* 4 ASCII */);
int32_t ys_normalize_code(const uint8_t *input, size_t input_len, uint8_t *out /* 4 ASCII */);

/* ---------------------------------------------------------------- 加密包 v1 */

/*
 * 打包：密文/签名都由内核生成。
 *   recipient_public 64 | sender_private 32 | name(UTF-8) | mime(UTF-8) |
 *   block_size(0 = 默认 1 MiB) | seed | data
 */
int32_t ys_pack(const uint8_t *recipient_public, const uint8_t *sender_private, const uint8_t *name,
                size_t name_len, const uint8_t *mime, size_t mime_len, uint32_t block_size,
                const uint8_t *seed, size_t seed_len, const uint8_t *data, size_t data_len,
                uint8_t *out, size_t out_cap, size_t *out_len);

/* 只解清单（不解数据块）：out 输出 JSON 元信息（name/mime/size/block_*/file_id/digests） */
int32_t ys_unpack_meta(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                       const uint8_t *sender_public, uint8_t *out, size_t out_cap, size_t *out_len);

/* 完整解包：out 输出明文（严格模式，任何篡改返回负错误码） */
int32_t ys_unpack(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                  const uint8_t *sender_public, uint8_t *out, size_t out_cap, size_t *out_len);

/* ---------------------------------------------------------------- 错误码（稳定契约） */

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
#define YS_ERR_INTERNAL (-99)

#ifdef __cplusplus
}
#endif

#endif /* YANSHU_SM_H */
