/*
 * yanshu_sm.h — 雁书 YanShu 端侧国密内核 C ABI（wasm32-unknown-unknown）
 *
 * 由 Rust `crypto/sm` 导出（`#[no_mangle] extern "C"`，不用 wasm-bindgen）。
 * wasm 模块导出 `memory` 与下列函数，**没有任何 import**。
 *
 * ## ABI 稳定性
 * 首版公布的 25 个导出**签名未变**（Web `feat/web-min-loop` 与 Gate 探针按它编译）。
 * 契约 YSPK/1.0 需要的 65 字节未压缩点、DER 签名、清单 created_at/ext 全在内核内部转换。
 * 新增能力放在 `*_v1` 导出里，不改变既有函数。
 *
 * ## 布局（可插拔，默认契约）
 * - 默认 `ys_pack` / `ys_unpack` 产/解 **契约布局 `YSPK/1.0`**（HEADER 112）。
 * - `ys_set_layout(1)` 切到 **rune-v1 兼容布局**（非契约、HEADER 40，仅 Gate 历史证据）；
 *   `ys_header_len()` 随布局返回 112 / 40；`ys_layout_of()` 可判别一个包属于哪种。
 *   两种布局不会混进同一个产物。
 *
 * ## 通用约定
 * - 长度参数 size_t（wasm32 = 4 字节）；指针 = 线性内存偏移；u64 参数在 JS 里是 BigInt。
 * - 返回 0 = 成功，负数 = 错误码；-4..-23 与首版一致，新增从 -24 起。
 * - `out_len`：缓冲区不足时写所需长度并返回 -2；`ys_pack*` 返回上界（+2，DER 签名 70..72 浮动）。
 * - 需要随机的接口都传 `seed`（JS 用 crypto.getRandomValues 现取，>=16 字节，不要复用）。
 * - `ys_alloc(n)` ↔ `ys_free(p, n)` 成对、长度一致。
 *
 * ## 公钥口径
 * ABI 一律 **64 字节 `X‖Y`**（首版口径）。契约要求的 `0x04‖X‖Y` 由内核内部补/去；
 * `ys_pack_v1` / `ys_sm2_sign_der` 等 `_v1` 导出同样接受 64 字节公钥。
 */

#ifndef YANSHU_SM_H
#define YANSHU_SM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- 内存 / 元信息 / 布局 */

uint8_t *ys_alloc(size_t len);
void ys_free(uint8_t *ptr, size_t len);
uint32_t ys_version(void);            /* 0x0001_0000 */
uint32_t ys_default_block_size(void); /* 1 MiB（首版名，保留） */
uint32_t ys_default_chunk_size(void); /* 同上（契约命名） */
uint32_t ys_header_len(void);         /* 当前布局：契约 112 / rune-v1 40 */

int32_t ys_set_layout(uint32_t id);   /* 0 = YSPK/1.0（默认），1 = rune-v1 */
uint32_t ys_get_layout(void);
int32_t ys_layout_of(const uint8_t *pack, size_t pack_len); /* 0 / 1 / 负数 */

/* 首版错误名（BAD_MAGIC…），Web 的映射表按这套查 */
int32_t ys_error_name(int32_t code, uint8_t *out, size_t cap, size_t *out_len);
/* 契约错误名（CRYPTO_*），新增 */
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

/* ---------------------------------------------------------------- SM2（64 字节公钥 / 裸 R‖S，首版口径） */

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
/* 1 = 通过，0 = 不通过，负数 = 错误 */
int32_t ys_sm2_verify(const uint8_t *public_key /* 64 */, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig /* 64 */);

/* 契约口径签名（DER 70..72 字节），新增 */
int32_t ys_sm2_sign_der(const uint8_t *priv_key /* 32 */, const uint8_t *seed, size_t seed_len,
                        const uint8_t *msg, size_t msg_len, uint8_t *sig_out, size_t sig_cap,
                        size_t *sig_len_out);

/* ---------------------------------------------------------------- 用户码（4 位，不加长） */

/* 入参 64 字节公钥；内核补 0x04 后按契约（SM3 覆盖 65 字节）派生 4 位码 */
int32_t ys_user_code(const uint8_t *public_key /* 64 */, uint8_t *out /* 4 ASCII */);
/* 第 5 位校验字符：仅 UI 防误输入，**不是用户码的一部分**，不上 wire */
int32_t ys_check_symbol(const uint8_t *public_key /* 64 */, uint8_t *out /* 1 ASCII */);
int32_t ys_normalize_code(const uint8_t *input, size_t input_len, uint8_t *out /* 4 ASCII */);

/* ---------------------------------------------------------------- 加密包 */

/*
 * 打包（默认契约布局）：name(UTF-8) / mime(ASCII 小写) / block_size(0 = 1 MiB)。
 * 契约清单里的 ext 为空、created_at = 0；需要它们用 ys_pack_v1。
 */
int32_t ys_pack(const uint8_t *recipient_public /* 64 */, const uint8_t *sender_private /* 32 */,
                const uint8_t *name, size_t name_len, const uint8_t *mime, size_t mime_len,
                uint32_t block_size, const uint8_t *seed, size_t seed_len, const uint8_t *data,
                size_t data_len, uint8_t *out, size_t out_cap, size_t *out_len);

/* 解包；sender_public 是调用方手里的发送方公钥（64 字节），与包内 SENDER_PUB 比对 */
int32_t ys_unpack(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private /* 32 */,
                  const uint8_t *sender_public /* 64 */, uint8_t *out, size_t out_cap,
                  size_t *out_len);

/* 只解清单（不解数据块），输出 JSON 元信息 */
int32_t ys_unpack_meta(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                       const uint8_t *sender_public, uint8_t *out, size_t out_cap,
                       size_t *out_len);

/* 打包（完整参数）：多一个 ext 与 created_at_ms（u64） */
int32_t ys_pack_v1(const uint8_t *recipient_public /* 64 */, const uint8_t *sender_private,
                   const uint8_t *name, size_t name_len, const uint8_t *mime, size_t mime_len,
                   const uint8_t *ext, size_t ext_len, uint64_t created_at_ms, uint32_t chunk_size,
                   const uint8_t *seed, size_t seed_len, const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_cap, size_t *out_len);

/* 解包（契约口径）：按 4 位发送方码校验（NULL/0 = 不校验） */
int32_t ys_unpack_v1(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                     const uint8_t *expected_sender_code, size_t expected_sender_code_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);
int32_t ys_unpack_meta_v1(const uint8_t *pack, size_t pack_len, const uint8_t *recipient_private,
                          const uint8_t *expected_sender_code, size_t expected_sender_code_len,
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
/* 新增（契约细粒度；旧映射表会落到 CRYPTO_INTERNAL，不影响旧语义） */
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
