/**
 * 端侧内核（Rust → wasm32，raw C ABI，**0 import**）的绑定表。
 *
 * 唯一权威：`crypto/include/yanshu_sm.h`（Rune 的 crate 导出）。本文件只做两件事：
 *   1. 列出我们依赖的导出与错误名 → 端侧错误码的映射；
 *   2. 记住"内核与契约之间还差什么"，返工时只改这里和 `wasm.js`。
 *
 * 约定（与头文件一致）：
 * - 指针 = wasm 线性内存偏移；长度 = 字节数（size_t → JS number）。
 * - `ys_alloc(n)` 申请、`ys_free(p, n)` 释放，长度必须一致。
 * - 返回 0 = 成功，负数为错误码；缓冲区不足返回 -2 并写所需长度。
 * - 需要随机的接口传 `seed`（>=16 字节，每次现取，不复用）。
 *
 * 布局（内核可插拔，默认契约）：
 * - 默认 `ys_pack` / `ys_unpack` 产/解 **契约布局 YSPK/1.0**（HEADER 112、`SENDER_PUB` 入包）；`ys_header_len()` = 112。
 * - `ys_set_layout(1)` 可切到 rune-v1 兼容布局（HEADER 40，仅历史证据用）。切分算术按 `ys_header_len()` 选（`layout.js`）。
 *
 * 边界转换（都在 `wasm.js`，业务无感）：
 * - 公钥：ABI 一律 64 字节 `X‖Y`；契约 §9.1 / §3.4 的 wire 形态是 65 字节未压缩点（`0x04‖X‖Y`），
 *   适配层补/去 `0x04`。内核内部也做同样的补/去，所以 `ys_user_code` 的口径与契约一致。
 * - 签名：优先用 `ys_sm2_sign_der`（契约 §10.4 的 DER 70..72）；没有该导出时用 `ys_sm2_sign`（`r‖s`）在本地转 DER。
 * - 解包：优先用 `ys_unpack_v1` / `ys_unpack_meta_v1`（按 4 位发送方码校验，§13 #18，公钥来自包内）；
 *   没有 `_v1` 时退回 `ys_unpack`（调用方传发送方公钥，与包内 `SENDER_PUB` 比对）。
 */

/** ABI 版本：0x00010000（与 `ys_version()` 比对） */
export const ABI_VERSION = 0x00010000

/** 必须存在的导出（缺失即 ABI 不匹配，不做降级猜测）。 */
export const REQUIRED_EXPORTS = [
  'ys_alloc',
  'ys_free',
  'ys_version',
  'ys_error_name',
  'ys_sm3',
  'ys_hmac_sm3',
  'ys_hkdf_sm3',
  'ys_sm4_encrypt_block',
  'ys_sm4_decrypt_block',
  'ys_sm4_gcm_encrypt',
  'ys_sm4_gcm_decrypt',
  'ys_sm2_keygen',
  'ys_sm2_pubkey',
  'ys_sm2_encrypt',
  'ys_sm2_decrypt',
  'ys_sm2_sign',
  'ys_sm2_verify',
  'ys_user_code',
  'ys_normalize_code',
  'ys_pack',
  'ys_unpack_meta',
  'ys_unpack',
]

/** 可选导出（有则用；缺失就走等价回退）。 */
export const OPTIONAL_EXPORTS = [
  'ys_default_block_size',
  'ys_default_chunk_size',
  'ys_header_len',
  'ys_get_layout',
  'ys_layout_of',
  'ys_sm2_sign_der',
  'ys_check_symbol',
  'ys_pack_v1',
  'ys_unpack_v1',
  'ys_unpack_meta_v1',
  'ys_error_name_v1',
]

/** 内核公钥 / 契约 wire 公钥长度。 */
export const KERNEL_PUBKEY_LEN = 64
export const WIRE_PUBKEY_LEN = 65

/** 内核错误码（头文件末尾的稳定契约）→ 错误名；`ys_error_name` 不可用时用它兜底。 */
export const ERROR_CODES = {
  [-24]: 'HEADER_INVALID',
  [-25]: 'ALG_UNSUPPORTED',
  [-26]: 'UNSIGNED',
  [-27]: 'LENGTH_INCONSISTENT',
  [-28]: 'CHUNK_ORDER',
  [-29]: 'CHUNK_AUTH_FAILED',
  [-30]: 'CHUNK_MISSING',
  [-31]: 'MANIFEST_AUTH_FAILED',
  [-32]: 'DIGEST_MISMATCH',
  [-33]: 'SENDER_MISMATCH',
  [-1]: 'BAD_ARGUMENT',
  [-2]: 'BUFFER_TOO_SMALL',
  [-3]: 'RNG',
  [-4]: 'BAD_MAGIC',
  [-5]: 'UNSUPPORTED_VERSION',
  [-6]: 'BAD_FLAGS',
  [-7]: 'TRUNCATED',
  [-8]: 'BAD_KEY_RECORD',
  [-9]: 'BAD_SIGNATURE_RECORD',
  [-10]: 'BAD_MANIFEST_RECORD',
  [-11]: 'BLOCK_SEQUENCE',
  [-12]: 'DUPLICATE_BLOCK',
  [-13]: 'MISSING_BLOCK',
  [-14]: 'LAST_FLAG_MISMATCH',
  [-15]: 'TAG_MISMATCH',
  [-16]: 'MANIFEST_MISMATCH',
  [-17]: 'SIGNATURE_MISMATCH',
  [-18]: 'TRAILING_BYTES',
  [-19]: 'BAD_POINT',
  [-20]: 'BAD_KDF',
  [-21]: 'BAD_CODE',
  [-22]: 'CODE_EXHAUSTED',
  [-23]: 'BAD_CIPHERTEXT',
  [-99]: 'INTERNAL',
}

/**
 * 错误名 → 端侧错误码（`crypto/errors.js` 里的 `CRYPTO_*`）。
 * 语义按"用户能做什么"归类：同一类的不同名字可以合并，但不许把"校验失败"说成"未就绪"。
 */
export const ERROR_NAME_TO_CODE = {
  BAD_ARGUMENT: 'CRYPTO_BAD_ARGUMENT',
  BUFFER_TOO_SMALL: 'CRYPTO_BUFFER_TOO_SMALL',
  RNG: 'CRYPTO_RNG',
  BAD_MAGIC: 'CRYPTO_MAGIC_MISMATCH',
  UNSUPPORTED_VERSION: 'CRYPTO_VERSION_UNSUPPORTED',
  BAD_FLAGS: 'CRYPTO_FLAGS_UNKNOWN',
  TRUNCATED: 'CRYPTO_LENGTH_INCONSISTENT',
  BAD_KEY_RECORD: 'CRYPTO_KEY_UNWRAP_FAILED',
  BAD_SIGNATURE_RECORD: 'CRYPTO_SIGNATURE_INVALID',
  BAD_MANIFEST_RECORD: 'CRYPTO_MANIFEST_INVALID',
  BLOCK_SEQUENCE: 'CRYPTO_CHUNK_ORDER',
  DUPLICATE_BLOCK: 'CRYPTO_CHUNK_ORDER',
  MISSING_BLOCK: 'CRYPTO_CHUNK_MISSING',
  LAST_FLAG_MISMATCH: 'CRYPTO_CHUNK_ORDER',
  TAG_MISMATCH: 'CRYPTO_CHUNK_AUTH_FAILED',
  MANIFEST_MISMATCH: 'CRYPTO_MANIFEST_AUTH_FAILED',
  SIGNATURE_MISMATCH: 'CRYPTO_SIGNATURE_INVALID',
  TRAILING_BYTES: 'CRYPTO_LENGTH_INCONSISTENT',
  BAD_POINT: 'CRYPTO_KEY_UNWRAP_FAILED',
  BAD_KDF: 'CRYPTO_KEY_UNWRAP_FAILED',
  BAD_CODE: 'CRYPTO_BAD_ARGUMENT',
  CODE_EXHAUSTED: 'CRYPTO_RNG',
  BAD_CIPHERTEXT: 'CRYPTO_KEY_UNWRAP_FAILED',
  INTERNAL: 'CRYPTO_INTERNAL',
  HEADER_INVALID: 'CRYPTO_HEADER_INVALID',
  ALG_UNSUPPORTED: 'CRYPTO_ALG_UNSUPPORTED',
  UNSIGNED: 'CRYPTO_UNSIGNED',
  LENGTH_INCONSISTENT: 'CRYPTO_LENGTH_INCONSISTENT',
  CHUNK_ORDER: 'CRYPTO_CHUNK_ORDER',
  CHUNK_AUTH_FAILED: 'CRYPTO_CHUNK_AUTH_FAILED',
  CHUNK_MISSING: 'CRYPTO_CHUNK_MISSING',
  MANIFEST_AUTH_FAILED: 'CRYPTO_MANIFEST_AUTH_FAILED',
  DIGEST_MISMATCH: 'CRYPTO_DIGEST_MISMATCH',
  SENDER_MISMATCH: 'CRYPTO_SENDER_MISMATCH',
}
