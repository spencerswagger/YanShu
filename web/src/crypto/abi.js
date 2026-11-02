/**
 * 端侧内核（Rust → wasm32，raw C ABI）**接口契约表**——本文件是唯一需要对齐的地方。
 *
 * 为什么单独一张表：Rune 的导出函数清单还没冻结，Web 侧所有调用都经这里，
 * 对齐时只改这个文件（+ 必要时改同名包装），业务代码不受影响。
 *
 * 设计原则（与 CRYPTO-PACK §16 的分工一致）：
 * - 加密包对 Web 是**不透明字节**：包的组装/拆解、HEADER/AAD/nonce/清单全在 WASM 里，
 *   Web 只按 §4.3 / §12 拿 "prelude" 与 "第 i 块切片"，不做任何字段拼接或解析。
 * - 所有指针都是 wasm 线性内存偏移，长度都是字节数；返回值 0 = 成功，负数 = 错误码。
 * - 输出缓冲区由调用方 `ys_alloc` 申请、用完 `ys_free`；长度不够时内核写"所需长度"并返回 -2。
 * - u64 参数一律拆成两个 u32（hi, lo），避免 JS/WASM 之间的 BigInt 边界问题。
 *
 * ⚠️ 对齐现状（2026-11-02 夜）：Rune 的 crate 在 `crypto/sm/src/ffi.rs` 里目前只导出了
 * `ys_alloc/ys_free/ys_version` 与基础算子（`ys_sm3`、`ys_sm2_*`、`ys_user_code`、`ys_normalize_code`、
 * `ys_pack`、`ys_unpack*`）。其中 `ys_pack/ys_unpack` 是**整包进出**的形态，而传输契约要求
 * "prelude 一次 + 块切片逐块"（§4.3 / §12），因此**必须**补一组会话式（streaming）导出；
 * 本表定义的就是这组。整包接口无法支撑 1 MiB 分块上传，也不允许 Web 自己去切包（那等于解析包内字段）。
 * 另：契约 §9.1 的公钥是 65 字节未压缩点（`0x04‖X‖Y`），§3.4 的码由这 65 字节派生；
 * 当前 crate 里是 64 字节（X‖Y）。两者不一致会让"码"和"发送方校验"对不上，需以契约为准。
 */

/** ABI 版本：0x00010000 = 1.0（与内核 `ys_abi_version()` 比对） */
export const ABI_VERSION = 0x00010000

/** 我们依赖的全部导出函数（缺任何一个都视为 ABI 不匹配，直接报错，不做降级猜测）。 */
export const REQUIRED_EXPORTS = [
  'ys_abi_version',
  'ys_alloc',
  'ys_free',
  'ys_identity_generate',
  'ys_identity_public',
  'ys_identity_code',
  'ys_sign',
  'ys_verify',
  'ys_sm3',
  'ys_code_of_public',
  'ys_normalize_code',
  'ys_pack_open',
  'ys_pack_digest',
  'ys_pack_seal',
  'ys_pack_chunk',
  'ys_pack_info',
  'ys_pack_export',
  'ys_pack_import',
  'ys_pack_close',
  'ys_unpack_open',
  'ys_unpack_chunk',
  'ys_unpack_finish',
  'ys_unpack_close',
]

/** 可选导出（有则用，无则走本地等价实现）。 */
export const OPTIONAL_EXPORTS = ['ys_version', 'ys_error_name']

/**
 * 函数签名说明（给人看的，也是被 Rune 对齐时的对照表）。
 *
 * 身份（SM2 密钥对；私钥 blob 只在浏览器本地，不上传、不备份）
 *   ys_identity_generate(seed:ptr, seedLen:u32, out:ptr, cap:u32, outLen:ptr) -> i32
 *       生成密钥对，输出**不透明身份 blob**（WASM 自己定义格式；Web 不解析）。
 *   ys_identity_public(blob:ptr, blobLen:u32, out:ptr, cap:u32, outLen:ptr) -> i32
 *       输出 65 字节未压缩公钥（0x04‖X32‖Y32），用于注册与分发。
 *   ys_identity_code(blob:ptr, blobLen:u32, out:ptr) -> i32
 *       输出 5 字节：4 位码 + 1 位校验字符（§3.4）。
 *   ys_sign(blob:ptr, blobLen:u32, seed:ptr, seedLen:u32, msg:ptr, msgLen:u32,
 *           out:ptr, cap:u32, outLen:ptr) -> i32
 *       输出 DER 签名（70..72 字节，§10.4）。若内核只能给 64 字节 r‖s，Web 侧按 §10.4 转 DER。
 *   ys_verify(pub:ptr, msg:ptr, msgLen:u32, sig:ptr, sigLen:u32) -> i32   // 1 通过 / 0 不通过
 *   ys_sm3(input:ptr, len:u32, out32:ptr) -> i32                        // 只用于 prelude_sm3
 *   ys_code_of_public(pub:ptr, out5:ptr) -> i32
 *   ys_normalize_code(input:ptr, len:u32, out4:ptr) -> i32              // 归一化后 4 字节
 *
 * 打包（发送方；分两遍读文件：先摘要、再加密，内存只驻留一个块）
 *   ys_pack_open(sender:ptr, senderLen:u32, recipientPub:ptr, name:ptr, nameLen:u32,
 *                mime:ptr, mimeLen:u32, sizeHi:u32, sizeLo:u32, chunkSize:u32,
 *                createdHi:u32, createdLo:u32, seed:ptr, seedLen:u32, outHandle:ptr) -> i32
 *   ys_pack_digest(handle:u32, index:u32, data:ptr, dataLen:u32) -> i32
 *   ys_pack_seal(handle:u32, out:ptr, cap:u32, outLen:ptr) -> i32       // 输出 prelude
 *   ys_pack_chunk(handle:u32, index:u32, data:ptr, dataLen:u32, out:ptr, cap:u32, outLen:ptr) -> i32
 *   ys_pack_info(handle:u32, out:ptr) -> i32                            // 24 字节，见 PACK_INFO_LAYOUT
 *   ys_pack_export(handle:u32, out:ptr, cap:u32, outLen:ptr) -> i32     // 会话快照，供刷新后续传
 *   ys_pack_import(blob:ptr, blobLen:u32, outHandle:ptr) -> i32
 *   ys_pack_close(handle:u32) -> i32
 *
 * 解包（接收方）
 *   ys_unpack_open(prelude:ptr, preludeLen:u32, identity:ptr, identityLen:u32,
 *                  outMeta:ptr, cap:u32, outLen:ptr, outHandle:ptr) -> i32
 *       校验 §13 里 prelude 能校验的部分（1..18），输出元信息 **JSON 文本**：
 *       {"name","mime","size","chunk_size","chunk_count","sender_code","version","signature":"ok"}
 *   ys_unpack_chunk(handle:u32, index:u32, ct:ptr, ctLen:u32, out:ptr, cap:u32, outLen:ptr) -> i32
 *       输入 = CHUNK_CT‖TAG（不含 16 字节块头，块头由内核按 §6.3 重建），输出明文块。
 *   ys_unpack_finish(handle:u32) -> i32                                 // §13 #22：末块唯一且齐备
 *   ys_unpack_close(handle:u32) -> i32
 */

/** `ys_pack_info` 输出布局（24 字节，大端）：chunkSize u32 | chunkCount u32 | size u64 | preludeLen u32 | state u32 */
export const PACK_INFO_LEN = 24

/** 内核错误码 → 端侧错误码。负数取绝对值索引；未列出的归到 CRYPTO_INTERNAL。 */
export const ERROR_CODE_MAP = {
  1: 'CRYPTO_BAD_ARGUMENT',
  2: 'CRYPTO_BUFFER_TOO_SMALL',
  3: 'CRYPTO_RNG',
  4: 'CRYPTO_MAGIC_MISMATCH',
  5: 'CRYPTO_VERSION_UNSUPPORTED',
  6: 'CRYPTO_HEADER_INVALID',
  7: 'CRYPTO_ALG_UNSUPPORTED',
  8: 'CRYPTO_FLAGS_UNKNOWN',
  9: 'CRYPTO_UNSIGNED',
  10: 'CRYPTO_LENGTH_INCONSISTENT',
  11: 'CRYPTO_KEY_UNWRAP_FAILED',
  12: 'CRYPTO_MANIFEST_AUTH_FAILED',
  13: 'CRYPTO_MANIFEST_INVALID',
  14: 'CRYPTO_SIGNATURE_INVALID',
  15: 'CRYPTO_SENDER_MISMATCH',
  16: 'CRYPTO_CHUNK_ORDER',
  17: 'CRYPTO_CHUNK_MISSING',
  18: 'CRYPTO_CHUNK_AUTH_FAILED',
  19: 'CRYPTO_DIGEST_MISMATCH',
}

/** `ys_error_name` 返回的名字（若内核提供）→ 端侧错误码；用于内核扩充错误码时不失配。 */
export const ERROR_NAME_MAP = {
  BadArgument: 'CRYPTO_BAD_ARGUMENT',
  BufferTooSmall: 'CRYPTO_BUFFER_TOO_SMALL',
  Rng: 'CRYPTO_RNG',
  MagicMismatch: 'CRYPTO_MAGIC_MISMATCH',
  VersionUnsupported: 'CRYPTO_VERSION_UNSUPPORTED',
  HeaderInvalid: 'CRYPTO_HEADER_INVALID',
  AlgUnsupported: 'CRYPTO_ALG_UNSUPPORTED',
  FlagsUnknown: 'CRYPTO_FLAGS_UNKNOWN',
  Unsigned: 'CRYPTO_UNSIGNED',
  LengthInconsistent: 'CRYPTO_LENGTH_INCONSISTENT',
  KeyUnwrapFailed: 'CRYPTO_KEY_UNWRAP_FAILED',
  ManifestAuthFailed: 'CRYPTO_MANIFEST_AUTH_FAILED',
  ManifestInvalid: 'CRYPTO_MANIFEST_INVALID',
  SignatureInvalid: 'CRYPTO_SIGNATURE_INVALID',
  SenderMismatch: 'CRYPTO_SENDER_MISMATCH',
  ChunkOrder: 'CRYPTO_CHUNK_ORDER',
  ChunkMissing: 'CRYPTO_CHUNK_MISSING',
  ChunkAuthFailed: 'CRYPTO_CHUNK_AUTH_FAILED',
  DigestMismatch: 'CRYPTO_DIGEST_MISMATCH',
}
