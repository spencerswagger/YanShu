/**
 * 端侧错误码（CRYPTO-PACK §13 与 API.md §10.3 的分界）。
 *
 * 这些码**永不上行**：只用于本地提示与日志，不上报服务端（避免把"解密失败"变成
 * 服务端可观测信号）。HTTP 侧错误码是另一套（API.md §10.1/§10.2），两套不混用。
 */

export const CRYPTO_ERRORS = {
  CRYPTO_NOT_READY: '加密内核未就绪',
  CRYPTO_ABI_MISMATCH: '加密内核接口不匹配',
  CRYPTO_BAD_ARGUMENT: '内部参数错误',
  CRYPTO_BUFFER_TOO_SMALL: '缓冲区不足',
  CRYPTO_MAGIC_MISMATCH: '不是雁书加密包',
  CRYPTO_VERSION_UNSUPPORTED: '加密包版本不支持（需要 YSPK/1.0）',
  CRYPTO_HEADER_INVALID: '加密包头无效',
  CRYPTO_ALG_UNSUPPORTED: '加密算法不支持',
  CRYPTO_FLAGS_UNKNOWN: '加密包标志位不认识',
  CRYPTO_UNSIGNED: '加密包缺少来源签名',
  CRYPTO_LENGTH_INCONSISTENT: '加密包长度不自洽',
  CRYPTO_KEY_UNWRAP_FAILED: '文件密钥解封失败（可能不是发给你的）',
  CRYPTO_MANIFEST_AUTH_FAILED: '清单校验失败（密文被改过）',
  CRYPTO_MANIFEST_INVALID: '清单结构无效',
  CRYPTO_SIGNATURE_INVALID: '来源签名校验失败',
  CRYPTO_SENDER_MISMATCH: '发送方与列表里的码不一致',
  CRYPTO_CHUNK_ORDER: '块顺序异常',
  CRYPTO_CHUNK_MISSING: '有块缺失',
  CRYPTO_CHUNK_AUTH_FAILED: '块校验失败（密文被改过）',
  CRYPTO_DIGEST_MISMATCH: '块摘要不一致',
  CRYPTO_RNG: '随机数不可用',
  CRYPTO_INTERNAL: '端侧内核内部错误',
  CRYPTO_STUB_FAKE: '当前是开发桩：数据未加密',
}

export class CryptoError extends Error {
  constructor(code, detail) {
    const message = CRYPTO_ERRORS[code] || '端侧错误'
    super(detail ? `${message}（${detail}）` : message)
    this.name = 'CryptoError'
    this.code = code
    this.detail = detail
  }
}

export function isCryptoError(err) {
  return err instanceof CryptoError || (err && String(err.code || '').startsWith('CRYPTO_'))
}

/** 给用户看的文案：端侧错误一律走这张表，不把原始异常抛给 UI。 */
export function cryptoMessage(err) {
  if (!err) return '未知错误'
  if (err instanceof CryptoError) return err.message
  if (String(err.code || '').startsWith('CRYPTO_')) {
    return CRYPTO_ERRORS[err.code] || '端侧错误'
  }
  return err.message || '端侧错误'
}
