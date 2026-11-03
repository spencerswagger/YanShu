/**
 * base64url（RFC 4648 §5），**不带 `=` 填充**。
 *
 * 契约（API.md §0.1 / CRYPTO-PACK §3.2）：解码方 MUST 拒绝含 `=` 的输入、
 * MUST 拒绝 len % 4 == 1 的输入。这里严格照做，不做"宽容解码"。
 */

const TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const LOOKUP = new Map([...TABLE].map((ch, i) => [ch, i]))

export function encode(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let out = ''
  let i = 0
  for (; i + 2 < buf.length; i += 3) {
    const n = (buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2]
    out += TABLE[(n >> 18) & 63] + TABLE[(n >> 12) & 63] + TABLE[(n >> 6) & 63] + TABLE[n & 63]
  }
  const rest = buf.length - i
  if (rest === 1) {
    const n = buf[i] << 16
    out += TABLE[(n >> 18) & 63] + TABLE[(n >> 12) & 63]
  } else if (rest === 2) {
    const n = (buf[i] << 16) | (buf[i + 1] << 8)
    out += TABLE[(n >> 18) & 63] + TABLE[(n >> 12) & 63] + TABLE[(n >> 6) & 63]
  }
  return out
}

export class Base64UrlError extends Error {}

export function decode(text) {
  if (typeof text !== 'string') throw new Base64UrlError('not a string')
  if (text.includes('=')) throw new Base64UrlError('padding is not allowed')
  if (text.length % 4 === 1) throw new Base64UrlError('invalid length')
  let bits = 0
  let acc = 0
  const out = []
  for (const ch of text) {
    const v = LOOKUP.get(ch)
    if (v === undefined) throw new Base64UrlError(`invalid character: ${ch}`)
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((acc >> bits) & 0xff)
    }
  }
  // 末尾多余的 bit 必须为 0（规范编码），否则视为非法
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Base64UrlError('non-canonical tail')
  return new Uint8Array(out)
}
