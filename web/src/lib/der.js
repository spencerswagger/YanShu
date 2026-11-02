/**
 * SM2 签名的 DER 编码（CRYPTO-PACK §3.5 / §10.4：`SEQUENCE { r INTEGER, s INTEGER }`，严格 DER）。
 *
 * 为什么放在 Web 侧：契约要求 wire 上的签名是 DER（70..72 字节），而内核若只给 64 字节
 * `r‖s`，转换必须在边界上做一次。这是**签名编码**，不是加密包内部字段，不违反"包内字段只由
 * WASM 读写"的边界。
 *
 * 规则：INTEGER 用最短补码，最高位为 1 时补一个 `0x00`；长度用最短编码。
 */

function encodeInteger(raw) {
  let i = 0
  while (i < raw.length - 1 && raw[i] === 0x00) i += 1
  let body = raw.slice(i)
  if (body.length === 0) body = Uint8Array.of(0)
  if (body[0] & 0x80) {
    const padded = new Uint8Array(body.length + 1)
    padded.set(body, 1)
    body = padded
  }
  return Uint8Array.of(0x02, body.length, ...body)
}

function encodeSequence(body) {
  if (body.length < 0x80) return Uint8Array.of(0x30, body.length, ...body)
  if (body.length <= 0xff) return Uint8Array.of(0x30, 0x81, body.length, ...body)
  return Uint8Array.of(0x30, 0x82, (body.length >> 8) & 0xff, body.length & 0xff, ...body)
}

/** 64 字节 `r‖s` → DER（70..72 字节）。输入不是 64 字节直接拒绝，避免"猜"。 */
export function encodeSignature(raw) {
  if (!raw || raw.length !== 64) throw new Error('raw signature must be 64 bytes')
  return encodeSequence(Uint8Array.of(...encodeInteger(raw.slice(0, 32)), ...encodeInteger(raw.slice(32))))
}

/**
 * 内核可能已经给 DER（70..72 字节）。这里只判断"看起来是 DER 且长度合规"，
 * 不做完整 ASN.1 解析（解析属于内核职责，Web 不猜语义）。
 */
export function normalizeSignature(sig) {
  if (sig.length === 64) return encodeSignature(sig)
  if (sig.length >= 70 && sig.length <= 72 && sig[0] === 0x30) return sig
  throw new Error(`unexpected signature length: ${sig.length}`)
}
