/**
 * SM2 签名的 DER 编码/解码（CRYPTO-PACK §3.5 / §10.4：`SEQUENCE { r INTEGER, s INTEGER }`，严格 DER）。
 *
 * 内核当前输出 `r‖s`（64 字节），wire 上要 DER（70..72）。这一层是纯编码转换，
 * 不涉及包内字段；内核返工成直接给 DER 后，`normalizeSignature` 会原样返回。
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
 * 内核可能已经给 DER。契约 §10.4 写的是 70..72（假设 r、s 各自 32 字节、最高位为 1 时补 1 字节），
 * 但 r/s 高位为 0 时严格 DER 会去掉前导零，长度可能到 68/69。这里按"形状"接受 68..72，
 * 不解析语义；服务端按 DER 解析，不看长度。
 */
export function normalizeSignature(sig) {
  if (!sig || sig.length === 0) throw new Error('empty signature')
  if (sig.length === 64) return encodeSignature(sig)
  if (sig.length >= 68 && sig.length <= 72 && sig[0] === 0x30) return sig
  throw new Error(`unexpected signature length: ${sig.length}`)
}

/**
 * DER → 64 字节 `r‖s`（给内核验签用）。严格解析：SEQUENCE、两个 INTEGER、最短编码、
 * 不允许尾部多余字节（契约 §10.4：不给签名延展性留空间）。
 */
export function decodeSignature(der) {
  if (!der || der.length < 68 || der[0] !== 0x30) throw new Error('not a DER signature')
  let offset = 2
  if (der[1] & 0x80) {
    const n = der[1] & 0x7f
    offset = 2 + n
  }
  const readInt = () => {
    if (der[offset] !== 0x02) throw new Error('expected INTEGER')
    const len = der[offset + 1]
    let start = offset + 2
    let end = start + len
    if (end > der.length) throw new Error('INTEGER overruns')
    let body = der.subarray(start, end)
    // 去掉可能的 0x00 前缀（补码为正数时 DER 会补 1 字节）
    while (body.length > 32 && body[0] === 0x00) body = body.subarray(1)
    if (body.length > 32) throw new Error('INTEGER too long')
    offset = end
    const out = new Uint8Array(32)
    out.set(body, 32 - body.length)
    return out
  }
  const r = readInt()
  const s = readInt()
  if (offset !== der.length) throw new Error('trailing bytes in signature')
  const out = new Uint8Array(64)
  out.set(r, 0)
  out.set(s, 32)
  return out
}
