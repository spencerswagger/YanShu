/**
 * 字节工具（只为拼 `YSAUTH1` 签名输入与派生量，**不解析/拼装加密包内部字段**）。
 *
 * 加密包一律当不透明字节：包内 HEADER / AAD / nonce / 清单的读写都在 WASM 里（契约 §16）。
 */

export const utf8 = new TextEncoder()
export const fromUtf8 = new TextDecoder('utf-8', { fatal: true })

export function bytes(...parts) {
  const list = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)))
  const total = list.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of list) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export function ascii(text) {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c > 0x7f) throw new Error('ascii only')
    out[i] = c
  }
  return out
}

export function u8(n) {
  return Uint8Array.of(n & 0xff)
}

export function u16be(n) {
  return Uint8Array.of((n >>> 8) & 0xff, n & 0xff)
}

export function u32be(n) {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n >>> 0, false)
  return b
}

export function u64be(n) {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false)
  return b
}

export function hex(buf) {
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(text) {
  const clean = text.replace(/\s+/g, '')
  if (clean.length % 2 !== 0) throw new Error('odd hex length')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function equal(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

export function toUint8(x) {
  if (x instanceof Uint8Array) return x
  if (x instanceof ArrayBuffer) return new Uint8Array(x)
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength)
  throw new Error('not binary')
}
