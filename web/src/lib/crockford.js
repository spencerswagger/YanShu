/**
 * 4 位 Crockford Base32 用户码（契约见 CRYPTO-PACK §3.4）。
 *
 * 前端只做两件事，两件都不涉及密钥：
 *   1. 归一化用户输入（大写 / 去 `-` 与空白 / O→0、I,L→1），拦掉明显打错的码；
 *   2. 由 4 位码算出第 5 位校验字符，本地拦"码打错"，不必等服务端回 404。
 *
 * 码本身**不是密钥、不是口令**：知道码只能给别人发文件，解不开任何东西。
 */

export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export const CHECK_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U'

const INDEX = new Map([...ALPHABET].map((ch, i) => [ch, i]))

/** 归一化：非法返回 null（不抛异常，UI 直接展示"码格式不对"）。 */
export function normalize(input) {
  if (typeof input !== 'string') return null
  let s = input.toUpperCase().replace(/[\s-]+/g, '')
  s = s.replace(/O/g, '0').replace(/[IL]/g, '1')
  if (s.length !== 4) return null
  for (const ch of s) if (!INDEX.has(ch)) return null
  return s
}

/** 20 bit 值（4 组 5 bit，MSB 在前）。 */
export function valueOf(code) {
  const n = normalize(code)
  if (!n) return null
  let v = 0
  for (const ch of n) v = v * 32 + INDEX.get(ch)
  return v
}

/** 第 5 位校验字符（展示用，`AWQW` → `X`）。 */
export function checkChar(code) {
  const v = valueOf(code)
  if (v === null) return null
  return CHECK_ALPHABET[v % 37]
}

/** `CODE-CHECK` 展示形态。 */
export function display(code) {
  const n = normalize(code)
  if (!n) return code
  return `${n}-${checkChar(n)}`
}

/**
 * 校验用户输入的 `CODE-CHECK`（也接受只输 4 位）。
 * @returns {{ok:boolean, code?:string, reason?:'format'|'check'}}
 */
export function verifyInput(input) {
  const raw = String(input || '').toUpperCase().replace(/\s+/g, '')
  const parts = raw.split('-').filter(Boolean)
  if (parts.length === 0) return { ok: false, reason: 'format' }
  const code = normalize(parts[0])
  if (!code) return { ok: false, reason: 'format' }
  if (parts.length >= 2) {
    const given = parts[1]
    if (given.length !== 1) return { ok: false, reason: 'format' }
    if (given !== checkChar(code)) return { ok: false, reason: 'check' }
  }
  return { ok: true, code }
}
