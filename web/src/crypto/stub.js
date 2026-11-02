/**
 * 端侧内核的**替身**。两种，语义严格区分：
 *
 * 1) `UnavailableKernel`（进生产的唯一替身）
 *    所有方法抛 `CRYPTO_NOT_READY`。WASM 没到位时 UI 只能说"内核未就绪"，
 *    **绝不**假装"加密成功"——否则没加密的字节会流进中转，等于骗过验收。
 *
 * 2) `DevStubKernel`（仅开发调试：`VITE_YS_CRYPTO=stub-fake` 且非生产构建）
 *    可逆异或 + 假校验和，只用来打通 UI 与传输编排；**不是加密、零保密性**：
 *    - 产物以 ASCII `YSSTUB01` 开头（不是 `YSPK`），一眼可辨；
 *    - prelude 明文里带 `STUB-NOT-ENCRYPTED` 和"密钥"，界面常驻红条；
 *    - 生产构建里 `crypto/index.js` 直接拒绝启用。
 *
 * 两个替身都实现与 `WasmKernel` 相同的门面方法（含 splitPack/joinPack），
 * 且段布局用契约那套（16 字节块头），这样传输编排在两种内核下走同一条代码路径。
 */
import { CryptoError } from './errors.js'
import { segmenterFor, splitPack, joinPack, chunkCountOf, plainTextLen } from './layout.js'
import { encodeSignature } from '../lib/der.js'
import { bytes, u32be } from '../lib/bytes.js'
import { PackSession, UnpackSession } from './session.js'

export class UnavailableKernel {
  constructor(reason) {
    this.mode = 'unavailable'
    this.isRealCrypto = false
    this.reason = reason || '端侧加密内核（WASM）未就绪'
    this.version = 0
    this.headerLen = 0
    this.blockSize = 1048576
    this.notes = []
    this.segmenter = null
  }

  #fail() {
    throw new CryptoError('CRYPTO_NOT_READY', this.reason)
  }

  generateIdentity() { return this.#fail() }
  publicKeyFromPrivate() { return this.#fail() }
  codeOf() { return this.#fail() }
  normalizeCode() { return this.#fail() }
  sign() { return this.#fail() }
  verify() { return this.#fail() }
  sm3() { return this.#fail() }
  pack() { return this.#fail() }
  unpackMeta() { return this.#fail() }
  unpack() { return this.#fail() }
  splitPack() { return this.#fail() }
  joinPack() { return this.#fail() }
  openPackSession() { return this.#fail() }
  resumePackSession() { return this.#fail() }
  openUnpackSession() { return this.#fail() }
}

// ---------------------------------------------------------------- 开发桩

const STUB_MAGIC = 'YSSTUB01'
const TAG_LEN = 16

function fnv1a(data, seed = 0x811c9dc5) {
  let h = seed >>> 0
  for (let i = 0; i < data.length; i++) {
    h ^= data[i]
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h >>> 0
}

function fakeDigest(data) {
  const out = new Uint8Array(32)
  const h = fnv1a(data)
  const h2 = fnv1a(data, 0x9e3779b9)
  for (let i = 0; i < 32; i++) out[i] = i < 16 ? (h >>> ((i % 4) * 8)) & 0xff : (h2 >>> ((i % 4) * 8)) & 0xff
  return out
}

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

function codeFromBytes(data) {
  const h = fnv1a(data)
  const v = h & 0xfffff
  let code = ''
  for (let i = 3; i >= 0; i--) code += ALPHABET[(v >> (i * 5)) & 31]
  return code
}

function xorStream(data, key, index) {
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length] ^ ((index + i) & 0xff)
  return out
}

export class DevStubKernel {
  constructor() {
    this.mode = 'stub-fake'
    this.isRealCrypto = false
    this.version = 0x00010000
    this.headerLen = 112
    this.layout = 'contract'
    this.layoutLabel = '开发桩（无布局语义）'
    this.blockSize = 1048576
    this.segmenter = segmenterFor(112)
    this.capabilities = { signDer: false, packV1: false, unpackByCode: false, layoutSwitch: false }
    this.notes = ['开发桩：可逆异或，不是加密']
  }

  #random(n) {
    const out = new Uint8Array(n)
    crypto.getRandomValues(out)
    return out
  }

  generateIdentity() {
    const privateKey = this.#random(32)
    return { privateKey, publicKey: this.publicKeyFromPrivate(privateKey) }
  }

  publicKeyFromPrivate(privateKey) {
    const pub = new Uint8Array(65)
    pub[0] = 0x04
    const d = fakeDigest(privateKey)
    pub.set(d, 1)
    pub.set(fakeDigest(d), 33)
    return pub
  }

  codeOf(publicKey) {
    return codeFromBytes(publicKey)
  }

  normalizeCode(text) {
    const s = String(text || '')
      .toUpperCase()
      .replace(/[\s-]+/g, '')
      .replace(/O/g, '0')
      .replace(/[IL]/g, '1')
    if (s.length !== 4 || [...s].some((c) => !ALPHABET.includes(c))) return null
    return s
  }

  sign(privateKey, message) {
    const raw = new Uint8Array(64)
    raw.set(fakeDigest(message), 0)
    raw.set(fakeDigest(privateKey), 32)
    // 让 r、s 的最高位为 1，DER 长度稳定落在 71/72（贴近真 SM2 的常见形态）
    raw[0] |= 0x80
    raw[32] |= 0x80
    return encodeSignature(raw)
  }

  verify(publicKey, message, signature) {
    return Boolean(signature) && signature.length >= 70 && signature.length <= 72
  }

  sm3(data) {
    return fakeDigest(data)
  }

  pack({ data, name, mime, recipientPublic, senderPrivate, blockSize = this.blockSize }) {
    const chunkSize = blockSize || this.blockSize
    const chunkCount = chunkCountOf(data.length, chunkSize)
    const key = this.#random(32)
    const digests = []
    for (let i = 0; i < chunkCount; i++) {
      const ptLen = plainTextLen(i, data.length, chunkSize, chunkCount)
      const start = i * chunkSize
      digests.push([...fakeDigest(data.subarray(start, start + ptLen))])
    }
    const header = {
      v: 'YSSTUB/1',
      note: 'STUB-NOT-ENCRYPTED',
      // 桩的"密钥"明文放在 prelude 里：零保密性，只保证可逆
      key: [...key],
      name,
      mime,
      size: data.length,
      chunk_size: chunkSize,
      chunk_count: chunkCount,
      sender_pub: [...this.publicKeyFromPrivate(senderPrivate)],
      recipient_pub: [...recipientPublic],
      digests,
    }
    const json = new TextEncoder().encode(JSON.stringify(header))
    const prelude = bytes(new TextEncoder().encode(STUB_MAGIC), u32be(json.length), json)

    const parts = [prelude]
    for (let i = 0; i < chunkCount; i++) {
      const ptLen = plainTextLen(i, data.length, chunkSize, chunkCount)
      const start = i * chunkSize
      const ct = xorStream(data.subarray(start, start + ptLen), key, i)
      parts.push(this.segmenter.buildRecordHeader(i, ptLen, chunkCount))
      parts.push(ct)
      parts.push(fakeDigest(ct).subarray(0, TAG_LEN))
    }
    const total = parts.reduce((n, p) => n + p.length, 0)
    const out = new Uint8Array(total)
    let off = 0
    for (const part of parts) {
      out.set(part, off)
      off += part.length
    }
    return out
  }

  #parsePrelude(pack) {
    const magic = new TextDecoder().decode(pack.subarray(0, STUB_MAGIC.length))
    if (magic !== STUB_MAGIC) {
      throw new CryptoError('CRYPTO_MAGIC_MISMATCH', '不是开发桩产出的数据（缺 YSSTUB01）')
    }
    const len = new DataView(pack.buffer, pack.byteOffset).getUint32(STUB_MAGIC.length, false)
    return JSON.parse(new TextDecoder().decode(pack.subarray(STUB_MAGIC.length + 4, STUB_MAGIC.length + 4 + len)))
  }

  #preludeLen(header) {
    const jsonLen = new TextEncoder().encode(JSON.stringify(header)).length
    return STUB_MAGIC.length + 4 + jsonLen
  }

  unpackMeta({ pack }) {
    const header = this.#parsePrelude(pack)
    return {
      name: header.name,
      mime: header.mime,
      size: header.size,
      block_size: header.chunk_size,
      block_count: header.chunk_count,
    }
  }

  unpack({ pack, recipientPrivate, senderPublic, senderCode }) {
    void senderCode
    const header = this.#parsePrelude(pack)
    const me = this.publicKeyFromPrivate(recipientPrivate)
    if (me.join(',') !== header.recipient_pub.join(',')) {
      throw new CryptoError('CRYPTO_KEY_UNWRAP_FAILED', '这份不是发给你的（桩）')
    }
    const chunkCount = header.chunk_count
    const chunkSize = header.chunk_size
    const preludeLen = this.#preludeLen(header)
    const key = new Uint8Array(header.key)
    const out = new Uint8Array(header.size)
    let offset = preludeLen
    for (let i = 0; i < chunkCount; i++) {
      const ptLen = plainTextLen(i, header.size, chunkSize, chunkCount)
      offset += this.segmenter.recordHeaderLen
      const ct = pack.subarray(offset, offset + ptLen)
      const tag = pack.subarray(offset + ptLen, offset + ptLen + TAG_LEN)
      const expected = fakeDigest(ct).subarray(0, TAG_LEN)
      for (let k = 0; k < TAG_LEN; k++) {
        if (tag[k] !== expected[k]) throw new CryptoError('CRYPTO_CHUNK_AUTH_FAILED', `第 ${i} 块 tag 不符`)
      }
      out.set(xorStream(ct, key, i), i * chunkSize)
      offset += ptLen + TAG_LEN
    }
    if (offset !== pack.length) throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '桩包尾部有多余字节')
    return out
  }

  splitPack(args) {
    return splitPack({ ...args, segmenter: this.segmenter })
  }

  joinPack(args) {
    return joinPack({ ...args, segmenter: this.segmenter })
  }

  openPackSession({ pack, plaintextSize, chunkSize }) {
    return new PackSession({ kernel: this, pack, plaintextSize, chunkSize })
  }

  resumePackSession(state) {
    if (!state || state.v !== 1 || !state.pack) {
      throw new CryptoError('CRYPTO_BAD_ARGUMENT', '会话快照不可用（请在当前页面续传或重发）')
    }
    return new PackSession({ kernel: this, ...state })
  }

  openUnpackSession({ prelude, recipientPrivate, senderPublic, senderCode, plaintextSize, chunkSize }) {
    return new UnpackSession({
      kernel: this,
      prelude,
      recipientPrivate,
      senderPublic,
      senderCode,
      plaintextSize,
      chunkSize,
    })
  }
}
