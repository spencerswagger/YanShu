/**
 * 端侧内核的**替身实现**。两种，语义严格区分：
 *
 * 1) `UnavailableKernel`（默认、也是唯一允许进生产的替身）
 *    所有方法一律抛 `CRYPTO_NOT_READY`。WASM 产物没到位时，UI 只能说"加密内核未就绪"，
 *    **绝不允许**在这里假装"加密成功"——那会让"没加密"的密文流到中转，等于骗过验收。
 *
 * 2) `DevStubKernel`（仅开发调试，`VITE_YS_CRYPTO=stub-fake` 且非生产构建）
 *    用可逆异或 + 假校验和把 UI/传输流程打通，**不是加密、不提供任何保密性**：
 *    - 产出的"prelude"以 ASCII `YSSTUB01` 开头，**不是** `YSPK`，肉眼/工具都能一眼看出不是真包；
 *    - UI 常驻红条提示"开发桩：数据未加密，勿传真实文件"；
 *    - 生产构建里 `crypto/index.js` 直接拒绝启用。
 *
 * 两者的方法集合与 `WasmKernel` 完全一致（同一套接口，便于替换）。
 */
import { CryptoError } from './errors.js'
import { ALPHABET, CHECK_ALPHABET } from '../lib/crockford.js'
import { utf8 } from '../lib/bytes.js'

export class UnavailableKernel {
  constructor(reason) {
    this.mode = 'unavailable'
    this.isRealCrypto = false
    this.reason = reason || '端侧加密内核（WASM）未就绪'
    this.version = 0
  }

  #fail() {
    throw new CryptoError('CRYPTO_NOT_READY', this.reason)
  }

  generateIdentity() {
    return this.#fail()
  }
  identityPublic() {
    return this.#fail()
  }
  identityCode() {
    return this.#fail()
  }
  sign() {
    return this.#fail()
  }
  verify() {
    return this.#fail()
  }
  sm3() {
    return this.#fail()
  }
  codeOfPublic() {
    return this.#fail()
  }
  normalizeCode() {
    return this.#fail()
  }
  packOpen() {
    return this.#fail()
  }
  packDigest() {
    return this.#fail()
  }
  packSeal() {
    return this.#fail()
  }
  packChunk() {
    return this.#fail()
  }
  packInfo() {
    return this.#fail()
  }
  packExport() {
    return this.#fail()
  }
  packImport() {
    return this.#fail()
  }
  packClose() {
    this.#fail()
  }
  unpackOpen() {
    return this.#fail()
  }
  unpackChunk() {
    return this.#fail()
  }
  unpackFinish() {
    this.#fail()
  }
  unpackClose() {
    this.#fail()
  }
}

// ---------------------------------------------------------------- 开发桩

const STUB_MAGIC = 'YSSTUB01'
// 与契约 §6.2 的 tag 长度（16 字节）保持一致，这样传输层的长度校验（PT_LEN+16）仍然成立；
// 但这 16 字节只是假校验和，不提供任何认证性。
const STUB_TAG = 16

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
  for (let i = 0; i < 32; i++) out[i] = (h >>> ((i % 4) * 8)) & 0xff
  return out
}

function codeFromPub(pub) {
  const h = fnv1a(pub)
  const v = h & 0xfffff // 20 bit
  let code = ''
  for (let i = 3; i >= 0; i--) code += ALPHABET[(v >> (i * 5)) & 31]
  return { code, check: CHECK_ALPHABET[v % 37] }
}

function xorStream(data, key, index) {
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ key[i % key.length] ^ ((index + i) & 0xff)
  }
  return out
}

export class DevStubKernel {
  constructor() {
    this.mode = 'stub-fake'
    this.isRealCrypto = false
    this.version = 0
    this.sessions = new Map()
    this.nextHandle = 1
  }

  #random(n) {
    const out = new Uint8Array(n)
    crypto.getRandomValues(out)
    return out
  }

  /** 身份 = 假密钥对（JSON 包子）；真实实现对 Web 是不透明字节，这里也保持不透明。 */
  generateIdentity() {
    const sk = this.#random(32)
    const pub = this.#random(65)
    pub[0] = 0x04
    return new TextEncoder().encode(JSON.stringify({ v: 'stub', sk: [...sk], pub: [...pub] }))
  }

  #parseIdentity(blob) {
    try {
      const obj = JSON.parse(new TextDecoder().decode(blob))
      if (obj.v !== 'stub' || !Array.isArray(obj.pub)) throw new Error('bad')
      return { sk: new Uint8Array(obj.sk), pub: new Uint8Array(obj.pub) }
    } catch {
      throw new CryptoError('CRYPTO_BAD_ARGUMENT', '身份 blob 无法解析（桩）')
    }
  }

  identityPublic(blob) {
    return this.#parseIdentity(blob).pub
  }

  identityCode(blob) {
    return codeFromPub(this.#parseIdentity(blob).pub)
  }

  sign(blob, message) {
    const { pub } = this.#parseIdentity(blob)
    // 假签名：64 字节 r‖s 形态（长度与真 SM2 一致，便于上层按 §10.4 转 DER）。
    // 内容只是摘要拼接，**没有**任何签名语义。
    const out = new Uint8Array(64)
    out.set(fakeDigest(message), 0)
    out.set(fakeDigest(pub), 32)
    return out
  }

  verify(publicKey, message, signature) {
    // 桩不做真实验签：只要求长度落在契约允许的 DER 区间（70..72）。
    return Boolean(signature) && signature.length >= 70 && signature.length <= 72
  }

  sm3(data) {
    return fakeDigest(data)
  }

  codeOfPublic(publicKey) {
    return codeFromPub(publicKey)
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

  packOpen(params) {
    const { identity, recipientPublic, name, mime, plaintextSize, chunkSize, createdAt } = params
    const sender = this.#parseIdentity(identity)
    const handle = this.nextHandle++
    this.sessions.set(handle, {
      kind: 'pack',
      senderPub: sender.pub,
      recipientPub: new Uint8Array(recipientPublic),
      name,
      mime,
      plaintextSize,
      chunkSize,
      createdAt,
      digests: new Map(),
      sealed: false,
      key: this.#random(32),
      seen: new Set(),
    })
    return handle
  }

  #session(handle, kind) {
    const s = this.sessions.get(handle)
    if (!s || s.kind !== kind) throw new CryptoError('CRYPTO_BAD_ARGUMENT', `会话 ${handle} 不存在`)
    return s
  }

  packDigest(handle, index, plain) {
    const s = this.#session(handle, 'pack')
    s.digests.set(index, fakeDigest(plain))
  }

  packSeal(handle) {
    const s = this.#session(handle, 'pack')
    if (s.prelude) return s.prelude
    const chunkCount = Math.max(1, Math.ceil(s.plaintextSize / s.chunkSize))
    const digests = []
    for (let i = 0; i < chunkCount; i++) {
      digests.push([...(s.digests.get(i) || fakeDigest(new Uint8Array(0)))])
    }
    s.sealed = true
    const header = {
      v: 'YSSTUB/1',
      // 桩的"密钥"就明文躺在 prelude 里 —— 这不是加密，连遮蔽都算不上，只用来验证可逆流程。
      key: [...s.key],
      name: s.name,
      mime: s.mime,
      size: s.plaintextSize,
      chunk_size: s.chunkSize,
      chunk_count: chunkCount,
      created_at: s.createdAt,
      sender_pub: [...s.senderPub],
      recipient_pub: [...s.recipientPub],
      digests,
      note: 'STUB-NOT-ENCRYPTED',
    }
    const json = new TextEncoder().encode(JSON.stringify(header))
    const out = new Uint8Array(STUB_MAGIC.length + 4 + json.length)
    out.set(utf8.encode(STUB_MAGIC), 0)
    new DataView(out.buffer).setUint32(STUB_MAGIC.length, json.length, false)
    out.set(json, STUB_MAGIC.length + 4)
    s.prelude = out
    return out
  }

  packChunk(handle, index, plain) {
    const s = this.#session(handle, 'pack')
    if (!s.sealed) throw new CryptoError('CRYPTO_BAD_ARGUMENT', '还没 seal 就加密块')
    const ct = xorStream(plain, s.key, index)
    const tag = fakeDigest(ct).subarray(0, STUB_TAG)
    const out = new Uint8Array(ct.length + STUB_TAG)
    out.set(ct, 0)
    out.set(tag, ct.length)
    return out
  }

  packInfo(handle) {
    const s = this.#session(handle, 'pack')
    const chunkCount = Math.max(1, Math.ceil(s.plaintextSize / s.chunkSize))
    const prelude = this.packSeal(handle)
    return {
      chunkSize: s.chunkSize,
      chunkCount,
      plaintextSize: s.plaintextSize,
      preludeLen: prelude.length,
      state: 1,
    }
  }

  packExport(handle) {
    const s = this.#session(handle, 'pack')
    const snap = {
      kind: 'pack',
      senderPub: [...s.senderPub],
      recipientPub: [...s.recipientPub],
      name: s.name,
      mime: s.mime,
      plaintextSize: s.plaintextSize,
      chunkSize: s.chunkSize,
      createdAt: s.createdAt,
      digests: [...s.digests.entries()].map(([i, d]) => [i, [...d]]),
      sealed: s.sealed,
      key: [...s.key],
      prelude: s.prelude ? [...s.prelude] : null,
    }
    return new TextEncoder().encode(JSON.stringify(snap))
  }

  packImport(blob) {
    const snap = JSON.parse(new TextDecoder().decode(blob))
    if (snap.kind !== 'pack') throw new CryptoError('CRYPTO_BAD_ARGUMENT', '快照类型不对')
    const handle = this.nextHandle++
    this.sessions.set(handle, {
      kind: 'pack',
      senderPub: new Uint8Array(snap.senderPub),
      recipientPub: new Uint8Array(snap.recipientPub),
      name: snap.name,
      mime: snap.mime,
      plaintextSize: snap.plaintextSize,
      chunkSize: snap.chunkSize,
      createdAt: snap.createdAt,
      digests: new Map(snap.digests.map(([i, d]) => [i, new Uint8Array(d)])),
      sealed: snap.sealed,
      key: new Uint8Array(snap.key),
      prelude: snap.prelude ? new Uint8Array(snap.prelude) : null,
      seen: new Set(),
    })
    return handle
  }

  packClose(handle) {
    this.sessions.delete(handle)
  }

  unpackOpen({ prelude, identity }) {
    const magic = new TextDecoder().decode(prelude.subarray(0, STUB_MAGIC.length))
    if (magic !== STUB_MAGIC) {
      throw new CryptoError('CRYPTO_MAGIC_MISMATCH', '不是开发桩产出的数据（缺 YSSTUB01）')
    }
    const len = new DataView(prelude.buffer, prelude.byteOffset).getUint32(STUB_MAGIC.length, false)
    const json = JSON.parse(
      new TextDecoder().decode(prelude.subarray(STUB_MAGIC.length + 4, STUB_MAGIC.length + 4 + len)),
    )
    const me = this.#parseIdentity(identity)
    // 桩的"收件人校验"：公钥必须对得上，否则解密失败（模拟 CRYPTO_KEY_UNWRAP_FAILED）
    const mine = [...me.pub].join(',')
    if (mine !== (json.recipient_pub || []).join(',')) {
      throw new CryptoError('CRYPTO_KEY_UNWRAP_FAILED', '这份不是发给你的（桩）')
    }
    const handle = this.nextHandle++
    this.sessions.set(handle, {
      kind: 'unpack',
      json,
      key: new Uint8Array(json.key ? json.key : []),
      seen: new Set(),
    })
    const code = codeFromPub(new Uint8Array(json.sender_pub))
    return {
      handle,
      meta: {
        name: json.name,
        mime: json.mime,
        size: json.size,
        chunk_size: json.chunk_size,
        chunk_count: json.chunk_count,
        sender_code: code.code,
        version: 'YSSTUB/1',
        signature: 'stub',
      },
    }
  }

  unpackChunk(handle, index, ciphertext) {
    const s = this.#session(handle, 'unpack')
    if (ciphertext.length < STUB_TAG) throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '切片太短')
    const ct = ciphertext.subarray(0, ciphertext.length - STUB_TAG)
    const tag = ciphertext.subarray(ciphertext.length - STUB_TAG)
    const expected = fakeDigest(ct).subarray(0, STUB_TAG)
    for (let i = 0; i < STUB_TAG; i++) {
      if (tag[i] !== expected[i]) throw new CryptoError('CRYPTO_CHUNK_AUTH_FAILED', `块 ${index}`)
    }
    s.seen.add(index)
    return xorStream(ct, s.key, index)
  }

  unpackFinish(handle) {
    const s = this.#session(handle, 'unpack')
    if (s.seen.size !== s.json.chunk_count) {
      throw new CryptoError('CRYPTO_CHUNK_MISSING', `已收 ${s.seen.size}/${s.json.chunk_count}`)
    }
  }

  unpackClose(handle) {
    this.sessions.delete(handle)
  }
}
