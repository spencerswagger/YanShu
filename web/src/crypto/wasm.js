/**
 * WASM 加载器与内存桥（WebAssembly.instantiate + 线性内存 alloc/free + 输入输出拷贝）。
 *
 * 只在主线程/Worker 里被 `crypto/index.js` 调一次；UI 不直接碰这里。
 * 内存纪律：每次调用都 `ys_alloc` → 拷贝 → 调 → 拷贝出 → `ys_free`，长度必须一致；
 * 任何一次 `memory.grow` 都会让旧 `ArrayBuffer` 失效，所以视图一律现取（见 `#mem()`）。
 */
import { ABI_VERSION, REQUIRED_EXPORTS, PACK_INFO_LEN, ERROR_CODE_MAP, ERROR_NAME_MAP } from './abi.js'
import { CryptoError } from './errors.js'
import { utf8 } from '../lib/bytes.js'

export async function loadKernelWasm(url) {
  let buffer
  try {
    const res = await fetch(url, { cache: 'no-cache' })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    buffer = await res.arrayBuffer()
  } catch (err) {
    throw new CryptoError('CRYPTO_NOT_READY', `未找到端侧内核产物（${url}）：${err.message}`)
  }
  let instance
  try {
    ;({ instance } = await WebAssembly.instantiate(buffer, {}))
  } catch (err) {
    throw new CryptoError('CRYPTO_NOT_READY', `wasm 实例化失败：${err.message}`)
  }
  return new WasmKernel(instance.exports)
}

export class WasmKernel {
  /** @param {WebAssembly.Exports} exports */
  constructor(exports) {
    this.mode = 'wasm'
    this.isRealCrypto = true
    this.exports = exports

    const missing = REQUIRED_EXPORTS.filter((name) => typeof exports[name] !== 'function')
    if (missing.length) {
      throw new CryptoError('CRYPTO_ABI_MISMATCH', `缺少导出：${missing.join(', ')}`)
    }
    if (!(exports.memory instanceof WebAssembly.Memory)) {
      throw new CryptoError('CRYPTO_ABI_MISMATCH', '缺少 memory 导出')
    }
    const version = exports.ys_abi_version()
    if (version !== ABI_VERSION) {
      throw new CryptoError(
        'CRYPTO_ABI_MISMATCH',
        `ABI 版本 0x${version.toString(16)} ≠ 0x${ABI_VERSION.toString(16)}`,
      )
    }
    this.version = typeof exports.ys_version === 'function' ? exports.ys_version() : version
  }

  // ---------------------------------------------------------------- 内存桥

  #mem() {
    return new Uint8Array(this.exports.memory.buffer)
  }

  #u32(ptr) {
    return new DataView(this.exports.memory.buffer).getUint32(ptr, true)
  }

  alloc(len) {
    const ptr = this.exports.ys_alloc(len)
    if (!ptr) throw new CryptoError('CRYPTO_BUFFER_TOO_SMALL', `alloc(${len}) 失败`)
    return ptr
  }

  free(ptr, len) {
    if (ptr) this.exports.ys_free(ptr, len)
  }

  /** 把 JS 字节写进线性内存，返回 {ptr, len, release()}。 */
  #write(bytes) {
    const src = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
    if (src.length === 0) return { ptr: 0, len: 0, release: () => {} }
    const ptr = this.alloc(src.length)
    this.#mem().set(src, ptr)
    return { ptr, len: src.length, release: () => this.free(ptr, src.length) }
  }

  #read(ptr, len) {
    return this.#mem().slice(ptr, ptr + len)
  }

  /** 统一错误码转换：负数 → CRYPTO_*；能拿到内核名字就用名字。 */
  #check(rc, what) {
    if (rc === 0) return
    if (rc > 0) return // ys_verify 之类：1 = 通过
    const name = this.#errorName(rc)
    const code = (name && ERROR_NAME_MAP[name]) || ERROR_CODE_MAP[-rc] || 'CRYPTO_INTERNAL'
    throw new CryptoError(code, `${what || '调用'} 返回 ${rc}${name ? `/${name}` : ''}`)
  }

  #errorName(rc) {
    if (typeof this.exports.ys_error_name !== 'function') return null
    const cap = 64
    const out = this.alloc(cap)
    const outLen = this.alloc(4)
    try {
      const r = this.exports.ys_error_name(rc, out, cap, outLen)
      if (r !== 0) return null
      const len = this.#u32(outLen)
      return new TextDecoder().decode(this.#read(out, len))
    } catch {
      return null
    } finally {
      this.free(out, cap)
      this.free(outLen, 4)
    }
  }

  /** 通用"输出缓冲区"调用：cap 不够（-2）时按内核回报的所需长度重试一次。 */
  #outCall(what, call, initialCap = 4096) {
    let cap = initialCap
    for (let attempt = 0; attempt < 2; attempt++) {
      const out = this.alloc(cap)
      const outLenPtr = this.alloc(4)
      try {
        const rc = call(out, cap, outLenPtr)
        const need = this.#u32(outLenPtr)
        if (rc === -2 && attempt === 0 && need > cap) {
          cap = need
          continue
        }
        this.#check(rc, what)
        return this.#read(out, need)
      } finally {
        this.free(out, cap)
        this.free(outLenPtr, 4)
      }
    }
    throw new CryptoError('CRYPTO_BUFFER_TOO_SMALL', what)
  }

  #seed() {
    const seed = new Uint8Array(32)
    crypto.getRandomValues(seed)
    return seed
  }

  // ---------------------------------------------------------------- 身份 / 码

  generateIdentity() {
    return this.#outCall('ys_identity_generate', (out, cap, outLen) => {
      const seed = this.#write(this.#seed())
      try {
        return this.exports.ys_identity_generate(seed.ptr, seed.len, out, cap, outLen)
      } finally {
        seed.release()
      }
    })
  }

  identityPublic(blob) {
    return this.#outCall('ys_identity_public', (out, cap, outLen) => {
      const b = this.#write(blob)
      try {
        return this.exports.ys_identity_public(b.ptr, b.len, out, cap, outLen)
      } finally {
        b.release()
      }
    }, 128)
  }

  identityCode(blob) {
    const out = this.alloc(5)
    const b = this.#write(blob)
    try {
      this.#check(this.exports.ys_identity_code(b.ptr, b.len, out), 'ys_identity_code')
      const raw = new TextDecoder().decode(this.#read(out, 5))
      return { code: raw.slice(0, 4), check: raw.slice(4, 5) }
    } finally {
      b.release()
      this.free(out, 5)
    }
  }

  sign(blob, message) {
    return this.#outCall('ys_sign', (out, cap, outLen) => {
      const b = this.#write(blob)
      const m = this.#write(message)
      const seed = this.#write(this.#seed())
      try {
        return this.exports.ys_sign(b.ptr, b.len, seed.ptr, seed.len, m.ptr, m.len, out, cap, outLen)
      } finally {
        b.release()
        m.release()
        seed.release()
      }
    }, 128)
  }

  verify(publicKey, message, signature) {
    const p = this.#write(publicKey)
    const m = this.#write(message)
    const s = this.#write(signature)
    try {
      const rc = this.exports.ys_verify(p.ptr, m.ptr, m.len, s.ptr, s.len)
      if (rc < 0) this.#check(rc, 'ys_verify')
      return rc === 1
    } finally {
      p.release()
      m.release()
      s.release()
    }
  }

  sm3(data) {
    const out = this.alloc(32)
    const d = this.#write(data)
    try {
      this.#check(this.exports.ys_sm3(d.ptr, d.len, out), 'ys_sm3')
      return this.#read(out, 32)
    } finally {
      d.release()
      this.free(out, 32)
    }
  }

  codeOfPublic(publicKey) {
    const out = this.alloc(5)
    const p = this.#write(publicKey)
    try {
      this.#check(this.exports.ys_code_of_public(p.ptr, out), 'ys_code_of_public')
      const raw = new TextDecoder().decode(this.#read(out, 5))
      return { code: raw.slice(0, 4), check: raw.slice(4, 5) }
    } finally {
      p.release()
      this.free(out, 5)
    }
  }

  normalizeCode(text) {
    const out = this.alloc(4)
    const input = this.#write(utf8.encode(text))
    try {
      const rc = this.exports.ys_normalize_code(input.ptr, input.len, out)
      if (rc !== 0) return null
      return new TextDecoder().decode(this.#read(out, 4))
    } finally {
      input.release()
      this.free(out, 4)
    }
  }

  // ---------------------------------------------------------------- 打包（发送方）

  packOpen({ identity, recipientPublic, name, mime, plaintextSize, chunkSize, createdAt }) {
    const sender = this.#write(identity)
    const recipient = this.#write(recipientPublic)
    const nameBytes = this.#write(utf8.encode(name))
    const mimeBytes = this.#write(utf8.encode(mime))
    const seed = this.#write(this.#seed())
    const handlePtr = this.alloc(4)
    try {
      const rc = this.exports.ys_pack_open(
        sender.ptr,
        sender.len,
        recipient.ptr,
        nameBytes.ptr,
        nameBytes.len,
        mimeBytes.ptr,
        mimeBytes.len,
        Math.floor(plaintextSize / 0x100000000),
        plaintextSize >>> 0,
        chunkSize,
        Math.floor(createdAt / 0x100000000),
        createdAt >>> 0,
        seed.ptr,
        seed.len,
        handlePtr,
      )
      this.#check(rc, 'ys_pack_open')
      return this.#u32(handlePtr)
    } finally {
      sender.release()
      recipient.release()
      nameBytes.release()
      mimeBytes.release()
      seed.release()
      this.free(handlePtr, 4)
    }
  }

  packDigest(handle, index, plain) {
    const d = this.#write(plain)
    try {
      this.#check(this.exports.ys_pack_digest(handle, index, d.ptr, d.len), 'ys_pack_digest')
    } finally {
      d.release()
    }
  }

  packSeal(handle) {
    return this.#outCall('ys_pack_seal', (out, cap, outLen) => {
      return this.exports.ys_pack_seal(handle, out, cap, outLen)
    }, 1024)
  }

  packChunk(handle, index, plain) {
    return this.#outCall(
      'ys_pack_chunk',
      (out, cap, outLen) => {
        const d = this.#write(plain)
        try {
          return this.exports.ys_pack_chunk(handle, index, d.ptr, d.len, out, cap, outLen)
        } finally {
          d.release()
        }
      },
      plain.length + 64,
    )
  }

  packInfo(handle) {
    const out = this.alloc(PACK_INFO_LEN)
    try {
      this.#check(this.exports.ys_pack_info(handle, out), 'ys_pack_info')
      const view = new DataView(this.exports.memory.buffer)
      return {
        chunkSize: view.getUint32(out, false),
        chunkCount: view.getUint32(out + 4, false),
        plaintextSize: Number(view.getBigUint64(out + 8, false)),
        preludeLen: view.getUint32(out + 16, false),
        state: view.getUint32(out + 20, false),
      }
    } finally {
      this.free(out, PACK_INFO_LEN)
    }
  }

  packExport(handle) {
    return this.#outCall('ys_pack_export', (out, cap, outLen) => {
      return this.exports.ys_pack_export(handle, out, cap, outLen)
    }, 1024)
  }

  packImport(blob) {
    const b = this.#write(blob)
    const handlePtr = this.alloc(4)
    try {
      this.#check(this.exports.ys_pack_import(b.ptr, b.len, handlePtr), 'ys_pack_import')
      return this.#u32(handlePtr)
    } finally {
      b.release()
      this.free(handlePtr, 4)
    }
  }

  packClose(handle) {
    this.exports.ys_pack_close(handle)
  }

  // ---------------------------------------------------------------- 解包（接收方）

  unpackOpen({ prelude, identity }) {
    const p = this.#write(prelude)
    const id = this.#write(identity)
    const handlePtr = this.alloc(4)
    try {
      const metaBytes = this.#outCall(
        'ys_unpack_open',
        (out, cap, outLen) => {
          return this.exports.ys_unpack_open(p.ptr, p.len, id.ptr, id.len, out, cap, outLen, handlePtr)
        },
        512,
      )
      let meta
      try {
        meta = JSON.parse(new TextDecoder().decode(metaBytes))
      } catch {
        throw new CryptoError('CRYPTO_MANIFEST_INVALID', '清单元信息不是合法 JSON')
      }
      return { handle: this.#u32(handlePtr), meta }
    } finally {
      p.release()
      id.release()
      this.free(handlePtr, 4)
    }
  }

  unpackChunk(handle, index, ciphertext) {
    return this.#outCall(
      'ys_unpack_chunk',
      (out, cap, outLen) => {
        const c = this.#write(ciphertext)
        try {
          return this.exports.ys_unpack_chunk(handle, index, c.ptr, c.len, out, cap, outLen)
        } finally {
          c.release()
        }
      },
      ciphertext.length + 64,
    )
  }

  unpackFinish(handle) {
    this.#check(this.exports.ys_unpack_finish(handle), 'ys_unpack_finish')
  }

  unpackClose(handle) {
    this.exports.ys_unpack_close(handle)
  }
}
