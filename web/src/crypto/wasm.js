/**
 * WASM 桥：`WebAssembly.instantiate(bytes, {})`（零 import）+ 线性内存 alloc/free + 收发拷贝。
 *
 * 只绑定 `crypto/include/yanshu_sm.h` 里的导出（见 `abi.js` 的清单），不自己发明函数。
 * 与业务之间的薄封装也在这里：公钥 64↔65、签名 r‖s→DER、整包进出的 pack/unpack。
 * 内核返工（包头 112、公钥入包、`ys_unpack` 去掉 sender_public）时，只改本文件。
 */
import {
  ABI_VERSION,
  REQUIRED_EXPORTS,
  OPTIONAL_EXPORTS,
  KERNEL_PUBKEY_LEN,
  WIRE_PUBKEY_LEN,
  ERROR_CODES,
  ERROR_NAME_TO_CODE,
} from './abi.js'
import { CryptoError } from './errors.js'
import { segmenterFor, splitPack, joinPack } from './layout.js'
import { normalizeSignature, decodeSignature } from '../lib/der.js'

export async function loadKernelWasm(url) {
  let buffer
  try {
    const res = await fetch(url, { cache: 'no-cache' })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    buffer = await res.arrayBuffer()
  } catch (err) {
    throw new CryptoError('CRYPTO_NOT_READY', `没有加载到端侧内核（${url}）：${err.message}`)
  }
  return instantiateKernel(buffer)
}

/** 直接吃字节（Node 测试 / 内联注入用）。 */
export async function instantiateKernel(bytes) {
  let module
  try {
    module = new WebAssembly.Module(bytes)
  } catch (err) {
    throw new CryptoError('CRYPTO_NOT_READY', `wasm 编译失败：${err.message}`)
  }
  const imports = WebAssembly.Module.imports(module)
  if (imports.length !== 0) {
    throw new CryptoError('CRYPTO_ABI_MISMATCH', `内核应当 0 import，实际 ${imports.length} 个`)
  }
  let instance
  try {
    instance = new WebAssembly.Instance(module, {})
  } catch (err) {
    throw new CryptoError('CRYPTO_NOT_READY', `wasm 实例化失败：${err.message}`)
  }
  return new WasmKernel(instance.exports)
}

export class WasmKernel {
  constructor(exports) {
    this.mode = 'wasm'
    this.isRealCrypto = true
    this.exports = exports
    this.segmenter = null
    this.notes = []

    const missing = REQUIRED_EXPORTS.filter((name) => typeof exports[name] !== 'function')
    if (missing.length) throw new CryptoError('CRYPTO_ABI_MISMATCH', `缺少导出：${missing.join(', ')}`)
    if (!(exports.memory instanceof WebAssembly.Memory)) {
      throw new CryptoError('CRYPTO_ABI_MISMATCH', '缺少 memory 导出')
    }

    const version = exports.ys_version()
    if (version !== ABI_VERSION) {
      throw new CryptoError('CRYPTO_ABI_MISMATCH', `内核版本 0x${version.toString(16)} ≠ 0x${ABI_VERSION.toString(16)}`)
    }
    this.version = version
    this.headerLen = typeof exports.ys_header_len === 'function' ? exports.ys_header_len() : 112
    this.blockSize =
      typeof exports.ys_default_block_size === 'function' ? exports.ys_default_block_size() : 1048576
    this.segmenter = segmenterFor(this.headerLen)
    if (this.headerLen !== 112) {
      this.notes.push(`内核包头 ${this.headerLen} 字节（契约是 112），切分用临时策略 ${this.segmenter.name}`)
    }
    const missingOptional = OPTIONAL_EXPORTS.filter((n) => typeof exports[n] !== 'function')
    if (missingOptional.length) this.notes.push(`缺少可选导出：${missingOptional.join(', ')}`)
  }

  // ---------------------------------------------------------------- 内存

  #mem() {
    return new Uint8Array(this.exports.memory.buffer)
  }

  #u32(ptr) {
    return new DataView(this.exports.memory.buffer).getUint32(ptr, true)
  }

  alloc(len) {
    if (len === 0) return 0
    const ptr = this.exports.ys_alloc(len)
    if (!ptr) throw new CryptoError('CRYPTO_BUFFER_TOO_SMALL', `ys_alloc(${len}) 失败`)
    return ptr
  }

  free(ptr, len) {
    if (ptr) this.exports.ys_free(ptr, len)
  }

  #write(value) {
    const src =
      typeof value === 'string'
        ? new TextEncoder().encode(value)
        : value instanceof Uint8Array
          ? value
          : new Uint8Array(value)
    if (src.length === 0) return { ptr: 0, len: 0, release: () => {} }
    const ptr = this.alloc(src.length)
    this.#mem().set(src, ptr)
    return { ptr, len: src.length, release: () => this.free(ptr, src.length) }
  }

  #read(ptr, len) {
    return this.#mem().slice(ptr, ptr + len)
  }

  #errorName(rc) {
    if (typeof this.exports.ys_error_name !== 'function') return null
    const cap = 64
    const out = this.alloc(cap)
    const outLen = this.alloc(4)
    try {
      const r = this.exports.ys_error_name(rc, out, cap, outLen)
      if (r !== 0) return null
      return new TextDecoder().decode(this.#read(out, this.#u32(outLen)))
    } catch {
      return null
    } finally {
      this.free(out, cap)
      this.free(outLen, 4)
    }
  }

  /** 负数 → CRYPTO_*；名字优先走 `ys_error_name`，取不到再按码表。 */
  #check(rc, what) {
    if (rc === 0) return
    const name = this.#errorName(rc) || ERROR_CODES[rc] || `RC_${rc}`
    const code = ERROR_NAME_TO_CODE[name] || 'CRYPTO_INTERNAL'
    throw new CryptoError(code, `${what} → ${name}(${rc})`)
  }

  /** 通用"输出缓冲区"调用：-2 时按内核回报的所需长度重试一次。 */
  #outCall(what, call, initialCap = 4096) {
    let cap = initialCap
    for (let attempt = 0; attempt < 3; attempt++) {
      const out = this.alloc(cap)
      const outLenPtr = this.alloc(4)
      try {
        const rc = call(out, cap, outLenPtr)
        const need = this.#u32(outLenPtr)
        if (rc === -2 && need > cap) {
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

  // ---------------------------------------------------------------- 公钥（64 ↔ 65）

  /** 内核 64 字节 X‖Y → wire 65 字节未压缩点。 */
  static toWire(publicKey64) {
    if (publicKey64.length === WIRE_PUBKEY_LEN) return publicKey64
    if (publicKey64.length !== KERNEL_PUBKEY_LEN) {
      throw new CryptoError('CRYPTO_BAD_ARGUMENT', `公钥长度 ${publicKey64.length}`)
    }
    const out = new Uint8Array(WIRE_PUBKEY_LEN)
    out[0] = 0x04
    out.set(publicKey64, 1)
    return out
  }

  /** wire 65 字节 → 内核 64 字节；也接受已经是 64 字节的输入（服务端存的就是 wire 形态）。 */
  static toKernel(publicKey) {
    if (publicKey.length === KERNEL_PUBKEY_LEN) return publicKey
    if (publicKey.length !== WIRE_PUBKEY_LEN || publicKey[0] !== 0x04) {
      throw new CryptoError('CRYPTO_BAD_ARGUMENT', `wire 公钥必须是 65 字节且 0x04 开头`)
    }
    return publicKey.subarray(1)
  }

  // ---------------------------------------------------------------- 身份 / 码 / 签名

  generateIdentity() {
    const seed = this.#seed()
    const priv = this.alloc(32)
    const pub = this.alloc(KERNEL_PUBKEY_LEN)
    const s = this.#write(seed)
    try {
      this.#check(this.exports.ys_sm2_keygen(s.ptr, s.len, priv, pub), 'ys_sm2_keygen')
      return {
        privateKey: this.#read(priv, 32),
        publicKey: WasmKernel.toWire(this.#read(pub, KERNEL_PUBKEY_LEN)),
      }
    } finally {
      s.release()
      this.free(priv, 32)
      this.free(pub, KERNEL_PUBKEY_LEN)
    }
  }

  publicKeyFromPrivate(privateKey) {
    const priv = this.#write(privateKey)
    const pub = this.alloc(KERNEL_PUBKEY_LEN)
    try {
      this.#check(this.exports.ys_sm2_pubkey(priv.ptr, pub), 'ys_sm2_pubkey')
      return WasmKernel.toWire(this.#read(pub, KERNEL_PUBKEY_LEN))
    } finally {
      priv.release()
      this.free(pub, KERNEL_PUBKEY_LEN)
    }
  }

  codeOf(publicKey) {
    const key = this.#write(WasmKernel.toKernel(publicKey))
    const out = this.alloc(4)
    try {
      this.#check(this.exports.ys_user_code(key.ptr, out), 'ys_user_code')
      return new TextDecoder().decode(this.#read(out, 4))
    } finally {
      key.release()
      this.free(out, 4)
    }
  }

  normalizeCode(text) {
    const input = this.#write(String(text || ''))
    const out = this.alloc(4)
    try {
      const rc = this.exports.ys_normalize_code(input.ptr, input.len, out)
      if (rc !== 0) return null
      return new TextDecoder().decode(this.#read(out, 4))
    } finally {
      input.release()
      this.free(out, 4)
    }
  }

  sign(privateKey, message) {
    const priv = this.#write(privateKey)
    const msg = this.#write(message)
    const seed = this.#write(this.#seed())
    const sig = this.alloc(64)
    try {
      this.#check(this.exports.ys_sm2_sign(priv.ptr, seed.ptr, seed.len, msg.ptr, msg.len, sig), 'ys_sm2_sign')
      // 内核给 r‖s；wire 上要 DER（契约 §10.4）
      return normalizeSignature(this.#read(sig, 64))
    } finally {
      priv.release()
      msg.release()
      seed.release()
      this.free(sig, 64)
    }
  }

  verify(publicKey, message, signature) {
    const pub = this.#write(WasmKernel.toKernel(publicKey))
    const msg = this.#write(message)
    const raw = decodeSignature(signature) // DER → r‖s
    const sig = this.#write(raw)
    try {
      const rc = this.exports.ys_sm2_verify(pub.ptr, msg.ptr, msg.len, sig.ptr)
      if (rc < 0) this.#check(rc, 'ys_sm2_verify')
      return rc === 1
    } finally {
      pub.release()
      msg.release()
      sig.release()
    }
  }

  sm3(data) {
    const input = this.#write(data)
    const out = this.alloc(32)
    try {
      this.#check(this.exports.ys_sm3(input.ptr, input.len, out), 'ys_sm3')
      return this.#read(out, 32)
    } finally {
      input.release()
      this.free(out, 32)
    }
  }

  // ---------------------------------------------------------------- 包（整包进出）

  /**
   * @param {object} p
   * @param {Uint8Array} p.data 明文
   * @param {string} p.name 文件名（只 basename）
   * @param {string} p.mime
   * @param {Uint8Array} p.recipientPublic 65 字节 wire 公钥
   * @param {Uint8Array} p.senderPrivate 32 字节
   * @param {number} [p.blockSize] 0 = 内核默认
   */
  pack({ data, name, mime, recipientPublic, senderPrivate, blockSize = 0 }) {
    const recipient = this.#write(WasmKernel.toKernel(recipientPublic))
    const sender = this.#write(senderPrivate)
    const nameBytes = this.#write(name || 'file')
    const mimeBytes = this.#write(mime || 'application/octet-stream')
    const seed = this.#write(this.#seed())
    const payload = this.#write(data)
    try {
      return this.#outCall(
        'ys_pack',
        (out, cap, outLen) =>
          this.exports.ys_pack(
            recipient.ptr,
            sender.ptr,
            nameBytes.ptr,
            nameBytes.len,
            mimeBytes.ptr,
            mimeBytes.len,
            blockSize,
            seed.ptr,
            seed.len,
            payload.ptr,
            payload.len,
            out,
            cap,
            outLen,
          ),
        data.length + 64 * 1024 + 4096,
      )
    } finally {
      recipient.release()
      sender.release()
      nameBytes.release()
      mimeBytes.release()
      seed.release()
      payload.release()
    }
  }

  unpackMeta({ pack, recipientPrivate, senderPublic }) {
    const p = this.#write(pack)
    const priv = this.#write(recipientPrivate)
    const pub = this.#write(WasmKernel.toKernel(senderPublic))
    try {
      const json = this.#outCall(
        'ys_unpack_meta',
        (out, cap, outLen) => this.exports.ys_unpack_meta(p.ptr, p.len, priv.ptr, pub.ptr, out, cap, outLen),
        1024,
      )
      try {
        return JSON.parse(new TextDecoder().decode(json))
      } catch {
        throw new CryptoError('CRYPTO_MANIFEST_INVALID', '清单 JSON 解析失败')
      }
    } finally {
      p.release()
      priv.release()
      pub.release()
    }
  }

  unpack({ pack, recipientPrivate, senderPublic }) {
    const p = this.#write(pack)
    const priv = this.#write(recipientPrivate)
    const pub = this.#write(WasmKernel.toKernel(senderPublic))
    try {
      return this.#outCall(
        'ys_unpack',
        (out, cap, outLen) => this.exports.ys_unpack(p.ptr, p.len, priv.ptr, pub.ptr, out, cap, outLen),
        pack.length + 4096,
      )
    } finally {
      p.release()
      priv.release()
      pub.release()
    }
  }

  // ---------------------------------------------------------------- 传输切分（纯算术）

  splitPack(args) {
    return splitPack({ ...args, segmenter: this.segmenter })
  }

  joinPack(args) {
    return joinPack({ ...args, segmenter: this.segmenter })
  }
}
