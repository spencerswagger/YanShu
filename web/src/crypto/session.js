/**
 * JS 侧"会话式"包装（不要求内核加接口）。
 *
 * 背景：内核只给 `ys_pack`（整份明文 → 整包）与 `ys_unpack`（整包 → 明文），没有 open/write/close 这类流式导出。
 * 传输却要 `prelude` + 逐块切片（CRYPTO-PACK §4.3 / §12），所以"会话"这一层放在前端：
 *
 *   PackSession    : 拿着内核产出的整包，按 §4.2 算术给出 prelude 与第 i 块切片，并能导出/恢复状态（续传）
 *   UnpackSession  : 收齐 prelude + 逐块喂入，最后交给内核 `ys_unpack` 一次性验签解密
 *
 * 为什么不"按块调 ys_pack"：一个文件是**一个**签名包（一个 DK、一份清单、一个签名），
 * 按块各打一包会变成"多包拼接"，那是另一种格式，契约里没有。会话层只切传输、不切密码学。
 *
 * 内核返工（`ys_unpack` 不再收发送方公钥）时，只需改 `WasmKernel.unpack/unpackMeta` 的入参拼装。
 */
import { CryptoError } from './errors.js'

/** 发送会话：内核整包 → prelude + 块切片（可导出、可恢复）。 */
export class PackSession {
  constructor({ kernel, pack, plaintextSize, chunkSize }) {
    this.kernel = kernel
    this.plaintextSize = plaintextSize
    this.chunkSize = chunkSize
    const split = kernel.splitPack({ pack, plaintextSize, chunkSize })
    this.pack = pack
    this.prelude = split.prelude
    this.slices = split.slices
    this.preludeLen = split.preludeLen
    this.chunkCount = split.chunkCount
    this.strategy = split.strategy
    this.closed = false
  }

  /** 会话快照（续传用）。整包是密文，留在本机没问题；大小上限由调用方把关。 */
  export() {
    return {
      v: 1,
      plaintextSize: this.plaintextSize,
      chunkSize: this.chunkSize,
      pack: this.pack,
    }
  }

  close() {
    this.closed = true
    this.pack = null
    this.slices = null
    this.prelude = null
  }
}

/** 接收会话：先喂 prelude 之外的所有块，再一次性 `ys_unpack`。 */
export class UnpackSession {
  constructor({ kernel, recipientPrivate, senderPublic, plaintextSize, chunkSize, prelude }) {
    this.kernel = kernel
    this.recipientPrivate = recipientPrivate
    this.senderPublic = senderPublic
    this.plaintextSize = plaintextSize
    this.chunkSize = chunkSize
    this.prelude = prelude
    this.chunkCount = Math.max(1, Math.ceil(plaintextSize / chunkSize))
    this.slices = new Array(this.chunkCount)
    this.received = 0
    this.closed = false
    this.meta = kernel.unpackMeta({ pack: prelude, recipientPrivate, senderPublic })
  }

  /** 喂入第 index 块切片（`CHUNK_CT‖TAG`）；长度先做一次本地校验，省得攒到最后才炸。 */
  feed(index, bytes) {
    if (this.closed) throw new CryptoError('CRYPTO_BAD_ARGUMENT', '会话已关闭')
    if (index < 0 || index >= this.chunkCount) {
      throw new CryptoError('CRYPTO_CHUNK_ORDER', `块号越界：${index}`)
    }
    if (this.slices[index]) throw new CryptoError('CRYPTO_CHUNK_ORDER', `块号重复：${index}`)
    const ptLen =
      index === this.chunkCount - 1
        ? this.plaintextSize - this.chunkSize * (this.chunkCount - 1)
        : this.chunkSize
    if (bytes.length !== ptLen + 16) {
      throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', `第 ${index} 块长度 ${bytes.length} ≠ ${ptLen + 16}`)
    }
    this.slices[index] = bytes
    this.received += 1
  }

  /** 全部到齐 → 拼回整包 → 内核验签解密。 */
  finish() {
    if (this.received !== this.chunkCount) {
      throw new CryptoError('CRYPTO_CHUNK_MISSING', `已收 ${this.received}/${this.chunkCount}`)
    }
    const pack = this.kernel.joinPack({
      prelude: this.prelude,
      slices: this.slices,
      plaintextSize: this.plaintextSize,
      chunkSize: this.chunkSize,
    })
    const plain = this.kernel.unpack({ pack, recipientPrivate: this.recipientPrivate, senderPublic: this.senderPublic })
    if (plain.length !== Number(this.meta.size)) {
      throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '解密结果与清单大小不一致')
    }
    return { plain, meta: this.meta }
  }

  close() {
    this.closed = true
    this.prelude = null
    this.slices = null
  }
}
