/**
 * 包的"传输切分"算术（CRYPTO-PACK §4.2 / §12）。
 *
 * 前端**不解析**包内任何字段：切分点只用纯算术——包总长减去块区长度就是 prelude 长度：
 *
 *   ENVELOPE_LEN = PRELUDE_LEN + Σ (recordHeaderLen + PT_LEN(i))
 *   ⇒ PRELUDE_LEN = packLen − n × recordHeaderLen − plaintextSize
 *
 * 每块切片 = 记录里 `recordHeaderLen` 之后的那段（`CHUNK_CT‖TAG`，长度 `PT_LEN+16`），
 * 与契约 §12 的传输映射一致；接收方按块序号重建记录头再拼回整包（§6.3）。
 *
 * 为什么有两条策略：内核当前 `ys_header_len() = 40`（PR #4 返工前的布局），
 * 块记录头 9 字节；契约（`IMAGE 112`）是 16 字节。返工后 `header_len` 变 112，
 * 这里自动只用契约那一套。两条策略都在本文件里，业务代码完全无感。
 */
import { u8, u16be, u32be, bytes } from '../lib/bytes.js'

/** 契约 §6.2：16 字节块头。 */
function contractRecordHeader(index, ptLen, chunkCount) {
  const isLast = index === chunkCount - 1 ? 1 : 0
  return bytes(
    u32be(index), // CHUNK_INDEX
    u32be(ptLen), // PT_LEN
    u32be(ptLen), // CT_LEN（GCM 长度保持）
    u8(isLast), // LAST_FLAG
    u8(0), // RESERVED
    u16be(0), // RESERVED
  )
}

/** 内核当前布局（header 40）：index u32be | last u8 | ct_len u32be。 */
function legacyRecordHeader(index, ptLen, chunkCount) {
  return bytes(u32be(index), u8(index === chunkCount - 1 ? 1 : 0), u32be(ptLen))
}

const STRATEGIES = {
  112: { name: 'contract', recordHeaderLen: 16, buildRecordHeader: contractRecordHeader },
  40: { name: 'legacy-40', recordHeaderLen: 9, buildRecordHeader: legacyRecordHeader },
}

export function segmenterFor(headerLen) {
  const strategy = STRATEGIES[headerLen]
  if (!strategy) {
    throw new Error(`未知的内核包头长度 ${headerLen}：切分算术没有对应策略（需要内核与契约对齐）`)
  }
  return strategy
}

export function chunkCountOf(plaintextSize, chunkSize) {
  if (!Number.isFinite(plaintextSize) || plaintextSize < 0) throw new Error('bad plaintextSize')
  return Math.max(1, Math.ceil(plaintextSize / chunkSize))
}

export function plainTextLen(index, plaintextSize, chunkSize, chunkCount) {
  return index === chunkCount - 1 ? plaintextSize - chunkSize * (chunkCount - 1) : chunkSize
}

/**
 * 整包 → prelude + 块切片。
 * @returns {{prelude: Uint8Array, slices: Uint8Array[], preludeLen: number, chunkCount: number, strategy: string}}
 */
export function splitPack({ pack, plaintextSize, chunkSize, segmenter }) {
  const chunkCount = chunkCountOf(plaintextSize, chunkSize)
  const overhead = segmenter.recordHeaderLen + 16
  const preludeLen = pack.length - overhead * chunkCount - plaintextSize
  if (!Number.isInteger(preludeLen) || preludeLen <= 0) {
    throw new Error(
      `切分算术不自洽：pack=${pack.length} 块数=${chunkCount} 明文=${plaintextSize} 记录头=${segmenter.recordHeaderLen}`,
    )
  }
  const slices = []
  let offset = preludeLen
  for (let i = 0; i < chunkCount; i++) {
    const ptLen = plainTextLen(i, plaintextSize, chunkSize, chunkCount)
    const start = offset + segmenter.recordHeaderLen
    slices.push(pack.subarray(start, start + ptLen + 16))
    offset += segmenter.recordHeaderLen + 16 + ptLen
  }
  if (offset !== pack.length) {
    throw new Error(`切分后长度不符：${offset} ≠ ${pack.length}`)
  }
  return {
    prelude: pack.subarray(0, preludeLen),
    slices,
    preludeLen,
    chunkCount,
    strategy: segmenter.name,
  }
}

/**
 * prelude + 块切片 → 整包（接收方，按 §6.3 重建 16 字节块头）。
 * @returns {Uint8Array}
 */
export function joinPack({ prelude, slices, plaintextSize, chunkSize, segmenter }) {
  const chunkCount = chunkCountOf(plaintextSize, chunkSize)
  if (slices.length !== chunkCount) {
    throw new Error(`块数不符：收到 ${slices.length}，应为 ${chunkCount}`)
  }
  const parts = [prelude]
  for (let i = 0; i < chunkCount; i++) {
    const ptLen = plainTextLen(i, plaintextSize, chunkSize, chunkCount)
    if (slices[i].length !== ptLen + 16) {
      throw new Error(`第 ${i} 块长度不符：${slices[i].length} ≠ ${ptLen + 16}`)
    }
    parts.push(segmenter.buildRecordHeader(i, ptLen, chunkCount))
    parts.push(slices[i])
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
