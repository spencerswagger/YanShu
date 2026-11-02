/**
 * 上传进度位图（API.md §6.5）。
 *
 * `bitmap` 是 base64url 无填充的字节串，**第 i 块的 bit 在第 i/8 字节的 bit (7 - i%8)**（MSB 优先）。
 * 用它算"还缺哪些块"，是刷新后续传的依据（配合 `missing` 区间字段）。
 */
import { decode } from './base64url.js'

export function decodeBitmap(text, chunkCount) {
  const bytes = text ? decode(text) : new Uint8Array(0)
  const got = new Array(chunkCount).fill(false)
  for (let i = 0; i < chunkCount; i++) {
    const byte = bytes[(i / 8) | 0]
    if (byte === undefined) break
    got[i] = ((byte >> (7 - (i % 8))) & 1) === 1
  }
  return got
}

/** 连续缺失区间，按 start 升序（与服务端 `missing` 字段同形）。 */
export function missingRanges(got) {
  const out = []
  let i = 0
  while (i < got.length) {
    if (got[i]) {
      i += 1
      continue
    }
    const start = i
    while (i < got.length && !got[i]) i += 1
    out.push({ start, count: i - start })
  }
  return out
}

export function missingIndexes(got) {
  const out = []
  for (let i = 0; i < got.length; i++) if (!got[i]) out.push(i)
  return out
}
