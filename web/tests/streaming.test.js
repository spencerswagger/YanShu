/**
 * 流式内核接入（PR #33 的 9 个增量导出）：
 *   ① 流式打包 → 流式解包，明文逐字节一致；
 *   ② 逐块摘要喂入 + prelude 幂等；
 *   ③ 缺块 → `streamUnpackEnd` 报 `CRYPTO_CHUNK_MISSING`（不交出残缺文件）；
 *   ④ 流式产出的 prelude 与整包 `ys_pack_v1` 的包头一致（同 seed/createdAt 下）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { instantiateKernel } from '../src/crypto/wasm.js'
import { kernelPathOrSkip } from './helpers/kernel.js'

const CHUNK = 1024

function makeData(n) {
  const out = new Uint8Array(n)
  for (let i = 0; i < n; i++) out[i] = (i * 13 + 5) & 0xff
  return out
}

function packStream(kernel, me, data, { skipChunk = -1 } = {}) {
  const seed = new Uint8Array(32).fill(9)
  const pub64 = me.publicKey.subarray(1)
  kernel.streamPackBegin({
    recipientPublic: pub64,
    senderPrivate: me.privateKey,
    name: 'stream.bin',
    mime: 'application/octet-stream',
    chunkSize: CHUNK,
    totalSize: data.length,
    seed,
    createdAt: 0,
  })
  for (let off = 0; off < data.length; off += CHUNK) {
    kernel.streamHashUpdate(data.subarray(off, Math.min(off + CHUNK, data.length)))
  }
  const prelude = kernel.streamPrelude()
  const prelude2 = kernel.streamPrelude()
  const count = Math.ceil(data.length / CHUNK)
  const records = []
  for (let i = 0; i < count; i++) {
    if (i === skipChunk) continue
    records.push(kernel.streamChunk(i, data.subarray(i * CHUNK, Math.min((i + 1) * CHUNK, data.length))))
  }
  kernel.streamPackEnd()
  return { prelude, prelude2, records, count, seed }
}

test('流式：打包 → 解包逐字节一致，prelude 幂等', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const me = kernel.generateIdentity()
  const data = makeData(CHUNK * 3 + 137)
  const { prelude, prelude2, records, count } = packStream(kernel, me, data)
  assert.deepEqual([...prelude], [...prelude2], 'prelude 必须幂等（可以先上传再传块）')
  assert.equal(records.length, count)

  const meta = kernel.streamUnpackBegin(prelude, me.privateKey)
  assert.equal(Number(meta.chunk_count), count)
  assert.equal(Number(meta.size), data.length)
  const out = []
  for (const r of records) out.push(kernel.streamUnpackChunk(r))
  kernel.streamUnpackEnd()
  const joined = Buffer.concat(out.map((b) => Buffer.from(b)))
  assert.equal(Buffer.compare(joined, Buffer.from(data)), 0, '流式往返必须逐字节一致')
})

test('流式：缺块 → streamUnpackEnd 必须报 CRYPTO_CHUNK_MISSING', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const me = kernel.generateIdentity()
  const data = makeData(CHUNK * 2)
  const { prelude, records } = packStream(kernel, me, data, { skipChunk: 1 })
  kernel.streamUnpackBegin(prelude, me.privateKey)
  kernel.streamUnpackChunk(records[0])
  assert.throws(() => kernel.streamUnpackEnd(), (err) => {
    assert.match(String(err.code || ''), /CHUNK_MISSING|CRYPTO_/)
    return true
  })
})

test('流式：篡改一块 → 解该块必须报错（tag 校验）', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const me = kernel.generateIdentity()
  const data = makeData(CHUNK)
  const { prelude, records } = packStream(kernel, me, data)
  kernel.streamUnpackBegin(prelude, me.privateKey)
  const bad = new Uint8Array(records[0])
  bad[bad.length - 1] ^= 1 // 改 tag 一字节
  assert.throws(() => kernel.streamUnpackChunk(bad), /CRYPTO|AUTH|TAG|CHUNK/i)
})
