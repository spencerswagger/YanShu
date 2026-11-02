/**
 * JS 侧会话包装（`crypto/session.js`）的单元测试。
 *
 * 内核只有整包 `ys_pack/ys_unpack`，"prelude + 逐块切片 + 导出/恢复"这一层在 JS 里：
 * 这里验证它的边界行为（乱序喂入、重复、长度不符、缺块、导出后恢复一致）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import { DevStubKernel } from '../src/crypto/stub.js'
import { instantiateKernel } from '../src/crypto/wasm.js'

const here = dirname(fileURLToPath(import.meta.url))
const wasmPath = [process.env.YS_WASM, resolve(here, '../public/ys_kernel.wasm')].filter(Boolean).find((p) => existsSync(p))
const skipReal = wasmPath ? false : '没找到内核产物'

function plaintext(size = 500) {
  return new Uint8Array(size).map((_, i) => (i * 29 + 3) & 0xff)
}

async function roundTrip(kernel, size = 500) {
  const alice = kernel.generateIdentity()
  const bob = kernel.generateIdentity()
  const data = plaintext(size)
  const pack = kernel.pack({
    data,
    name: 'session.bin',
    mime: 'application/octet-stream',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
    blockSize: 64,
  })
  const session = kernel.openPackSession({ pack, plaintextSize: data.length, chunkSize: 64 })
  assert.equal(session.chunkCount, Math.ceil(size / 64))
  assert.ok(session.prelude.length > 0)
  assert.equal(session.slices.length, session.chunkCount)

  // 导出/恢复：prelude 与所有切片必须逐字节相同（续传靠这个）
  const restored = kernel.resumePackSession(session.export())
  assert.deepEqual([...restored.prelude], [...session.prelude])
  assert.deepEqual(restored.slices.map((s) => [...s]), session.slices.map((s) => [...s]))

  const unpack = kernel.openUnpackSession({
    prelude: session.prelude,
    recipientPrivate: bob.privateKey,
    senderPublic: alice.publicKey,
    plaintextSize: data.length,
    chunkSize: 64,
  })
  if (unpack.meta) assert.equal(unpack.meta.name, 'session.bin')
  // 乱序喂
  for (const i of [...Array(unpack.chunkCount).keys()].reverse()) unpack.feed(i, restored.slices[i])
  const { plain, meta } = unpack.finish()
  assert.equal(meta.name, 'session.bin')
  assert.equal(meta.size, data.length)
  assert.deepEqual([...plain], [...data], '会话收到的明文必须与源文件一致')
  unpack.close()
  session.close()
  return { kernel, data, session, unpack }
}

test('会话包装（开发桩）：导出/恢复、乱序喂入、关闭', async () => {
  const kernel = new DevStubKernel()
  const { session } = await roundTrip(kernel)
  assert.equal(session.closed, true)
})

test('会话包装（开发桩）：重复块 / 长度不符 / 缺块都要明确报错', async () => {
  const kernel = new DevStubKernel()
  const alice = kernel.generateIdentity()
  const bob = kernel.generateIdentity()
  const data = plaintext(200)
  const pack = kernel.pack({
    data,
    name: 'x.bin',
    mime: 'application/octet-stream',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
    blockSize: 64,
  })
  const session = kernel.openPackSession({ pack, plaintextSize: data.length, chunkSize: 64 })
  const open = () =>
    kernel.openUnpackSession({
      prelude: session.prelude,
      recipientPrivate: bob.privateKey,
      senderPublic: alice.publicKey,
      plaintextSize: data.length,
      chunkSize: 64,
    })

  const a = open()
  a.feed(0, session.slices[0])
  assert.throws(() => a.feed(0, session.slices[0]), (err) => err.code === 'CRYPTO_CHUNK_ORDER')
  assert.throws(() => a.feed(999, session.slices[0]), (err) => err.code === 'CRYPTO_CHUNK_ORDER')
  assert.throws(() => a.feed(1, new Uint8Array(3)), (err) => err.code === 'CRYPTO_LENGTH_INCONSISTENT')
  assert.throws(() => a.finish(), (err) => err.code === 'CRYPTO_CHUNK_MISSING')
  a.close()

  const b = open()
  b.close()
  assert.throws(() => b.feed(0, session.slices[0]), (err) => err.code === 'CRYPTO_BAD_ARGUMENT')
})

test('会话包装（真内核）：同一套导出/恢复与乱序解密', { skip: skipReal }, async () => {
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  await roundTrip(kernel, 500)
})
