import test from 'node:test'
import assert from 'node:assert/strict'
import { DevStubKernel, UnavailableKernel } from '../src/crypto/stub.js'
import { createKernel, resetKernel } from '../src/crypto/index.js'
import { CryptoError } from '../src/crypto/errors.js'

test('未就绪替身：一律抛 CRYPTO_NOT_READY，绝不假装加密成功', () => {
  const k = new UnavailableKernel('wasm 未提供')
  assert.equal(k.isRealCrypto, false)
  for (const fn of ['generateIdentity', 'sign', 'packOpen', 'unpackOpen', 'sm3']) {
    assert.throws(
      () => k[fn](),
      (err) => err instanceof CryptoError && err.code === 'CRYPTO_NOT_READY',
      `${fn} 必须报未就绪`,
    )
  }
})

test('开发桩：产物以 YSSTUB01 开头（不是 YSPK），且自带"未加密"标记', () => {
  const k = new DevStubKernel()
  assert.equal(k.isRealCrypto, false)
  const alice = k.generateIdentity()
  assert.match(k.identityCode(alice).code, /^[0-9A-HJKMNP-TV-Z]{4}$/)

  const bob = k.generateIdentity()
  const bobPub = k.identityPublic(bob)
  const handle = k.packOpen({
    identity: alice,
    recipientPublic: bobPub,
    name: 'hi.bin',
    mime: 'application/octet-stream',
    plaintextSize: 5,
    chunkSize: 32,
    createdAt: 1767225600000,
  })
  const plain = new Uint8Array([1, 2, 3, 4, 5])
  k.packDigest(handle, 0, plain)
  const prelude = k.packSeal(handle)
  const head = new TextDecoder().decode(prelude.slice(0, 8))
  assert.equal(head, 'YSSTUB01', '桩产物必须一眼可辨，不能伪装成 YSPK 包')
  assert.match(new TextDecoder().decode(prelude), /STUB-NOT-ENCRYPTED/)
  k.packClose(handle)
})

test('开发桩：篡改块必须报 CRYPTO_CHUNK_AUTH_FAILED', () => {
  const k = new DevStubKernel()
  const alice = k.generateIdentity()
  const bob = k.generateIdentity()
  const handle = k.packOpen({
    identity: alice,
    recipientPublic: k.identityPublic(bob),
    name: 'hi.bin',
    mime: 'application/octet-stream',
    plaintextSize: 4,
    chunkSize: 32,
    createdAt: Date.now(),
  })
  const plain = new Uint8Array([9, 9, 9, 9])
  k.packDigest(handle, 0, plain)
  const prelude = k.packSeal(handle)
  const slice = k.packChunk(handle, 0, plain)
  slice[0] ^= 0xff
  const opened = k.unpackOpen({ prelude, identity: bob })
  assert.throws(
    () => k.unpackChunk(opened.handle, 0, slice),
    (err) => err.code === 'CRYPTO_CHUNK_AUTH_FAILED',
  )
})

test('开发桩拒绝解真包（YSPK 开头 → CRYPTO_MAGIC_MISMATCH）', () => {
  const k = new DevStubKernel()
  const bob = k.generateIdentity()
  const fakeRealPack = new TextEncoder().encode('YSPK\x01\x00\x00\x70rest')
  assert.throws(
    () => k.unpackOpen({ prelude: fakeRealPack, identity: bob }),
    (err) => err.code === 'CRYPTO_MAGIC_MISMATCH',
  )
})

test('生产构建拒绝开发桩', async () => {
  resetKernel()
  await assert.rejects(
    createKernel({ mode: 'stub-fake', isProd: true }),
    (err) => err.code === 'CRYPTO_ABI_MISMATCH',
  )
  resetKernel()
})
