import test from 'node:test'
import assert from 'node:assert/strict'
import { DevStubKernel, UnavailableKernel } from '../src/crypto/stub.js'
import { createKernel, resetKernel } from '../src/crypto/index.js'
import { CryptoError } from '../src/crypto/errors.js'

test('未就绪替身：一律报 CRYPTO_NOT_READY，绝不假装加密成功', () => {
  const k = new UnavailableKernel('wasm 未提供')
  assert.equal(k.isRealCrypto, false)
  for (const fn of ['generateIdentity', 'sign', 'pack', 'unpack', 'splitPack']) {
    assert.throws(
      () => k[fn]({}),
      (err) => err instanceof CryptoError && err.code === 'CRYPTO_NOT_READY',
      `${fn} 必须报未就绪`,
    )
  }
})

test('开发桩：pack 产物以 YSSTUB01 开头（不是 YSPK），并带"未加密"标记', () => {
  const k = new DevStubKernel()
  const alice = k.generateIdentity()
  const bob = k.generateIdentity()
  assert.match(k.codeOf(alice.publicKey), /^[0-9A-HJKMNP-TV-Z]{4}$/)

  const pack = k.pack({
    data: new Uint8Array([1, 2, 3, 4, 5]),
    name: 'hi.bin',
    mime: 'application/octet-stream',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
  })
  const text = new TextDecoder().decode(pack)
  assert.match(text, /^YSSTUB01/)
  assert.match(text, /STUB-NOT-ENCRYPTED/)
  assert.equal(text.startsWith('YSPK'), false)
})

test('开发桩：篡改块切片必须报 CRYPTO_CHUNK_AUTH_FAILED', () => {
  const k = new DevStubKernel()
  const alice = k.generateIdentity()
  const bob = k.generateIdentity()
  const data = new Uint8Array(300).fill(7)
  const pack = k.pack({ data, name: 'a.bin', mime: 'application/octet-stream', recipientPublic: bob.publicKey, senderPrivate: alice.privateKey })
  const { prelude, slices } = k.splitPack({ pack, plaintextSize: data.length, chunkSize: k.blockSize })
  slices[0][0] ^= 0xff
  const tampered = k.joinPack({ prelude, slices, plaintextSize: data.length, chunkSize: k.blockSize })
  assert.throws(
    () => k.unpack({ pack: tampered, recipientPrivate: bob.privateKey, senderPublic: alice.publicKey }),
    (err) => err.code === 'CRYPTO_CHUNK_AUTH_FAILED',
  )
})

test('开发桩拒绝解真包（YSPK 开头 → CRYPTO_MAGIC_MISMATCH）', () => {
  const k = new DevStubKernel()
  const bob = k.generateIdentity()
  assert.throws(
    () =>
      k.unpack({
        pack: new TextEncoder().encode('YSPK\x01\x00\x28rest-of-pack'),
        recipientPrivate: bob.privateKey,
        senderPublic: bob.publicKey,
      }),
    (err) => err.code === 'CRYPTO_MAGIC_MISMATCH',
  )
})

test('码归一化走内核口径（O→0、I/L→1、去 -）', () => {
  const k = new DevStubKernel()
  assert.equal(k.normalizeCode('k7-qf'), 'K7QF')
  assert.equal(k.normalizeCode('0il1'), '0111')
  assert.equal(k.normalizeCode('k7q'), null)
  assert.equal(k.normalizeCode('K7QU'), null)
})

test('生产构建拒绝开发桩', async () => {
  resetKernel()
  await assert.rejects(
    createKernel({ mode: 'stub-fake', isProd: true }),
    (err) => err.code === 'CRYPTO_ABI_MISMATCH',
  )
  resetKernel()
})
