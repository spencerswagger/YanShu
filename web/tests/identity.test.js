import test from 'node:test'
import assert from 'node:assert/strict'
import { createIdentityManager } from '../src/store/identity.js'
import { memoryBackend } from '../src/store/db.js'
import { DevStubKernel } from '../src/crypto/stub.js'

function setup() {
  const kernel = new DevStubKernel()
  const backend = memoryBackend()
  const manager = createIdentityManager({ kernel, backend })
  return { kernel, backend, manager }
}

test('首次进入生成密钥对并派生 4 位码；私钥只落本机 backend', async () => {
  const { manager, backend } = setup()
  await manager.loadOrCreate()
  assert.match(manager.session.code, /^[0-9A-HJKMNP-TV-Z]{4}$/)
  assert.equal(manager.session.publicKey.length, 65)
  const stored = await backend.get('self')
  assert.ok(stored.identity, '本地存了身份 blob（私钥只在本机）')
  assert.equal(stored.registered, false)
})

test('私钥不进 session.publicKey，也不出现在持久化记录的明文字段里', async () => {
  const { manager, backend } = setup()
  await manager.loadOrCreate()
  const stored = await backend.get('self')
  const keys = Object.keys(stored)
  assert.deepEqual(keys.sort(), ['check', 'code', 'createdAt', 'identity', 'nickname', 'publicKey', 'registered'])
  assert.equal(stored.publicKey.length, 87) // 65 字节 base64url 无填充
})

test('撞码：自动换密钥对重试一次后成功', async () => {
  const { manager } = setup()
  await manager.loadOrCreate()
  const firstCode = manager.session.code
  let calls = 0
  const api = {
    async register() {
      calls += 1
      if (calls === 1) {
        const err = new Error('code taken')
        err.code = 'CODE_TAKEN'
        throw err
      }
      return { code: manager.session.code, nickname: '雁' + manager.session.code }
    },
  }
  const result = await manager.register({ api, autoRetries: 1 })
  assert.equal(result.collisions, 1)
  assert.equal(calls, 2)
  assert.equal(manager.session.registered, true)
  assert.notEqual(manager.session.code, firstCode, '撞码必须换密钥对（码会变）')
})

test('撞码：自动重试一次后仍冲突就停下来等用户', async () => {
  const { manager } = setup()
  await manager.loadOrCreate()
  const api = {
    async register() {
      const err = new Error('code taken')
      err.code = 'CODE_TAKEN'
      throw err
    },
  }
  await assert.rejects(manager.register({ api, autoRetries: 1 }), (err) => err.code === 'CODE_TAKEN')
})

test('PUBKEY_TAKEN：清本地身份重来一次', async () => {
  const { manager } = setup()
  await manager.loadOrCreate()
  let calls = 0
  const api = {
    async register() {
      calls += 1
      if (calls === 1) {
        const err = new Error('pubkey taken')
        err.code = 'PUBKEY_TAKEN'
        throw err
      }
      return { code: manager.session.code, nickname: 'x' }
    },
  }
  const result = await manager.register({ api, autoRetries: 1 })
  assert.equal(result.ok, true)
  assert.equal(calls, 2)
})
