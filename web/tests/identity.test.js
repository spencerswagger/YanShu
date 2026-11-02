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
  assert.equal(manager.session.publicKey.length, 65, 'wire 公钥是 65 字节未压缩点')
  assert.equal(manager.session.privateKey.length, 32)
  const stored = await backend.get('self')
  assert.ok(stored.privateKey, '本地存了私钥（只在本机）')
  assert.equal(stored.registered, false)
})

test('持久化字段白名单：只有私钥/公钥/码/昵称/注册态/时间', async () => {
  const { manager, backend } = setup()
  await manager.loadOrCreate()
  const stored = await backend.get('self')
  assert.deepEqual(Object.keys(stored).sort(), [
    'code',
    'createdAt',
    'nickname',
    'privateKey',
    'publicKey',
    'registered',
  ])
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

test('空文件名：落盘显示“未命名”并保留扩展名（契约空名裁决）', async () => {
  const { safeFileName } = await import('../src/net/download.js')
  assert.equal(safeFileName('', 'txt'), '未命名.txt')
  assert.equal(safeFileName('', ''), '未命名')
  assert.equal(safeFileName('../evil.txt', 'txt'), 'evil.txt')
  assert.equal(safeFileName('正常.txt'), '正常.txt')
})
