/**
 * 双端闭环集成测试（A 端 → 中转 → B 端 → 落盘）。
 *
 * 用真 HTTP + 真编排代码（net/upload.js / net/download.js / store/identity.js），
 * 端侧内核换开发桩（可逆异或），所以这份测试证明的是：
 *   传输编排、签名挑战、prelude/块切分、续传、状态机、错误映射、落盘链路；
 * 它**不**证明密码学正确——那由 `wasm-real.test.js` 用真内核跑，验收里不要拿这份当加密证据。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { createRelay } from '../relay/dev-relay.mjs'
import { createClient, ApiError } from '../src/net/client.js'
import { createApi } from '../src/net/api.js'
import { createIdentityManager } from '../src/store/identity.js'
import { memoryBackend } from '../src/store/db.js'
import { DevStubKernel } from '../src/crypto/stub.js'
import { sendFile, resumeSend } from '../src/net/upload.js'
import { receiveTransfer } from '../src/net/download.js'
import { decode as b64uDecode, encode as b64uEncode } from '../src/lib/base64url.js'

let relay
let client

async function boot() {
  relay = createRelay({ verifyDigests: false }) // 桩的 SM3 是假的
  await new Promise((resolve) => relay.server.listen(0, '127.0.0.1', resolve))
  const port = relay.server.address().port
  client = createClient({ baseUrl: `http://127.0.0.1:${port}/v1` })
}

async function makePeer(customClient = client, blockSize = 32) {
  const kernel = new DevStubKernel()
  kernel.blockSize = blockSize // 测试里把块调小，几十字节的文件也能覆盖多块路径
  const identity = createIdentityManager({ kernel, backend: memoryBackend() })
  await identity.loadOrCreate()
  const api = createApi({ client: customClient, kernel, session: identity.session })
  await identity.register({ api, nickname: `雁${identity.session.code}` })
  const senderPublic = async (code) => {
    const json = await api.getCode(code)
    return b64uDecode(json.public_key)
  }
  return { kernel, identity, api, session: identity.session, senderPublic }
}

async function send(from, to, file) {
  return sendFile({
    api: from.api,
    kernel: from.kernel,
    session: from.session,
    file,
    recipient: {
      code: to.session.code,
      nickname: to.session.nickname,
      publicKey: to.session.publicKey,
    },
    pendingStore: memoryBackend(),
  })
}

function makeFile(size, name = 'sample.bin') {
  const data = new Uint8Array(size)
  for (let i = 0; i < size; i++) data[i] = (i * 31 + 7) & 0xff
  return { file: new File([data], name, { type: 'application/octet-stream' }), data }
}

test.before(boot)
test.after(() => relay.server.close())

test('A 加密上传 → B 用码取回 → 解密落盘，字节一致；ack 后中转密文被删', async () => {
  const alice = await makePeer()
  const bob = await makePeer()
  const { file, data } = makeFile(300)

  const sent = await send(alice, bob, file)
  assert.equal(sent.state, 'READY')
  assert.equal(sent.chunkCount, 10)
  assert.ok(sent.preludeLen > 0)

  const inbox = await bob.api.inbox({ state: 'ready' })
  assert.equal(inbox.items.length, 1)
  assert.equal(inbox.items[0].sender_code, alice.session.code)
  assert.equal(inbox.items[0].plaintext_size, 300)

  let saved = null
  const received = await receiveTransfer({
    api: bob.api,
    kernel: bob.kernel,
    session: bob.session,
    transferId: sent.transferId,
    senderPublic: bob.senderPublic,
    save: (blob, name) => {
      saved = { blob, name }
    },
  })
  assert.equal(saved.name, 'sample.bin')
  assert.equal(received.size, 300)
  assert.deepEqual([...new Uint8Array(await saved.blob.arrayBuffer())], [...data])

  const after = relay.state.transfers.get(sent.transferId)
  assert.equal(after.state, 'CONSUMED')
  assert.equal(after.chunks.size, 0, '密文块必须被删')
  assert.equal(after.prelude, null, 'prelude 必须被删')
})

test('撤回后另一端取件被 410 拒绝，错误码是 TRANSFER_REVOKED', async () => {
  const alice = await makePeer()
  const bob = await makePeer()
  const { file } = makeFile(64)

  const sent = await send(alice, bob, file)
  await alice.api.revoke({ transferId: sent.transferId })

  await assert.rejects(
    receiveTransfer({
      api: bob.api,
      kernel: bob.kernel,
      session: bob.session,
      transferId: sent.transferId,
      senderPublic: bob.senderPublic,
      save: () => {},
    }),
    (err) => err.code === 'TRANSFER_REVOKED',
  )
})

test('上传中断后用 GET /status 续传，只补缺失块', async () => {
  const alice = await makePeer()
  const bob = await makePeer()
  const { file, data } = makeFile(320) // 10 块
  const pending = memoryBackend()

  const realPut = alice.api.putChunk
  let puts = 0
  alice.api.putChunk = async (args) => {
    puts += 1
    if (puts > 4) throw new ApiError({ code: 'NETWORK_ERROR', status: 0, message: '模拟断网' })
    return realPut(args)
  }

  await assert.rejects(
    sendFile({
      api: alice.api,
      kernel: alice.kernel,
      session: alice.session,
      file,
      recipient: { code: bob.session.code, nickname: bob.session.nickname, publicKey: bob.session.publicKey },
      pendingStore: pending,
    }),
  )

  const records = await pending.all()
  assert.equal(records.length, 1)
  const record = records[0]
  assert.equal(record.state, 'UPLOADING')
  assert.ok(record.pack instanceof Uint8Array, '续传要靠本机留着的密文包')

  const before = await alice.api.uploadStatus({ transferId: record.transferId, uploadToken: record.uploadToken })
  assert.ok(before.received_chunks >= 1 && before.received_chunks < record.chunkCount)

  alice.api.putChunk = realPut
  const resumed = await resumeSend({
    api: alice.api,
    kernel: alice.kernel,
    session: alice.session,
    record,
    pendingStore: pending,
  })
  assert.equal(resumed.state, 'READY')

  const afterStatus = await alice.api.uploadStatus({ transferId: record.transferId, uploadToken: record.uploadToken })
  assert.equal(afterStatus.received_chunks, record.chunkCount)

  let saved = null
  await receiveTransfer({
    api: bob.api,
    kernel: bob.kernel,
    session: bob.session,
    transferId: record.transferId,
    senderPublic: bob.senderPublic,
    save: (blob, name) => {
      saved = { blob, name }
    },
  })
  assert.deepEqual([...new Uint8Array(await saved.blob.arrayBuffer())], [...data])
})

test('块 PUT 触发 429 时带 Retry-After（客户端不得在窗口内重试）', async () => {
  const limited = createRelay({ limits: { chunkPutPerMin: 2 }, verifyDigests: false })
  await new Promise((resolve) => limited.server.listen(0, '127.0.0.1', resolve))
  const port = limited.server.address().port
  const limitedClient = createClient({ baseUrl: `http://127.0.0.1:${port}/v1` })

  const alice = await makePeer(limitedClient)
  const bob = await makePeer(limitedClient)
  const { file } = makeFile(64)

  const api = createApi({ client: limitedClient, kernel: alice.kernel, session: alice.session })
  const sent = await sendFile({
    api,
    kernel: alice.kernel,
    session: alice.session,
    file,
    recipient: { code: bob.session.code, nickname: bob.session.nickname, publicKey: bob.session.publicKey },
    pendingStore: memoryBackend(),
  })

  let rateLimited = null
  for (let i = 0; i < 3; i++) {
    try {
      await api.putChunk({
        transferId: sent.transferId,
        uploadToken: sent.uploadToken,
        index: 0,
        bytes: new Uint8Array(48),
      })
    } catch (err) {
      rateLimited = err
      break
    }
  }
  assert.ok(rateLimited instanceof ApiError)
  assert.equal(rateLimited.code, 'RATE_LIMITED')
  assert.equal(rateLimited.status, 429)
  assert.ok(rateLimited.retryAfter > 0, '429 必须带 Retry-After')
  limited.server.close()
})

test('错码/未注册的码：404 CODE_NOT_FOUND', async () => {
  const alice = await makePeer()
  await assert.rejects(alice.api.getCode('ZZZZ'), (err) => err.code === 'CODE_NOT_FOUND')
})

test('同一块重复上传是幂等的（204），改了内容则 409 CHUNK_CONFLICT', async () => {
  const alice = await makePeer()
  const bob = await makePeer()
  const prelude = new Uint8Array(64).fill(0x5a)
  const created = await alice.api.createTransfer({
    recipient_code: bob.session.code,
    plaintext_size: 64,
    chunk_size: 32,
    chunk_count: 2,
    prelude_len: prelude.length,
    prelude_sm3: b64uEncode(alice.kernel.sm3(prelude)),
    ttl_seconds: 3600,
    max_downloads: 1,
  })
  await alice.api.putPrelude({ transferId: created.transfer_id, uploadToken: created.upload_token, prelude })

  const slice = new Uint8Array(48)
  const first = await alice.api.putChunk({
    transferId: created.transfer_id,
    uploadToken: created.upload_token,
    index: 0,
    bytes: slice,
  })
  assert.equal(first.status, 201)
  const again = await alice.api.putChunk({
    transferId: created.transfer_id,
    uploadToken: created.upload_token,
    index: 0,
    bytes: slice,
  })
  assert.equal(again.status, 204, '同长度同摘要 → 幂等 204')

  const changed = new Uint8Array(48)
  changed[0] = 1
  await assert.rejects(
    alice.api.putChunk({
      transferId: created.transfer_id,
      uploadToken: created.upload_token,
      index: 0,
      bytes: changed,
    }),
    (err) => err.code === 'CHUNK_CONFLICT',
  )
})
