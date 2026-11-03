/**
 * 真内核集成测试（Rust→WASM，raw C ABI）。
 *
 * 产物不在仓库里（根 `.gitignore` 忽略 `*.wasm`），所以：
 *   - 找 `YS_WASM` 环境变量，或默认 `web/public/ys_kernel.wasm`；
 *   - 找不到就 skip（**不伪装 PASS**）。
 *
 * 构建方式（在仓库根）：
 *   cd crypto && CARGO_TARGET_DIR=/.cache/rust-web cargo build --release --target wasm32-unknown-unknown -p yanshu-sm
 *   cp /.cache/rust-web/wasm32-unknown-unknown/release/yanshu_sm.wasm web/public/ys_kernel.wasm
 *
 * 这份测试与 `loop.test.js` 的区别：这里跑的是**真国密**（SM3/SM4-GCM/SM2），
 * 包也是内核按自己的布局产出的，切分/拼回走同一条传输代码。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { kernelPathOrSkip, buildMetaOrSkip } from './helpers/kernel.js'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import { instantiateKernel } from '../src/crypto/wasm.js'
import { createRelay } from '../relay/dev-relay.mjs'
import { createClient } from '../src/net/client.js'
import { createApi } from '../src/net/api.js'
import { createIdentityManager } from '../src/store/identity.js'
import { memoryBackend } from '../src/store/db.js'
import { sendFile } from '../src/net/upload.js'
import { receiveTransfer } from '../src/net/download.js'
import { decode as b64uDecode } from '../src/lib/base64url.js'

test('真内核：产物与构建溯源同源（sha256 + commit + 版本）', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const metaPath = buildMetaOrSkip(t)
  if (!metaPath) return
  const meta = JSON.parse(readFileSync(metaPath, 'utf8'))
  const digest = createHash('sha256').update(readFileSync(wasmPath)).digest('hex')
  assert.equal(digest, meta.sha256, 'wasm 的 sha256 必须与构建溯源一致')
  assert.match(meta.commit, /^[0-9a-f]{40}$/, '溯源里必须记 40 位 commit')
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  assert.equal(`0x${kernel.version.toString(16)}`, meta.ysVersion)
  assert.equal(kernel.headerLen, meta.headerLen)
  console.log(`[provenance] commit=${meta.commit.slice(0, 7)} sha256=${digest.slice(0, 12)}…`)
})

test('真内核：0 import、导出齐全、版本/包头/块大小可读', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  assert.equal(kernel.mode, 'wasm')
  assert.equal(kernel.isRealCrypto, true)
  assert.equal(kernel.version, 0x00010000)
  assert.equal(kernel.headerLen, 112, '契约布局 HEADER 112')
  assert.equal(kernel.layout, 'contract', '五项契约特征全过才允许标成契约布局')
  assert.deepEqual(kernel.layoutFailedSignals, [], `失败特征：${kernel.layoutFailedSignals.join(',')}`)
  // 新原型：6 参自证解包 + DER 签名 + v1 打包
  assert.equal(kernel.capabilities.selfUnpack, true, 'ys_unpack_v1 应为 6 参自证原型')
  assert.equal(typeof kernel.exports.ys_layout_of, 'undefined', '当前 ABI 已删掉布局判别导出（单一格式）')
  assert.equal(typeof kernel.exports.ys_get_layout, 'undefined')
  // 原型钉死：ys_unpack 7 参（第 4 参公钥可选）、ys_unpack_v1 6 参（自证）
  assert.equal(kernel.exports.ys_unpack.length, 7)
  // 6 参自证原型：不同轮次叫过 _v1 / _v2，按 arity 探测
  assert.ok(['ys_unpack_v1', 'ys_unpack_v2'].some((n) => kernel.exports[n]?.length === 6))
  assert.equal(kernel.capabilities.selfUnpack, true)
  const selfTest = kernel.selfTest()
  assert.equal(selfTest.ok, true, `自检失败：${JSON.stringify(selfTest.checks)}`)
  // 契约 §2.3 四条判据：版本 / HEADER / V1 样例真解 / 改版本字节必拒
  assert.deepEqual(selfTest.checks, { version: true, header: true, v1Sample: true, versionGate: true })
  assert.equal(kernel.capabilities.signDer, true)
  assert.equal(kernel.capabilities.packV1, true)
  assert.ok([40, 112].includes(kernel.headerLen), `包头 ${kernel.headerLen}`)
  assert.ok(kernel.blockSize >= 16 && kernel.blockSize <= 64 * 1024 * 1024)
  assert.ok(kernel.notes.length >= 0)
})

test('真内核：密钥对 / 码 / 归一化 / 签名验签', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const alice = kernel.generateIdentity()
  assert.equal(alice.privateKey.length, 32)
  assert.equal(alice.publicKey.length, 65)
  assert.equal(alice.publicKey[0], 0x04)
  assert.equal(kernel.publicKeyFromPrivate(alice.privateKey).join(','), alice.publicKey.join(','))

  const code = kernel.codeOf(alice.publicKey)
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}$/)
  assert.equal(kernel.normalizeCode(code.toLowerCase()), code)
  assert.equal(kernel.normalizeCode(`${code.slice(0, 2)}-${code.slice(2)}`), code)

  const msg = new TextEncoder().encode('YSAUTH1-test')
  const sig = kernel.sign(alice.privateKey, msg)
  assert.ok(sig.length >= 70 && sig.length <= 72, `签名应为 DER：${sig.length}`)
  assert.equal(kernel.verify(alice.publicKey, msg, sig), true)
  const tampered = new Uint8Array(msg)
  tampered[0] ^= 1
  assert.equal(kernel.verify(alice.publicKey, tampered, sig), false)
})

test('真内核：打包 → 切分 → 拼回 → 解包，明文一致；改一个字节必须报错', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  kernel.blockSize = 4096 // 用小块，几十 KB 就能覆盖多块
  const alice = kernel.generateIdentity()
  const bob = kernel.generateIdentity()
  const data = new Uint8Array(10000).map((_, i) => (i * 97 + 13) & 0xff)

  const pack = kernel.pack({
    data,
    name: '真包.bin',
    mime: 'application/octet-stream',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
    blockSize: kernel.blockSize,
  })
  const { prelude, slices, preludeLen, chunkCount } = kernel.splitPack({
    pack,
    plaintextSize: data.length,
    chunkSize: kernel.blockSize,
  })
  assert.equal(chunkCount, Math.ceil(data.length / kernel.blockSize))
  assert.equal(preludeLen, pack.length - (kernel.segmenter.recordHeaderLen + 16) * chunkCount - data.length)

  // 契约布局的内核会校验整包长度，所以这里用完整包解清单
  const meta = kernel.unpackMeta({ pack, recipientPrivate: bob.privateKey, senderPublic: alice.publicKey })
  assert.equal(meta.size, data.length)
  // 内核 JSON 用契约命名（chunk_count）；老版本叫 block_count
  assert.equal(meta.chunk_count ?? meta.block_count, chunkCount)
  assert.equal(meta.name, '真包.bin')

  const restored = kernel.joinPack({ prelude, slices, plaintextSize: data.length, chunkSize: kernel.blockSize })
  assert.deepEqual([...restored], [...pack], '拼回的整包必须逐字节相同')

  const plain = kernel.unpack({ pack: restored, recipientPrivate: bob.privateKey, senderPublic: alice.publicKey })
  assert.deepEqual([...plain], [...data])

  // 篡改第一块密文：必须失败，且错误码映射到端侧 AUTH 类
  const bad = slices.map((s) => new Uint8Array(s))
  bad[0][0] ^= 0x01
  const tamperedPack = kernel.joinPack({ prelude, slices: bad, plaintextSize: data.length, chunkSize: kernel.blockSize })
  assert.throws(
    () => kernel.unpack({ pack: tamperedPack, recipientPrivate: bob.privateKey, senderPublic: alice.publicKey }),
    (err) => /^CRYPTO_/.test(err.code),
  )

  // 换别的包的块：也必须失败（块序/摘要对不上）
  const wrongPack = kernel.pack({
    data: new Uint8Array(10000).fill(0x33),
    name: 'x.bin',
    mime: 'application/octet-stream',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
    blockSize: kernel.blockSize,
  })
  const wrong = kernel.splitPack({ pack: wrongPack, plaintextSize: 10000, chunkSize: kernel.blockSize })
  const mixed = slices.map((s, i) => (i === 0 ? new Uint8Array(wrong.slices[0]) : new Uint8Array(s)))
  const mixedPack = kernel.joinPack({ prelude, slices: mixed, plaintextSize: data.length, chunkSize: kernel.blockSize })
  assert.throws(
    () => kernel.unpack({ pack: mixedPack, recipientPrivate: bob.privateKey, senderPublic: alice.publicKey }),
    (err) => /^CRYPTO_/.test(err.code),
  )
})

test('真内核：码派生与契约 §15.1 向量一致（PB_S → AWQW / 校验 X）', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const PB_S = Uint8Array.from(
    Buffer.from(
      '04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d',
      'hex',
    ),
  )
  assert.equal(kernel.codeOf(PB_S), 'AWQW', '内核应按 65 字节（补 0x04）派生码')
})

test('真内核：解包不需要发送方公钥（包内 SENDER_PUB 自证）', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  kernel.blockSize = 4096
  const alice = kernel.generateIdentity()
  const bob = kernel.generateIdentity()
  const data = new Uint8Array(3000).map((_, i) => (i * 17) & 0xff)
  const pack = kernel.pack({
    data,
    name: 'self.bin',
    mime: 'application/octet-stream',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
    blockSize: kernel.blockSize,
  })
  // 只给收件人私钥：既不给发送方公钥、也不给发送方码
  const meta = kernel.unpackMeta({ pack, recipientPrivate: bob.privateKey })
  assert.equal(meta.sender_code, kernel.codeOf(alice.publicKey), '包内公钥派生的发送方码')
  const plain = kernel.unpack({ pack, recipientPrivate: bob.privateKey })
  assert.deepEqual([...plain], [...data])

  // 换掉包内 SENDER_PUB 任一字节 → 必须失败（来源不可伪造）
  const tampered = new Uint8Array(pack)
  tampered[112 + 10] ^= 0x01 // SENDER_PUB 段内第 10 字节（HEADER 之后）
  assert.throws(
    () => kernel.unpack({ pack: tampered, recipientPrivate: bob.privateKey }),
    (err) => /^CRYPTO_/.test(err.code),
  )
})

test('真内核：包里搜不到文件名与明文片段（服务端零知识）', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const alice = kernel.generateIdentity()
  const bob = kernel.generateIdentity()
  const marker = new TextEncoder().encode('SECRET-PLAINTEXT-MARKER-0123456789')
  const data = new Uint8Array(5000)
  data.set(marker, 100)
  const pack = kernel.pack({
    data,
    name: '绝密文件名-报告.pdf',
    mime: 'application/pdf',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
  })
  const nameBytes = new TextEncoder().encode('绝密文件名')
  const contains = (hay, needle) => {
    outer: for (let i = 0; i + needle.length <= hay.length; i++) {
      for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer
      return true
    }
    return false
  }
  assert.equal(contains(pack, nameBytes), false, '文件名不得出现在包字节里')
  assert.equal(contains(pack, marker), false, '明文片段不得出现在包字节里')
})

test('真内核 + 真中转：A 端加密 → 分块上传 → B 端取回解密，字节一致', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const relay = createRelay() // 真 SM3 摘要校验开着
  await new Promise((resolve) => relay.server.listen(0, '127.0.0.1', resolve))
  const port = relay.server.address().port
  const client = createClient({ baseUrl: `http://127.0.0.1:${port}/v1` })

  const makePeer = async () => {
    const kernel = await instantiateKernel(readFileSync(wasmPath))
    kernel.blockSize = 4096
    const identity = createIdentityManager({ kernel, backend: memoryBackend() })
    await identity.loadOrCreate()
    const api = createApi({ client, kernel, session: identity.session })
    await identity.register({ api, nickname: `雁${identity.session.code}` })
    return {
      kernel,
      api,
      session: identity.session,
      senderPublic: async (code) => {
        const json = await api.getCode(code)
        return b64uDecode(json.public_key)
      },
    }
  }

  const alice = await makePeer()
  const bob = await makePeer()

  const data = new Uint8Array(20000).map((_, i) => (i * 41 + 5) & 0xff)
  const file = new File([data], 'real.bin', { type: 'application/octet-stream' })
  const sent = await sendFile({
    api: alice.api,
    kernel: alice.kernel,
    session: alice.session,
    file,
    recipient: { code: bob.session.code, nickname: bob.session.nickname, publicKey: bob.session.publicKey },
    pendingStore: memoryBackend(),
  })
  assert.equal(sent.state, 'READY')
  assert.ok(sent.chunkCount >= 5)

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
  assert.equal(saved.name, 'real.bin')
  assert.equal(received.size, data.length)
  assert.deepEqual([...new Uint8Array(await saved.blob.arrayBuffer())], [...data])

  const after = relay.state.transfers.get(sent.transferId)
  assert.equal(after.state, 'CONSUMED')
  assert.equal(after.chunks.size, 0)
  relay.server.close()
})

test('真内核：prelude-only 能显示发件人/文件名/大小，但如实标"未校验"', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  kernel.blockSize = 4096
  const alice = kernel.generateIdentity()
  const bob = kernel.generateIdentity()
  const data = new Uint8Array(9000).map((_, i) => (i * 5) & 0xff)
  const pack = kernel.pack({
    data,
    name: 'prelude.bin',
    mime: 'application/octet-stream',
    recipientPublic: bob.publicKey,
    senderPrivate: alice.privateKey,
    blockSize: kernel.blockSize,
  })
  const { prelude } = kernel.splitPack({ pack, plaintextSize: data.length, chunkSize: kernel.blockSize })

  const early = kernel.unpackMetaPrelude({ prelude, recipientPrivate: bob.privateKey })
  assert.ok(early, '内核应提供 ys_unpack_meta_prelude')
  assert.equal(early.meta_scope, 'prelude')
  assert.equal(early.data_verified, false, 'prelude 阶段块未校验，必须如实标 false')
  assert.equal(early.name, 'prelude.bin')
  assert.equal(Number(early.size), data.length)
  assert.equal(early.sender_code, kernel.codeOf(alice.publicKey))

  // 反向：整包 _meta 对 prelude-only 必须拒绝（TRUNCATED），两个入口不许混用
  assert.throws(
    () => kernel.unpackMeta({ pack: prelude, recipientPrivate: bob.privateKey }),
    (err) => err.code === 'CRYPTO_TRUNCATED',
  )

  // 收齐后：session 标记已校验
  const session = kernel.openUnpackSession({
    prelude,
    recipientPrivate: bob.privateKey,
    plaintextSize: data.length,
    chunkSize: kernel.blockSize,
  })
  assert.equal(session.metaScope, 'prelude')
  assert.equal(session.dataVerified, false)
  const { slices } = kernel.splitPack({ pack, plaintextSize: data.length, chunkSize: kernel.blockSize })
  slices.forEach((s, i) => session.feed(i, s))
  const done = session.finish()
  assert.equal(done.dataVerified, true)
  assert.equal(done.meta.scope, 'full')
  assert.deepEqual([...done.plain], [...data])
})
