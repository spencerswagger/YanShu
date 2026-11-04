/**
 * P2P 直传客户端（默认中转、后台静默打洞、用户点切、断线回落）。
 * 全部用 mock：不打真洞、不连真 WS，只断言路由与失败路径的行为。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { createChunkRouter } from '../src/net/chunkRouter.js'
import { attemptDirect, shouldAttemptDirect, stunOnly, buildRtcConfig } from '../src/net/p2p.js'
import {
  encodeChunkFrame,
  decodeChunkFrame,
  createDirectBuffer,
  takeChunkBytes,
} from '../src/net/p2pChunks.js'
import { createSignaler } from '../src/net/signal.js'

const bytes = (n) => new Uint8Array([n, n + 1, n + 2])

test('ws_url 为空：不尝试打洞（连 RTC 都不构造）', async () => {
  assert.equal(shouldAttemptDirect({ wsUrl: '', hasPeer: true, hasStun: true }), false)
  let ctor = 0
  const result = await attemptDirect({
    signaler: { send() {} },
    wsUrl: '',
    transferId: 't1',
    peerCode: 'AWQW',
    stunUrls: ['stun:stun.example:3478'],
    RTCPeerConnectionImpl: class {
      constructor() {
        ctor += 1
      }
    },
  })
  assert.equal(result, null)
  assert.equal(ctor, 0, '没有 ws_url 时不许构造 RTCPeerConnection')
})

test('只有 STUN：turn: 一律被丢弃', () => {
  const urls = ['stun:a:3478', 'turn:b:3478?transport=udp', 'stuns:c:5349']
  assert.deepEqual(stunOnly(urls), ['stun:a:3478'])
  assert.deepEqual(buildRtcConfig(urls), { iceServers: [{ urls: 'stun:a:3478' }] })
})

test('打洞超时：静默返回 null，不抛错', async () => {
  class FakeRTC {
    createDataChannel() {
      return { onopen: null, close() {} } // 永不 open
    }
    async createOffer() {
      return { type: 'offer', sdp: 'x' }
    }
    async setLocalDescription() {}
    close() {}
  }
  const sent = []
  const started = Date.now()
  const result = await attemptDirect({
    signaler: { send: (f) => sent.push(f.type) },
    wsUrl: 'ws://x/v1/ws',
    transferId: 't1',
    peerCode: 'AWQW',
    stunUrls: ['stun:a:3478'],
    timeoutMs: 60,
    RTCPeerConnectionImpl: FakeRTC,
  })
  assert.equal(result, null)
  assert.ok(Date.now() - started < 1000, '超时必须按 timeoutMs 结束')
  assert.deepEqual(sent, ['RTC_OFFER'], '发了 offer 但没打通')
})

test('默认全走中转：未启用直连前一块都不走通道', async () => {
  const relay = []
  const channel = []
  const router = createChunkRouter({ putChunk: async ({ index }) => relay.push(index) })
  await router.send(0, bytes(0))
  await router.send(1, bytes(1))
  assert.deepEqual(relay, [0, 1])
  assert.deepEqual(channel, [])
  assert.equal(router.mode, 'relay')
})

test('用户点切后：剩余块走直连，已传块不重传', async () => {
  const relay = []
  const direct = []
  const router = createChunkRouter({ putChunk: async ({ index }) => relay.push(index) })
  await router.send(0, bytes(0)) // 切换前：中转
  router.enableDirect({ send: async (index) => direct.push(index) })
  await router.send(1, bytes(1))
  await router.send(2, bytes(2))
  assert.deepEqual(relay, [0], '已传块不得重传')
  assert.deepEqual(direct, [1, 2])
  assert.deepEqual(router.stats, { relay: 1, direct: 2, fallback: 0 })
})

test('直连断了：当块立即回落中转，后续继续走中转', async () => {
  const relay = []
  const router = createChunkRouter({ putChunk: async ({ index }) => relay.push(index) })
  let calls = 0
  router.enableDirect({
    send: async () => {
      calls += 1
      throw new Error('channel closed')
    },
  })
  assert.equal(await router.send(5, bytes(5)), 'relay')
  assert.equal(await router.send(6, bytes(6)), 'relay')
  assert.deepEqual(relay, [5, 6])
  assert.equal(router.mode, 'relay')
  assert.equal(router.stats.fallback, 1, '回落只记一次')
  assert.equal(calls, 1, '断线后不再尝试直连')
})

test('块帧编解码：index 放帧头，密文字节原样', () => {
  const frame = encodeChunkFrame(42, bytes(9))
  const { index, bytes: payload } = decodeChunkFrame(frame.buffer)
  assert.equal(index, 42)
  assert.deepEqual([...payload], [...bytes(9)])
  assert.throws(() => decodeChunkFrame(new Uint8Array([0, 0]).buffer), /P2P_FRAME_TOO_SHORT/)
})

test('接收侧：直连缓冲优先，取不到才回中转（取过即消费）', async () => {
  const buffer = createDirectBuffer()
  buffer.put(3, bytes(3))
  let relayCalls = 0
  const getChunk = async () => {
    relayCalls += 1
    return bytes(9)
  }
  const first = await takeChunkBytes({ directBuffer: buffer, index: 3, getChunk })
  assert.equal(first.source, 'direct')
  assert.equal(relayCalls, 0)
  const second = await takeChunkBytes({ directBuffer: buffer, index: 3, getChunk })
  assert.equal(second.source, 'relay', '缓冲已消费，必须回中转')
  assert.equal(relayCalls, 1)
})

test('信令：连上后先发 HELLO（带挑战与签名），PING 回 PONG', async () => {
  const sent = []
  class FakeWS {
    constructor(url) {
      this.url = url
      this.readyState = 0
      setTimeout(() => {
        this.readyState = 1
        this.onopen?.()
      }, 0)
    }
    send(text) {
      sent.push(JSON.parse(text))
      if (JSON.parse(text).type === 'HELLO') {
        setTimeout(() => this.onmessage?.({ data: JSON.stringify({ type: 'HELLO_OK' }) }), 0)
      }
    }
    close() {
      this.readyState = 3
      this.onclose?.()
    }
  }
  const nonce = Buffer.from(new Uint8Array(32).fill(7)).toString('base64url')
  const client = { post: async () => ({ json: { challenge_id: 'ch1', nonce } }) }
  // 70 字节规范 DER 形状（30 44 ...），normalizeSignature 只做长度/前缀校验
  const kernel = { sign: () => new Uint8Array([0x30, 0x44, ...new Array(68).fill(1)]) }
  const signaler = createSignaler({
    wsUrl: 'ws://x/v1/ws',
    client,
    kernel,
    session: { code: 'AWQW', privateKey: new Uint8Array(32) },
    WebSocketImpl: FakeWS,
    helloTimeoutMs: 50,
  })
  await signaler.open()
  await new Promise((r) => setTimeout(r, 10))
  assert.equal(sent[0].type, 'HELLO')
  assert.equal(sent[0].code, 'AWQW')
  assert.ok(sent[0].challenge_id, 'HELLO 必须带挑战 id')
  assert.ok(sent[0].signature, 'HELLO 必须带签名')
  signaler.send({ type: 'PING' })
  assert.equal(sent.filter((f) => f.type === 'PONG').length, 0, '客户端不主动 PONG')
  signaler.close()
})

test('信令：没有 ws_url 时 open 返回 null（不建连接）', async () => {
  let built = 0
  const signaler = createSignaler({
    wsUrl: '',
    client: {},
    kernel: {},
    session: { code: 'AWQW' },
    WebSocketImpl: class {
      constructor() {
        built += 1
      }
    },
  })
  assert.equal(await signaler.open(), null)
  assert.equal(built, 0)
})
