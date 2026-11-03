/**
 * 接收侧信令（answerer）：offer→answer、ICE 双向、中途失败回落、非本传输忽略。
 * 全部 mock RTCPeerConnection，不打真洞。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { createResponder } from '../src/net/p2pResponder.js'
import { createDirectBuffer, takeChunkBytes } from '../src/net/p2pChunks.js'

function makeSignaler() {
  const handlers = new Set()
  const sent = []
  return {
    sent,
    send(frame) {
      sent.push(frame)
    },
    on(fn) {
      handlers.add(fn)
      return () => handlers.delete(fn)
    },
    emit(frame) {
      for (const fn of handlers) fn(frame)
    },
  }
}

/** 记录调用顺序的假 RTC；`answer` 阶段可注入失败 */
function fakeRTC({ onDataChannel = null, failAnswer = false } = {}) {
  const created = []
  class Fake {
    constructor(config) {
      this.config = config
      this.calls = []
      this.onicecandidate = null
      this.ondatachannel = null
      this.closed = false
      created.push(this)
    }
    async setRemoteDescription(d) {
      this.calls.push(['setRemote', d])
    }
    async createAnswer() {
      if (failAnswer) throw new Error('answer failed')
      return { type: 'answer', sdp: 'a' }
    }
    async setLocalDescription(d) {
      this.calls.push(['setLocal', d])
      this.localDescription = d
    }
    async addIceCandidate(c) {
      this.calls.push(['addIce', c])
    }
    close() {
      this.closed = true
    }
    /** 测试用：模拟远端通道建立 */
    _openChannel(channel) {
      this.ondatachannel?.({ channel })
    }
  }
  return { Fake, created, onDataChannel }
}

test('收到本传输的 RTC_OFFER → 回 RTC_ANSWER（只放 STUN）', async () => {
  const signaler = makeSignaler()
  const { Fake, created } = fakeRTC()
  const responder = createResponder({
    signaler,
    transferId: 'T1',
    selfCode: 'AWQW',
    peerCode: 'P19X',
    stunUrls: ['stun:a:3478', 'turn:b:3478'],
    buffer: createDirectBuffer(),
    RTCPeerConnectionImpl: Fake,
  })
  signaler.emit({ type: 'RTC_OFFER', transfer_id: 'T1', from_code: 'P19X', payload: { type: 'offer', sdp: 'o' } })
  await new Promise((r) => setTimeout(r, 10))

  assert.equal(created.length, 1, '必须构造 RTCPeerConnection')
  assert.deepEqual(created[0].config, { iceServers: [{ urls: 'stun:a:3478' }] }, 'turn: 必须被丢弃')
  const answer = signaler.sent.find((f) => f.type === 'RTC_ANSWER')
  assert.ok(answer, '必须回 RTC_ANSWER')
  assert.equal(answer.transfer_id, 'T1')
  assert.equal(answer.to_code, 'P19X')
  assert.deepEqual(answer.payload, { type: 'answer', sdp: 'a' })
  responder.close()
})

test('ICE 双向传递：收到的候选进 pc，本端候选发给对端', async () => {
  const signaler = makeSignaler()
  const { Fake, created } = fakeRTC()
  createResponder({
    signaler,
    transferId: 'T1',
    selfCode: 'AWQW',
    peerCode: 'P19X',
    stunUrls: ['stun:a:3478'],
    buffer: createDirectBuffer(),
    RTCPeerConnectionImpl: Fake,
  })
  signaler.emit({ type: 'RTC_OFFER', transfer_id: 'T1', payload: { type: 'offer', sdp: 'o' } })
  await new Promise((r) => setTimeout(r, 10))

  // 远端 → 本端
  signaler.emit({ type: 'RTC_ICE', transfer_id: 'T1', payload: { candidate: 'c1' } })
  await new Promise((r) => setTimeout(r, 5))
  assert.ok(
    created[0].calls.some(([k, v]) => k === 'addIce' && v.candidate === 'c1'),
    '收到的候选必须 addIceCandidate',
  )

  // 本端 → 远端
  created[0].onicecandidate({ candidate: { toJSON: () => ({ candidate: 'c2' }) } })
  const out = signaler.sent.find((f) => f.type === 'RTC_ICE')
  assert.ok(out, '本端候选必须发出去')
  assert.deepEqual(out.payload, { candidate: 'c2' })
})

test('非本传输 / 非本端的 RTC_OFFER 一律忽略（不构造 pc）', async () => {
  const signaler = makeSignaler()
  const { Fake, created } = fakeRTC()
  createResponder({
    signaler,
    transferId: 'T1',
    selfCode: 'AWQW',
    peerCode: 'P19X',
    stunUrls: ['stun:a:3478'],
    buffer: createDirectBuffer(),
    RTCPeerConnectionImpl: Fake,
  })
  signaler.emit({ type: 'RTC_OFFER', transfer_id: 'T2', payload: {} }) // 别的传输
  signaler.emit({ type: 'RTC_OFFER', transfer_id: 'T1', to_code: 'ZZZZ', payload: {} }) // 不是发给我的
  signaler.emit({ type: 'RTC_OFFER', transfer_id: 'T1', from_code: 'ABCD', payload: {} }) // 不是对端
  await new Promise((r) => setTimeout(r, 10))
  assert.equal(created.length, 0, '不该处理不属于自己的信令')
  assert.equal(signaler.sent.filter((f) => f.type === 'RTC_ANSWER').length, 0)
})

test('answer 失败 → 静默回落 relay，不抛错', async () => {
  const signaler = makeSignaler()
  const { Fake, created } = fakeRTC({ failAnswer: true })
  const states = []
  createResponder({
    signaler,
    transferId: 'T1',
    selfCode: 'AWQW',
    peerCode: 'P19X',
    stunUrls: ['stun:a:3478'],
    buffer: createDirectBuffer(),
    RTCPeerConnectionImpl: Fake,
    onStatus: (s) => states.push(s),
  })
  signaler.emit({ type: 'RTC_OFFER', transfer_id: 'T1', payload: {} })
  await new Promise((r) => setTimeout(r, 10))
  assert.equal(states.at(-1), 'relay', '失败必须回落 relay')
  assert.equal(created[0].closed, true, 'pc 必须被关掉')
  assert.equal(signaler.sent.filter((f) => f.type === 'RTC_ANSWER').length, 0)
})

test('直连中途失败：已到的块用直连，缺的块走中转补齐，文件仍完整', async () => {
  const buffer = createDirectBuffer()
  const source = [new Uint8Array([1, 1]), new Uint8Array([2, 2]), new Uint8Array([3, 3])]
  // 直连只送到了第 0 块（第 1 块送来的字节是坏的，内核会拒）
  buffer.put(0, source[0])
  buffer.put(1, new Uint8Array([9, 9]))

  const fromRelay = []
  const relayGet = async (i) => {
    fromRelay.push(i)
    return source[i]
  }

  const assembled = []
  for (let i = 0; i < 3; i++) {
    const picked = await takeChunkBytes({ directBuffer: buffer, index: i, getChunk: relayGet })
    let bytes = picked.bytes
    if (picked.source === 'direct' && bytes[0] === 9) {
      // 模拟内核拒收坏块 → 当块改走中转
      bytes = await relayGet(i)
    }
    assembled.push(bytes)
  }

  assert.deepEqual(fromRelay, [1, 2], '坏块与缺块都要回中转补')
  assert.deepEqual(
    assembled.map((b) => [...b]),
    source.map((b) => [...b]),
    '最终装配结果必须与源数据一致（不允许因直连半途失败交出残缺文件）',
  )
})
