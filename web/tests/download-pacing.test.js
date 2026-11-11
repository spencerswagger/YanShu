/**
 * 接收主循环的两条硬约束（v0.2.4 口径 2 FAIL 的直接回归）：
 *   ① 429 不是"等 5 秒再试"就完事：块级 429 必须按 Retry-After 等、并且**在进度里说出来**；
 *      修前 1 GiB 到 69%（707/1024）后掉到约 1 块/5.6 秒，测试窗口内根本跑不完。
 *   ② 顺序不能乱、不能跳块：客户端自己排队（pacer），每次只发一块，429 就原地重试同一块；
 *      收完 `streamUnpackEnd()` + 校验字节数，才算成功。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { receiveTransfer } from '../src/net/download.js'
import { ApiError } from '../src/net/client.js'
import { createChunkPacer } from '../src/net/chunkPacer.js'

const CHUNK = 8
const COUNT = 12
const HEADER = 16

/** 假内核：记录头 = [u32 index][12 字节填充]，块体就是明文 */
function fakeKernel() {
  const order = []
  let expected = 0
  let ended = false
  return {
    supportsStreaming: true,
    order,
    get ended() {
      return ended
    },
    segmenter: {
      buildRecordHeader(index, len) {
        const h = new Uint8Array(HEADER)
        new DataView(h.buffer).setUint32(0, index, false)
        new DataView(h.buffer).setUint32(4, len, false)
        return h
      },
    },
    streamUnpackBegin() {
      return { chunk_count: COUNT, size: COUNT * CHUNK, name: 'big.bin', sender_code: 'AAAA' }
    },
    streamUnpackChunk(record) {
      const index = new DataView(record.buffer, record.byteOffset, record.byteLength).getUint32(0, false)
      const len = new DataView(record.buffer, record.byteOffset, record.byteLength).getUint32(4, false)
      assert.equal(index, expected, `块必须按序喂给内核（拿到 ${index}，期望 ${expected}）`)
      expected += 1
      order.push(index)
      return record.slice(HEADER, HEADER + len)
    },
    streamUnpackEnd() {
      ended = true
    },
  }
}

function makeApi({ throttle = new Map() } = {}) {
  const calls = new Map()
  return {
    calls,
    async getPrelude() {
      return { bytes: new Uint8Array([1, 2, 3]), downloadId: 'dl-1' }
    },
    async getChunk({ index, retry }) {
      assert.equal(retry, false, '块下载必须关掉 client 层固定 5s 退避，交给 pacer')
      const n = (calls.get(index) || 0) + 1
      calls.set(index, n)
      const limit = throttle.get(index) || 0
      if (n <= limit) {
        throw new ApiError({ code: 'RATE_LIMITED', status: 429, retryAfter: 0.01, message: 'too many requests' })
      }
      const body = new Uint8Array(CHUNK).fill(index & 0xff)
      const rec = new Uint8Array(HEADER + CHUNK)
      new DataView(rec.buffer).setUint32(0, index, false)
      new DataView(rec.buffer).setUint32(4, CHUNK, false)
      rec.set(body, HEADER)
      return rec
    },
    async ack() {
      return {}
    },
  }
}

function makeSink() {
  const parts = []
  return {
    kind: 'memory',
    name: 'big.bin',
    parts,
    async write(bytes) {
      parts.push(bytes.slice())
    },
    async close() {
      const total = parts.reduce((n, p) => n + p.length, 0)
      const all = new Uint8Array(total)
      let off = 0
      for (const p of parts) {
        all.set(p, off)
        off += p.length
      }
      return { name: this.name, blob: all }
    },
    async abort() {
      parts.length = 0
    },
  }
}

test('接收：1024 块式串行排队，429 原地重试不丢块、不乱序，且进度里明说限速', async () => {
  const api = makeApi({ throttle: new Map([[0, 1], [5, 2]]) })
  const kernel = fakeKernel()
  const sink = makeSink()
  const events = []

  const result = await receiveTransfer({
    pacer: createChunkPacer({ ratePerSec: 1000, burst: 1000, maxRatePerSec: 1000, sleep: async () => {} }),
    api,
    kernel,
    session: { privateKey: new Uint8Array(32) },
    transferId: 't-1',
    sinkFactory: () => sink,
    onProgress: (p) => events.push(p),
    save: null,
    ack: true,
  })

  assert.equal(kernel.ended, true, '必须走完 streamUnpackEnd（全部块到齐）')
  assert.deepEqual(kernel.order, [...Array(COUNT).keys()], '块顺序必须严格递增')
  assert.equal(result.size, COUNT * CHUNK)
  assert.equal(sink.parts.length, COUNT, '每块都要真正写出')
  const throttled = events.filter((e) => /限速/.test(e.message || ''))
  assert.ok(throttled.length >= 3, `每吃一次 429 都要有可见提示（实际 ${throttled.length} 条）`)
  assert.ok(throttled[0].throttled >= 1, '进度里要带被限速次数')
})

test('接收：连续 9 次 429 → 明确报 RATE_LIMITED，不静默转圈', async () => {
  const api = makeApi({ throttle: new Map([[0, 9]]) })
  const kernel = fakeKernel()
  const sink = makeSink()
  await assert.rejects(
    () =>
      receiveTransfer({
        pacer: createChunkPacer({ ratePerSec: 1000, burst: 1000, maxRatePerSec: 1000, sleep: async () => {} }),
        api,
        kernel,
        session: { privateKey: new Uint8Array(32) },
        transferId: 't-2',
        sinkFactory: () => sink,
        onProgress: () => {},
      }),
    (err) => err.code === 'RATE_LIMITED',
  )
  assert.equal(api.calls.get(0), 9, '必须第 9 次 429 才放弃（阈值钉死：>8 才报错）')
  assert.equal(kernel.ended, false, '没到齐就不能 end')
  assert.ok(sink.parts.every((p) => p.length === CHUNK), '失败时不能交残缺块')
})

test('pacer：429 降速并按 Retry-After 等（不套 5s 地板），连续成功后回升', async () => {
  const waits = []
  const pacer = createChunkPacer({
    ratePerSec: 4,
    sleep: async (ms) => {
      waits.push(ms)
    },
  })
  await pacer.acquire()
  const before = pacer.ratePerSec
  const waitMs = pacer.onThrottled(1)
  assert.equal(waitMs, 1000, '429 时必须按服务端 Retry-After 等，而不是固定 5 秒')
  assert.ok(pacer.ratePerSec < before, '吃 429 必须降速')
  assert.match(pacer.summary(), /限速 1 次/)
  for (let i = 0; i < 240; i++) pacer.onSuccess()
  assert.ok(pacer.ratePerSec > 2 - 1e-9 && pacer.ratePerSec <= 2, `AIMD 必须收敛在 2 次/秒以内（实际 ${pacer.ratePerSec}）`)
  await pacer.acquire()
  assert.ok(waits.length >= 1)
})

test('回退路径（无流式内核）遇到超过 maxPackSize 的明文：取块之前就明确报 FILE_TOO_LARGE', async () => {
  const api = {
    calls: 0,
    async getTransfer() {
      return { state: 'READY', plaintext_size: 1024 * 1024 * 1024, chunk_count: 1024, sender_code: 'AAAA' }
    },
    async getPrelude() {
      api.calls += 1
      return { bytes: new Uint8Array([1]), downloadId: 'd' }
    },
    async getChunk() {
      api.calls += 1
      return new Uint8Array(1)
    },
  }
  const kernel = { supportsStreaming: false } // 没有流式入口 → 只能整包
  await assert.rejects(
    () =>
      receiveTransfer({
        api,
        kernel,
        session: { privateKey: new Uint8Array(32) },
        transferId: 't-legacy',
        senderPublic: async () => new Uint8Array(65),
        save: null,
      }),
    (err) => err.code === 'FILE_TOO_LARGE',
  )
  assert.equal(api.calls, 0, '必须在取 prelude/块之前挡住，不能先把 1 GiB 拉下来')
})

test('恰好 8 次 429：必须扛过去（阈值另一侧钉死）', async () => {
  const api = makeApi({ throttle: new Map([[0, 8]]) })
  const kernel = fakeKernel()
  const sink = makeSink()
  await receiveTransfer({
    pacer: createChunkPacer({ ratePerSec: 1000, burst: 1000, maxRatePerSec: 1000, sleep: async () => {} }),
    api,
    kernel,
    session: { privateKey: new Uint8Array(32) },
    transferId: 't-8',
    sinkFactory: () => sink,
    onProgress: () => {},
    save: null,
  })
  assert.equal(api.calls.get(0), 9, '8 次 429 + 1 次成功')
  assert.deepEqual(kernel.order, [...Array(COUNT).keys()])
})

test('单块一次瞬时 5xx：必须原地重试，不许打死整条下载（相对 main 是回退）', async () => {
  for (const status of [500, 502, 503, 504]) {
    const kernel = fakeKernel()
    const sink = makeSink()
    const calls = new Map()
    const api = {
      async getPrelude() {
        return { bytes: new Uint8Array([1]), downloadId: 'dl-1' }
      },
      async getChunk({ index }) {
        const n = (calls.get(index) || 0) + 1
        calls.set(index, n)
        if (index === 3 && n === 1) throw new ApiError({ code: `HTTP_${status}`, status, message: 'boom' })
        const rec = new Uint8Array(HEADER + CHUNK)
        new DataView(rec.buffer).setUint32(0, index, false)
        new DataView(rec.buffer).setUint32(4, CHUNK, false)
        rec.set(new Uint8Array(CHUNK).fill(index & 0xff), HEADER)
        return rec
      },
      async ack() {},
    }
    const events = []
    await receiveTransfer({
      pacer: createChunkPacer({ ratePerSec: 1000, burst: 1000, maxRatePerSec: 1000, sleep: async () => {} }),
      api,
      kernel,
      session: { privateKey: new Uint8Array(32) },
      transferId: `t-5xx-${status}`,
      sinkFactory: () => sink,
      onProgress: (p) => events.push(p),
      save: null,
    })
    assert.equal(calls.get(3), 2, `${status}：该块必须重试一次`)
    assert.deepEqual(kernel.order, [...Array(COUNT).keys()], `${status}：块顺序不能乱`)
    assert.ok(events.some((e) => String(e.message || '').includes(String(status))), `${status}：必须给可见提示`)
  }
})
