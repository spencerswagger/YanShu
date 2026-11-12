/**
 * 「没落盘成功不许报成功」的回归（Owl II 的 P1-3 / Ops 的 P0）。
 *
 * 背景事实：**v0.2.4 的流式接收从不调用 `save()`**（`v0.2.4:web/src/net/download.js`
 * 收尾只有 `await sink.close()` → `if (ack) api.ack()` → `return`，`save` 只出现在
 * 整包回退路径 `receiveOnce` 的 `:255`）。所以这一组用例专门钉死新实现的三条：
 *   ① 写盘失败 → 必须抛可读错误码（UI 有文案），**不得** ack（ack = 服务端删密文）；
 *   ② 交付下载失败 → 同样不 ack、不报成功；
 *   ③ 成功时顺序是 close → save → ack。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { receiveTransfer } from '../src/net/download.js'
import { createChunkPacer } from '../src/net/chunkPacer.js'
import { createMemorySink, createOpfsSink } from '../src/lib/saveStream.js'
import { describeError } from '../src/net/errors.js'

const CHUNK = 8
const COUNT = 4
const HEADER = 16

function fakeKernel() {
  let expected = 0
  return {
    supportsStreaming: true,
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
      assert.equal(new DataView(record.buffer, record.byteOffset).getUint32(0, false), expected)
      expected += 1
      return record.slice(HEADER, HEADER + CHUNK)
    },
    streamUnpackEnd() {},
  }
}

function fakeApi() {
  const acked = []
  return {
    acked,
    async getPrelude() {
      return { bytes: new Uint8Array([1]), downloadId: 'dl-1' }
    },
    async getChunk({ index }) {
      const rec = new Uint8Array(HEADER + CHUNK)
      new DataView(rec.buffer).setUint32(0, index, false)
      new DataView(rec.buffer).setUint32(4, CHUNK, false)
      rec.set(new Uint8Array(CHUNK).fill(index & 0xff), HEADER)
      return rec
    },
    async ack({ transferId }) {
      acked.push(transferId)
    },
  }
}

const fastPacer = () => createChunkPacer({ ratePerSec: 1000, burst: 1000, maxRatePerSec: 1000, sleep: async () => {} })

function run({ sink, save, api = fakeApi(), onProgress = () => {}, cleanupDelayMs = 0 }) {
  return receiveTransfer({
    api,
    kernel: fakeKernel(),
    session: { privateKey: new Uint8Array(32) },
    transferId: 't-save',
    sinkFactory: () => sink,
    save,
    pacer: fastPacer(),
    onProgress,
    cleanupDelayMs,
  })
}

/** 让 setTimeout(0) 跑完 */
const tick = () => new Promise((r) => setTimeout(r, 20))

test('写盘失败（OPFS 配额满）：报 SAVE_QUOTA_EXCEEDED、不 ack、不报成功', async () => {
  const root = {
    async getFileHandle() {
      return {
        async createWritable() {
          return {
            async write() {
              throw new DOMException('quota exceeded', 'QuotaExceededError')
            },
            async close() {},
            async abort() {},
          }
        },
        async getFile() {
          throw new Error('不该走到这里')
        },
      }
    },
    async removeEntry() {},
  }
  const sink = createOpfsSink('big.bin', { root })
  await sink.open()
  const api = fakeApi()
  let saved = 0
  await assert.rejects(
    () => run({ sink, save: () => void saved++, api }),
    (err) => err.code === 'SAVE_QUOTA_EXCEEDED',
  )
  assert.equal(api.acked.length, 0, '没落盘就不许 ack（ack = 服务端删密文）')
  assert.equal(saved, 0, '没落盘就不许把文件交给浏览器')
  const copy = describeError({ code: 'SAVE_QUOTA_EXCEEDED' })
  assert.ok(copy.title && copy.hint, 'UI 必须有可读文案，不能只显示英文异常名')
})

test('写盘失败时 sink.abort() 会清掉半成品（不留垃圾也不留半截文件）', async () => {
  let removed = null
  const root = {
    async getFileHandle(name) {
      return {
        async createWritable() {
          return { async write() {}, async close() {}, async abort() {} }
        },
        async getFile() {
          return { size: 0 }
        },
      }
    },
    async removeEntry(name) {
      removed = name
    },
  }
  const sink = createOpfsSink('half.bin', { root })
  await sink.open()
  await assert.rejects(
    () =>
      run({
        sink: {
          ...sink,
          async close() {
            throw Object.assign(new Error('disk full'), { code: 'SAVE_WRITE_FAILED' })
          },
        },
        save: () => {},
      }),
    (err) => err.code === 'SAVE_WRITE_FAILED',
  )
  assert.equal(removed, sink.entryName, '失败必须清掉 OPFS 半成品（按唯一条目名）')
})

test('交付下载失败（浏览器拒绝 a.click）：报 SAVE_DELIVERY_FAILED、不 ack', async () => {
  const api = fakeApi()
  const sink = createMemorySink({ maxBytes: 1024 })
  sink.name = 'big.bin'
  Object.assign(globalThis, {
    document: {
      createElement: () => ({
        click() {
          throw new DOMException('not allowed', 'SecurityError')
        },
        remove() {},
      }),
      body: { appendChild() {} },
    },
    URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
  })
  const { saveBlob } = await import('../src/lib/save.js')
  await assert.rejects(
    () => run({ sink, save: saveBlob, api }),
    (err) => err.code === 'SAVE_DELIVERY_FAILED',
  )
  assert.equal(api.acked.length, 0, '文件没交出去就不许 ack')
})

test('成功路径顺序：close → save → ack（save 抛错则整单失败、ack 为零）', async () => {
  const order = []
  const api = fakeApi()
  const origAck = api.ack
  api.ack = async (arg) => {
    order.push('ack')
    return origAck(arg)
  }
  const sink = {
    kind: 'memory',
    name: 'big.bin',
    async write() {},
    async close() {
      order.push('close')
      return { name: 'big.bin', blob: { size: COUNT * CHUNK } }
    },
    async cleanup() {
      order.push('cleanup')
    },
    async abort() {},
  }
  const r = await run({
    sink,
    save: async () => {
      order.push('save')
    },
    api,
  })
  // cleanup 必须在 ack **之后**（OPFS 副本是「click 成功但没写盘」的唯一兜底，不能删在 ack 前）
  assert.deepEqual(order, ['close', 'save', 'ack'], `ack 前的顺序必须是 close→save→ack（实际 ${order}）`)
  assert.equal(r.size, COUNT * CHUNK)
  await tick()
  assert.deepEqual(order, ['close', 'save', 'ack', 'cleanup'], `副本要在 ack 之后才清（实际 ${order}）`)
})

test('sink.close() 既没 blob/file 也没 delivered：在 ack 之前就报错（别静默跳过交付）', async () => {
  const api = fakeApi()
  let saved = 0
  const sink = {
    kind: 'weird',
    name: 'big.bin',
    async write() {},
    async close() {
      // 违反 sink 契约：既没交出 blob/file，也没声明 delivered
      return { name: 'big.bin' }
    },
    async abort() {},
  }
  await assert.rejects(
    () => run({ sink, save: () => void saved++, api }),
    (err) => err.code === 'SAVE_DELIVERY_FAILED',
  )
  assert.equal(api.acked.length, 0, '交付形态不合格就不许 ack（ack = 服务端删密文，v0.2.4 原地复现）')
  assert.equal(saved, 0, '没有可交出的东西，不许假装交付')
})

test('sink 声明 delivered:true（用户选路径已直接写盘）→ 不再弹一次下载，照常 ack', async () => {
  const order = []
  const api = fakeApi()
  const origAck = api.ack
  api.ack = async (arg) => {
    order.push('ack')
    return origAck(arg)
  }
  let saved = 0
  const sink = {
    kind: 'file',
    name: 'big.bin',
    async write() {},
    async close() {
      order.push('close')
      return { name: 'big.bin', delivered: true }
    },
    async abort() {},
  }
  await run({ sink, save: () => void saved++, api })
  assert.equal(saved, 0, 'delivered 的 sink 已经写进用户目标位置，不能再用 <a download> 弹一次')
  assert.deepEqual(order, ['close', 'ack'])
})

/**
 * Gate 的 P0 现场复刻（主线 `e01e67d`）：
 *   `download.js:139` 把 `await sink.close()` 的返回值丢掉 → 「没有 showSaveFilePicker 的环境里数据落到内存 sink，
 *   组装完直接丢弃，没有报错」→ `InboxPanel` 无条件写「已保存至本机」→ `ack()` 让服务端删密文 → 不可恢复。
 * 这三条必须各有用例：① 返回值必须被交付；② 交付失败不许 ack；③ 顺序 ack 在最后。
 */
test('Gate 现场①（无 showSaveFilePicker / 小文件走内存 sink）：close() 的字节必须真交给浏览器，ack 在最后', async () => {
  const hadPicker = Object.prototype.hasOwnProperty.call(globalThis, 'showSaveFilePicker')
  const picker = globalThis.showSaveFilePicker
  delete globalThis.showSaveFilePicker
  try {
    const order = []
    const api = fakeApi()
    const origAck = api.ack
    api.ack = async (arg) => {
      order.push('ack')
      return origAck(arg)
    }
    // 生产选路：App 传的就是 defaultSinkFactory（无 picker → 小文件内存 sink；大文件 OPFS/明确报错）
    const { defaultSinkFactory } = await import('../src/lib/saveStream.js')
    const r = await receiveTransfer({
      api,
      kernel: fakeKernel(),
      session: { privateKey: new Uint8Array(32) },
      transferId: 't-gate-1',
      sinkFactory: (m) => defaultSinkFactory(m, { root: null, canPick: false }),
      save: async (payload) => {
        order.push('save')
        assert.ok(payload, 'close() 的返回值必须被用上（v0.2.4 就是这里丢掉 → 静默丢数据）')
        assert.equal(payload.size, COUNT * CHUNK, '交给浏览器的必须是完整明文')
      },
      pacer: fastPacer(),
      onProgress: () => {},
      cleanupDelayMs: 0,
    })
    assert.deepEqual(order, ['save', 'ack'], 'ack（服务端删密文）必须在交付之后')
    assert.equal(r.size, COUNT * CHUNK)
  } finally {
    if (hadPicker) globalThis.showSaveFilePicker = picker
  }
})

test('Gate 现场②（大文件 / 无 picker）：不许落到整包内存 sink，必须走 OPFS 并把 File 交出去', async () => {
  const written = []
  const files = new Map()
  const root = {
    async getFileHandle(name, { create } = {}) {
      if (!files.has(name) && create) files.set(name, { chunks: [] })
      const entry = files.get(name)
      return {
        async createWritable() {
          return {
            async write(bytes) {
              entry.chunks.push(bytes.slice())
              written.push(bytes.length)
            },
            async close() {},
            async abort() {},
          }
        },
        async getFile() {
          const size = entry.chunks.reduce((n, c) => n + c.length, 0)
          return { name, size, kind: 'file', lastModified: Date.now() }
        },
      }
    },
    async removeEntry(name) {
      files.delete(name)
    },
  }
  // 假内核谎报 2 GiB（只验证「按大小选路」，不验证真的写 2 GiB）
  const bigKernel = { ...fakeKernel(), streamUnpackBegin: () => ({ chunk_count: COUNT, size: 2 * 1024 * 1024 * 1024, name: 'big.bin', sender_code: 'AAAA' }) }
  let kind = ''
  let delivered = null
  const api = fakeApi()
  const order = []
  const origAck = api.ack
  api.ack = async (arg) => {
    order.push('ack')
    return origAck(arg)
  }
  const { defaultSinkFactory } = await import('../src/lib/saveStream.js')
  await receiveTransfer({
    api,
    kernel: bigKernel,
    session: { privateKey: new Uint8Array(32) },
    transferId: 't-gate-2',
    sinkFactory: async (m) => {
      const sink = await defaultSinkFactory(m, { root, canPick: false })
      kind = sink.kind
      return sink
    },
    save: async (payload) => {
      order.push('save')
      delivered = payload
    },
    pacer: fastPacer(),
    onProgress: () => {},
    cleanupDelayMs: 0,
  })
  assert.equal(kind, 'opfs', '2 GiB 且无 picker 必须走 OPFS（v0.2.4 是整包内存累积）')
  assert.ok(written.length > 0, '必须真的边收边写盘')
  assert.ok(delivered && typeof delivered.size === 'number', '必须交出 OPFS 的 File（不是丢弃）')
  assert.deepEqual(order, ['save', 'ack'])
})

test('Gate 现场③（close() 返回空）：抛 SAVE_DELIVERY_FAILED、ack 为 0、UI 有可读文案', async () => {
  const api = fakeApi()
  let saved = 0
  await assert.rejects(
    () =>
      run({
        sink: { kind: 'broken', name: 'big.bin', async write() {}, async close() { return null }, async abort() {} },
        save: () => void saved++,
        api,
      }),
    (err) => err.code === 'SAVE_DELIVERY_FAILED',
  )
  assert.equal(saved, 0, '没有可交付的东西，不许调用交付')
  assert.equal(api.acked.length, 0, '交付没成就不许 ack（ack = 服务端删密文，数据不可恢复）')
  const copy = describeError({ code: 'SAVE_DELIVERY_FAILED' })
  assert.ok(copy.title && copy.hint, 'UI 必须有可读文案（InboxPanel 走 describeError 显示 errorText）')
})
