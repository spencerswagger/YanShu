/**
 * 落盘选路（v0.2.4 口径 2 FAIL 的第二条根因）：
 * 裸 `catch {}` 把 `showSaveFilePicker` 的失败吞掉 → 静默退回整包内存累积。
 * 现在：小文件内存（有硬上限）、大文件优先 OPFS（无手势也能用）、都不行就明确报错。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  MAX_MEMORY_SAVE_BYTES,
  SaveError,
  createMemorySink,
  createOpfsSink,
  defaultSinkFactory,
  makeOpfsEntryName,
  sweepStaleOpfsEntries,
} from '../src/lib/saveStream.js'

function fakeOpfs() {
  const files = new Map()
  const root = {
    files,
    async getFileHandle(name, { create } = {}) {
      if (!files.has(name)) {
        if (!create) throw new DOMException('not found', 'NotFoundError')
        files.set(name, { chunks: [] })
      }
      const entry = files.get(name)
      return {
        async createWritable() {
          return {
            async write(bytes) {
              entry.chunks.push(bytes.slice())
            },
            async close() {},
            async abort() {},
          }
        },
        async getFile() {
          const size = entry.chunks.reduce((n, c) => n + c.length, 0)
          return { name, size, kind: 'file' }
        },
      }
    },
    async removeEntry(name) {
      files.delete(name)
    },
  }
  return root
}

test('小文件走内存 sink，close 交 Blob', async () => {
  const sink = await defaultSinkFactory({ name: 'a.txt', size: 1024 }, { root: null })
  assert.equal(sink.kind, 'memory')
  await sink.write(new Uint8Array([1, 2, 3]))
  const out = await sink.close()
  assert.equal(out.name, 'a.txt')
  assert.equal(out.blob.size, 3)
})

test('内存 sink 超过上限必须报错，不许静默攒到 OOM', async () => {
  const sink = createMemorySink({ maxBytes: 4 })
  await assert.rejects(() => sink.write(new Uint8Array(5)), (err) => err.code === 'SAVE_MEMORY_LIMIT')
})

test('大文件 + 没有手势（无头浏览器）→ 走 OPFS 流式写盘，close 交 File', async () => {
  const root = fakeOpfs()
  const notices = []
  const sink = await defaultSinkFactory(
    { name: 'big.bin', size: 4 * 1024 * 1024 * 1024 },
    { root, canPick: false, onNotice: (n) => notices.push(n) },
  )
  assert.equal(sink.kind, 'opfs')
  for (let i = 0; i < 4; i++) await sink.write(new Uint8Array(1024).fill(i))
  const out = await sink.close()
  assert.equal(out.file.size, 4096, '必须真的写到浏览器内部存储')
  assert.equal(root.files.get(sink.entryName).chunks.length, 4, '临时条目名唯一（ys-<uuid>.part）')
  assert.equal(notices.length, 0)
})

test('大文件 + 选择保存位置失败（用户取消/无手势）→ 不静默，改走 OPFS 并留提示', async () => {
  const root = fakeOpfs()
  const notices = []
  const prev = globalThis.showSaveFilePicker
  globalThis.showSaveFilePicker = async () => {
    throw new DOMException('Must be handling a user gesture', 'SecurityError')
  }
  try {
    const sink = await defaultSinkFactory(
      { name: 'big.bin', size: 2 * 1024 * 1024 * 1024 },
      { root, canPick: true, onNotice: (n) => notices.push(n) },
    )
    assert.equal(sink.kind, 'opfs', 'picker 失败不能退回整包内存')
    assert.equal(notices.length, 1)
    assert.equal(notices[0].code, 'SAVE_PICKER_UNAVAILABLE')
  } finally {
    globalThis.showSaveFilePicker = prev
  }
})

test('大文件 + 既不能选路径也没有 OPFS → 明确报 SAVE_UNSUPPORTED_LARGE', async () => {
  await assert.rejects(
    () => defaultSinkFactory({ name: 'big.bin', size: 8 * 1024 * 1024 * 1024 }, { root: null, canPick: false }),
    (err) => err instanceof SaveError && err.code === 'SAVE_UNSUPPORTED_LARGE',
  )
})

test('OPFS sink 中途 abort 要把半成品删掉', async () => {
  const root = fakeOpfs()
  const sink = createOpfsSink('half.bin', { root })
  await sink.open()
  await sink.write(new Uint8Array(10))
  await sink.abort()
  assert.equal(root.files.has(sink.entryName), false)
})

test('内存上限就是 64 MiB（超过必须换流式落盘）', () => {
  assert.equal(MAX_MEMORY_SAVE_BYTES, 64 * 1024 * 1024)
})

test('OPFS 成功后 cleanup() 必须删掉暂存副本（否则每个大文件留一份）', async () => {
  const root = fakeOpfs()
  const sink = createOpfsSink('big.bin', { root })
  await sink.open()
  await sink.write(new Uint8Array(16))
  await sink.close()
  assert.equal(root.files.has(sink.entryName), true, 'close 之后副本还在（交给浏览器下载要用）')
  await sink.cleanup()
  assert.equal(root.files.has(sink.entryName), false, '交付之后必须清掉，别一直占 origin 存储')
})

test('OPFS 写盘撞配额 → SAVE_QUOTA_EXCEEDED（不是裸 QuotaExceededError）', async () => {
  const root = {
    async getFileHandle() {
      return {
        async createWritable() {
          return {
            async write() {
              throw new DOMException('quota', 'QuotaExceededError')
            },
            async close() {},
            async abort() {},
          }
        },
        async getFile() {
          return { size: 0 }
        },
      }
    },
    async removeEntry() {},
  }
  const sink = createOpfsSink('q.bin', { root })
  await sink.open()
  await assert.rejects(() => sink.write(new Uint8Array(4)), (err) => err.code === 'SAVE_QUOTA_EXCEEDED')
})

test('同一文件名连续两次下载：旧的 cleanup 不得删掉新那句正在写的条目', async () => {
  const root = fakeOpfs()
  const first = createOpfsSink('same.bin', { root })
  await first.open()
  await first.write(new Uint8Array(4))
  await first.close()

  // 第一次的 60s 定时器先到点（模拟"用户在窗口内又点了一次下载"）
  const second = createOpfsSink('same.bin', { root })
  await second.open()
  await second.write(new Uint8Array(8))
  await first.cleanup()
  await second.write(new Uint8Array(8))

  const out = await second.close()
  assert.equal(out.file.size, 16, '第二次下载必须完整落盘（旧定时器不许删到它）')
  assert.equal(out.name, 'same.bin', '交付名仍是原名，不是 .part')
  assert.equal(root.files.has(first.entryName), false, '第一次的条目应被清掉')
  assert.equal(root.files.has(second.entryName), true, '第二次的条目要留着，等它自己 cleanup')
  await second.cleanup()
  assert.equal(root.files.has(second.entryName), false)
})

const DAY = 24 * 60 * 60 * 1000

/** 假 OPFS 目录：带 `entries()` 异步迭代（Chrome 的 FileSystemDirectoryHandle 形态） */
function fakeOpfsDir(seed) {
  const files = new Map(seed)
  return {
    files,
    removed: [],
    async *entries() {
      for (const [name, meta] of [...files.entries()]) {
        yield [
          name,
          {
            kind: 'file',
            async getFile() {
              return { name, lastModified: meta.lastModified }
            },
          },
        ]
      }
    },
    async removeEntry(name) {
      this.removed.push(name)
      files.delete(name)
    },
  }
}

test('OPFS 孤儿临时条目：>24h 的 *.part 被清掉，正在写的（新）动不动，非临时条目不动', async () => {
  const now = 1_700_000_000_000
  const root = fakeOpfsDir([
    ['ys-old.part', { lastModified: now - 2 * DAY }], // 关页面/ack 失败留下的孤儿
    ['ys-fresh.part', { lastModified: now - 60_000 }], // 正在写/刚写完，不能被误删
    ['ys-old.part.bak', { lastModified: now - 2 * DAY }], // 后缀不符：不碰
    ['keep.txt', { lastModified: now - 30 * DAY }], // 不是临时条目：不碰
  ])
  const r = await sweepStaleOpfsEntries(root, { now: () => now })
  assert.deepEqual(r.removed, ['ys-old.part'], `只清孤儿临时条目（实际 ${r.removed}）`)
  assert.equal(r.scanned, 2, '只统计 ys-*.part')
  assert.ok(root.files.has('ys-fresh.part'), '新条目必须留着（正在写）')
  assert.ok(root.files.has('keep.txt'))
})

test('条目读不到 lastModified（0）→ 必须跳过，不能当成「超老」立即删（会删掉正在写的）', async () => {
  const now = 1_700_000_000_000
  const root = {
    removed: [],
    async *entries() {
      yield ['ys-unknown.part', { kind: 'file', async getFile() { return { name: 'ys-unknown.part' } } }]
    },
    async removeEntry(name) {
      this.removed.push(name)
    },
  }
  const r = await sweepStaleOpfsEntries(root, { now: () => now })
  assert.deepEqual(r.removed, [], 'lastModified 缺失 ≠ 过期：删了就是删正在写的')
  assert.equal(r.scanned, 1)
})

test('拿不到目录迭代能力（老浏览器/单测环境）→ 清扫静默跳过，不影响下载', async () => {
  const r = await sweepStaleOpfsEntries({ async removeEntry() {} })
  assert.deepEqual(r, { scanned: 0, removed: [] })
  assert.deepEqual(await sweepStaleOpfsEntries(null), { scanned: 0, removed: [] })
})

test('清扫遇到异常（getFile 抛 / 迭代抛）不冒泡', async () => {
  const root = {
    async *entries() {
      yield ['ys-x.part', { kind: 'file', async getFile() { throw new Error('gone') } }]
    },
    async removeEntry() {},
  }
  assert.deepEqual(await sweepStaleOpfsEntries(root), { scanned: 1, removed: [] }, '读不到 lastModified 就跳过（不误删、不冒泡）')
})

test('临时条目名不拼交付名：180 字符/emoji 长名不撞文件名上限，且两次唯一（60s 内重下不互删）', () => {
  const long = 'x'.repeat(180) + '📦.bin'
  const a = createOpfsSink(long, { root: {} })
  const b = createOpfsSink(long, { root: {} })
  assert.notEqual(a.entryName, b.entryName, '两次必须唯一，否则上一次的 cleanup 定时器会删掉这一次正在写的文件')
  assert.match(a.entryName, /^ys-[\w-]+\.part$/, `条目名形态应固定（实际 ${a.entryName}）`)
  assert.ok(a.entryName.length <= 64, `条目名不受交付名长度影响（实际 ${a.entryName.length}）`)
  assert.equal(a.name, long, '交付名保持不变（用户看到的名字）')
  assert.match(makeOpfsEntryName('abc'), /^ys-abc\.part$/)
})
