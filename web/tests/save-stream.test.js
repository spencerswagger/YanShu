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
  assert.equal(root.files.get('big.bin').chunks.length, 4)
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
  assert.equal(root.files.has('half.bin'), false)
})

test('内存上限就是 64 MiB（超过必须换流式落盘）', () => {
  assert.equal(MAX_MEMORY_SAVE_BYTES, 64 * 1024 * 1024)
})
