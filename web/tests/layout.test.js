import test from 'node:test'
import assert from 'node:assert/strict'
import { segmenterFor, splitPack, joinPack, chunkCountOf, plainTextLen } from '../src/crypto/layout.js'
import { bytes } from '../src/lib/bytes.js'

/** 造一个"看起来像包"的字节串：prelude + 每块 (recordHeaderLen + tag16 + ptLen)。 */
function fakePack({ preludeLen, plaintextSize, chunkSize, segmenter }) {
  const n = chunkCountOf(plaintextSize, chunkSize)
  const parts = [new Uint8Array(preludeLen).fill(0x11)]
  for (let i = 0; i < n; i++) {
    const ptLen = plainTextLen(i, plaintextSize, chunkSize, n)
    parts.push(segmenter.buildRecordHeader(i, ptLen, n))
    parts.push(new Uint8Array(ptLen).fill(0x40 + i)) // 密文
    parts.push(new Uint8Array(16).fill(0x99)) // tag
  }
  return bytes(...parts)
}

for (const headerLen of [112, 40]) {
  const segmenter = segmenterFor(headerLen)

  test(`切分/拼回（header ${headerLen} / ${segmenter.name}）：块数、长度、字节都自洽`, () => {
    const plaintextSize = 1000
    const chunkSize = 256
    const pack = fakePack({ preludeLen: 500, plaintextSize, chunkSize, segmenter })
    const { prelude, slices, preludeLen, chunkCount } = splitPack({ pack, plaintextSize, chunkSize, segmenter })
    assert.equal(chunkCount, 4)
    assert.equal(preludeLen, 500)
    assert.equal(prelude.length, 500)
    assert.deepEqual(slices.map((s) => s.length), [272, 272, 272, 248])

    const restored = joinPack({ prelude, slices, plaintextSize, chunkSize, segmenter })
    assert.deepEqual([...restored], [...pack], '拼回的整包必须逐字节相同')
  })
}

test('切分算术不自洽时直接报错（不猜）', () => {
  const segmenter = segmenterFor(112)
  const pack = new Uint8Array(1000)
  assert.throws(() => splitPack({ pack, plaintextSize: 5000, chunkSize: 256, segmenter }))
})

test('块数/块长边界：空文件也算 1 块', () => {
  assert.equal(chunkCountOf(0, 1048576), 1)
  assert.equal(plainTextLen(0, 0, 1048576, 1), 0)
  assert.equal(chunkCountOf(1048577, 1048576), 2)
  assert.equal(plainTextLen(1, 1048577, 1048576, 2), 1)
})

test('未知包头长度必须拒绝（说明内核与契约没对齐）', () => {
  assert.throws(() => segmenterFor(48))
})
