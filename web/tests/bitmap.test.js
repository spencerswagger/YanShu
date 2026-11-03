import test from 'node:test'
import assert from 'node:assert/strict'
import { decodeBitmap, missingRanges, missingIndexes } from '../src/lib/bitmap.js'

test('位图解码：契约示例 "wA" → 块 0、1 已收（API.md §6.5）', () => {
  assert.deepEqual(decodeBitmap('wA', 3), [true, true, false])
})

test('缺失区间与缺失索引', () => {
  const got = [true, true, false, false, true, false]
  assert.deepEqual(missingRanges(got), [
    { start: 2, count: 2 },
    { start: 5, count: 1 },
  ])
  assert.deepEqual(missingIndexes(got), [2, 3, 5])
})

test('空位图（还没传块）全缺', () => {
  assert.deepEqual(decodeBitmap('', 2), [false, false])
  assert.deepEqual(missingRanges([false, false]), [{ start: 0, count: 2 }])
})
