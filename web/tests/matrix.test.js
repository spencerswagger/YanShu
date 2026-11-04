/**
 * 块矩阵聚合（v4 稿）：
 *   ① 格数上限 PC 1024 / 移动 100，与块数解耦；
 *   ② 每格代表 ceil(n/格数) 块；
 *   ③ 格色规则：任一失败→fail、全完成→done、有在传→run、部分完成→part、否则 wait；
 *   ④ rAF 批量：每帧 ≤64 格。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  aggregateCells,
  cellCountFor,
  blocksPerCell,
  diffCells,
  planFrames,
  PC_MAX_CELLS,
  M_MAX_CELLS,
  FRAME_BUDGET,
} from '../src/lib/matrix.js'

const fill = (n, fn) => Array.from({ length: n }, (_, i) => fn(i))

test('格数上限：PC 1024 / 移动 100，小文件按块数', () => {
  assert.equal(cellCountFor(1024, PC_MAX_CELLS), 1024)
  assert.equal(cellCountFor(4096, PC_MAX_CELLS), 1024, '4096 块也只画 1024 格')
  assert.equal(cellCountFor(1024, M_MAX_CELLS), 100)
  assert.equal(cellCountFor(7, PC_MAX_CELLS), 7)
  assert.equal(blocksPerCell(4096, 1024), 4)
  assert.equal(blocksPerCell(1024, 100), 11)
})

test('聚合：1024 块 → 1024 格，状态与块一一对应', () => {
  const states = fill(1024, (i) => (i < 600 ? 'done' : i < 603 ? 'run' : i === 700 ? 'fail' : 'wait'))
  const { cells, perCell, cols } = aggregateCells({ chunkCount: 1024, states, maxCells: PC_MAX_CELLS })
  assert.equal(cells.length, 1024)
  assert.equal(perCell, 1)
  assert.equal(cols, 32)
  assert.equal(cells[0].state, 'done')
  assert.equal(cells[600].state, 'run')
  assert.equal(cells[700].state, 'fail')
  assert.equal(cells[900].state, 'wait')
})

test('聚合：4096 块 → 1024 格，每格 4 块；任一失败即失败色，部分完成按比例', () => {
  // 第 0 格：4 块里 1 块失败 → fail
  // 第 1 格：4 块里 2 块完成 → part，fill = 0.5
  // 第 2 格：4 块全完成 → done
  const states = fill(4096, () => 'wait')
  states[0] = 'fail'
  states[4] = 'done'
  states[5] = 'done'
  for (let i = 8; i < 12; i++) states[i] = 'done'
  const { cells, perCell } = aggregateCells({ chunkCount: 4096, states, maxCells: PC_MAX_CELLS })
  assert.equal(cells.length, 1024)
  assert.equal(perCell, 4)
  assert.equal(cells[0].state, 'fail', '任一失败 → 失败色')
  assert.equal(cells[1].state, 'part')
  assert.equal(cells[1].fill, 0.5, '部分完成按比例渐变')
  assert.equal(cells[2].state, 'done')
})

test('移动 100 格：1024 块每格 11 块，列数 10', () => {
  const states = fill(1024, (i) => (i < 550 ? 'done' : 'wait'))
  const { cells, perCell, cols } = aggregateCells({ chunkCount: 1024, states, maxCells: M_MAX_CELLS })
  assert.equal(cells.length, 100)
  assert.equal(perCell, 11)
  assert.equal(cols, 10)
  assert.equal(cells[0].state, 'done')
  assert.equal(cells[99].state, 'wait')
})

test('rAF 批量：1024 个变更切成每帧 ≤64', () => {
  const changed = fill(1024, (i) => i)
  const frames = planFrames(changed)
  assert.ok(frames.length >= 16, '至少 16 帧')
  assert.ok(frames.every((f) => f.length <= FRAME_BUDGET), `每帧必须 ≤${FRAME_BUDGET}`)
  assert.equal(frames.flat().length, 1024, '不丢变更')
})

test('diffCells 只报变化的格（无变化时为空）', () => {
  const a = [{ state: 'done', fill: 1 }, { state: 'wait', fill: 0 }]
  assert.deepEqual(diffCells(a, a), [])
  const b = [{ state: 'done', fill: 1 }, { state: 'run', fill: 0 }]
  assert.deepEqual(diffCells(a, b), [1])
})
