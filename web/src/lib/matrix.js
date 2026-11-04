/**
 * 块矩阵聚合（v4 稿）：把 n 个块压到有限格子里，DOM 节点数与块数解耦。
 *
 * 规则（照稿，改这里就等于改规则）：
 * - 格数上限：PC 32×32 = 1024，移动 10×10 = 100；
 * - 每格代表 `ceil(n / 格数)` 块；
 * - 格色：任一失败 → fail；全部完成 → done；有在传 → run；部分完成 → part（按完成比例渐变）；否则 wait。
 */

export const PC_COLS = 32
export const M_COLS = 10
export const PC_MAX_CELLS = 1024
export const M_MAX_CELLS = 100
/** rAF 批量预算：单帧最多改多少格 */
export const FRAME_BUDGET = 64

export const STATE_WAIT = 'wait'
export const STATE_RUN = 'run'
export const STATE_DONE = 'done'
export const STATE_FAIL = 'fail'
export const STATE_PART = 'part'

export function cellCountFor(chunkCount, maxCells = PC_MAX_CELLS) {
  const n = Math.max(1, Number(chunkCount) || 1)
  return Math.min(maxCells, n)
}

export function blocksPerCell(chunkCount, cells) {
  return Math.ceil(Math.max(1, Number(chunkCount) || 1) / Math.max(1, cells))
}

/**
 * @param {{chunkCount:number, states:string[], maxCells?:number}} p
 * @returns {{cells:{state:string,fill:number}[], perCell:number, cols:number}}
 */
export function aggregateCells({ chunkCount, states = [], maxCells = PC_MAX_CELLS }) {
  const total = Math.max(1, Number(chunkCount) || 1)
  const cells = cellCountFor(total, maxCells)
  const perCell = blocksPerCell(total, cells)
  const out = []
  for (let c = 0; c < cells; c++) {
    const start = c * perCell
    const end = Math.min(total, start + perCell)
    if (start >= end) {
      out.push({ state: STATE_WAIT, fill: 0 })
      continue
    }
    let fail = 0
    let done = 0
    let run = 0
    const span = end - start
    for (let i = start; i < end; i++) {
      const s = states[i] || STATE_WAIT
      if (s === STATE_FAIL) fail += 1
      else if (s === STATE_DONE) done += 1
      else if (s === STATE_RUN) run += 1
    }
    let state
    if (fail > 0) state = STATE_FAIL
    else if (done === span) state = STATE_DONE
    else if (run > 0) state = STATE_RUN
    else if (done > 0) state = STATE_PART
    else state = STATE_WAIT
    out.push({ state, fill: done / span })
  }
  return { cells: out, perCell, cols: maxCells === M_MAX_CELLS ? M_COLS : PC_COLS }
}

/** 只返回发生变化的格子下标（用于 rAF 批量写 DOM，避免整表重绘） */
export function diffCells(prev, next) {
  const out = []
  const n = Math.max(prev?.length || 0, next.length)
  for (let i = 0; i < n; i++) {
    const a = prev?.[i]
    const b = next[i]
    if (!a || a.state !== b.state || Math.abs((a.fill || 0) - (b.fill || 0)) > 0.001) out.push(i)
  }
  return out
}

/** 把变更切成每帧 ≤ budget 的批次 */
export function planFrames(changedIndexes, budget = FRAME_BUDGET) {
  const frames = []
  for (let i = 0; i < changedIndexes.length; i += budget) {
    frames.push(changedIndexes.slice(i, i + budget))
  }
  return frames
}
