<script setup>
/**
 * 块矩阵（v4）：格子只表达状态，不承担点击。
 * - DOM 节点数 = 格数（PC ≤1024 / 移动 ≤100），与块数解耦；
 * - 更新走 rAF 批量，单帧最多改 FRAME_BUDGET 格。
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import {
  aggregateCells,
  diffCells,
  planFrames,
  FRAME_BUDGET,
  PC_MAX_CELLS,
  M_MAX_CELLS,
  PC_COLS,
  M_COLS,
} from '../lib/matrix.js'

const props = defineProps({
  chunkCount: { type: Number, default: 1 },
  states: { type: Array, default: () => [] },
  variant: { type: String, default: 'pc' }, // pc | mobile
})

const maxCells = computed(() => (props.variant === 'mobile' ? M_MAX_CELLS : PC_MAX_CELLS))
const cols = computed(() => (props.variant === 'mobile' ? M_COLS : PC_COLS))
const agg = computed(() =>
  aggregateCells({ chunkCount: props.chunkCount, states: props.states, maxCells: maxCells.value }),
)

const host = ref(null)
let rendered = []
let frame = 0
let queue = []

function paint(indexes) {
  const el = host.value
  if (!el) return
  for (const i of indexes) {
    const cell = el.children[i]
    const c = agg.value.cells[i]
    if (!cell || !c) continue
    cell.className = `c ${c.state}`
    if (c.state === 'part') {
      cell.style.background = `linear-gradient(90deg, var(--accent) ${Math.round(c.fill * 100)}%, var(--wait) ${Math.round(c.fill * 100)}%)`
    } else {
      cell.style.background = ''
    }
  }
}

function schedule() {
  const changed = diffCells(rendered, agg.value.cells)
  rendered = agg.value.cells.map((c) => ({ ...c }))
  if (!changed.length) return
  queue.push(...changed)
  if (frame) return
  const step = () => {
    const batch = queue.splice(0, FRAME_BUDGET) // 单帧 ≤64 格
    paint(batch)
    frame = queue.length ? requestAnimationFrame(step) : 0
  }
  frame = requestAnimationFrame(step)
}

watch(() => [props.chunkCount, props.states], schedule, { immediate: true, deep: true })

onBeforeUnmount(() => {
  if (frame) cancelAnimationFrame(frame)
  frame = 0
  queue = []
})
</script>

<template>
  <div
    ref="host"
    class="matrix"
    :class="variant"
    :style="{ gridTemplateColumns: `repeat(${cols}, 1fr)` }"
    aria-hidden="true"
  >
    <div v-for="(c, i) in agg.cells" :key="i" class="c" :class="c.state" />
  </div>
</template>
