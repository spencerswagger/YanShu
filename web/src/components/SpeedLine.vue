<script setup>
/**
 * 速度 / ETA 数字行：`12.4 MB/s · 剩 1 分 20 秒`（速度左、ETA 右），下方 `已传 x / y`。
 * 异常态：`网络较慢` / `连接停滞，重试中`（后者隐藏 ETA）。
 */
import { computed } from 'vue'
import { formatBytesPair, formatEta, formatSpeed } from '../lib/speed.js'

const props = defineProps({
  speedBps: { type: Number, default: 0 },
  etaSec: { type: [Number, null], default: null },
  state: { type: String, default: 'ok' }, // ok | slow | stalled
  done: { type: Number, default: 0 },
  total: { type: Number, default: 0 },
})

const speedText = computed(() => (props.state === 'ok' ? formatSpeed(props.speedBps) : ''))
const etaText = computed(() => (props.state === 'stalled' ? '' : formatEta(props.etaSec)))
const pairText = computed(() => formatBytesPair(props.done, props.total))
</script>

<template>
  <div class="speed-line">
    <div class="speed-row">
      <span v-if="state === 'ok'" class="speed">{{ speedText }}</span>
      <span v-else class="warn">{{ state === 'stalled' ? '连接停滞，重试中' : '网络较慢' }}</span>
      <span class="grow"></span>
      <span v-if="etaText" class="eta">{{ etaText }}</span>
    </div>
    <div class="meta">{{ pairText }}</div>
  </div>
</template>
