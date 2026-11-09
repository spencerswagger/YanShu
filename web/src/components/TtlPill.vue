<script setup>
/**
 * TTL 胶囊：`23 小时后过期` / `42 分钟后过期` / `已过期，无法取回`；≤1 小时换警示色 + 沙漏。
 *
 * 时间来自 `lib/expiryTicker.js` 的**单一定时器**（与整行灰化/下载置灰共用同一个 `now`），
 * 到点精确调度（临近窗口 ≤60s 时直接 setTimeout 到那一刻），所以文字与行状态同帧翻转。
 */
import { computed, onBeforeUnmount, watch } from 'vue'
import { expiryNow, trackDeadline } from '../lib/expiryTicker.js'
import { formatTtl, isExpired, isExpiringSoon, remainingMs } from '../lib/serverClock.js'

const props = defineProps({ expiresAt: { type: [String, Number], default: 0 } })

const now = expiryNow()
let untrack = null

watch(
  () => props.expiresAt,
  (v) => {
    untrack?.()
    const ms = typeof v === 'number' ? v : Date.parse(v)
    untrack = trackDeadline(ms)
  },
  { immediate: true },
)
onBeforeUnmount(() => untrack?.())

const ms = computed(() => {
  void now.value // 依赖共享 tick：到点由它叫醒
  return remainingMs(props.expiresAt)
})
const expired = computed(() => isExpired(ms.value))
const soon = computed(() => isExpiringSoon(ms.value))
const text = computed(() => formatTtl(ms.value))
</script>

<template>
  <span class="ttl" :class="{ soon, expired }">
    <svg v-if="soon" width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M7 3h10M7 21h10M8 3c0 5 8 5 8 9s-8 4-8 9M16 3c0 5-8 5-8 9s8 4 8 9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
    </svg>
    {{ text }}
  </span>
</template>
