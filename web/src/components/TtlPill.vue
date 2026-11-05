<script setup>
/** TTL 胶囊：`23 小时后过期` / `42 分钟后过期` / `已过期，无法取回`；≤1 小时换警示色 + 沙漏。 */
import { computed, onBeforeUnmount, ref } from 'vue'
import { formatTtl, isExpired, isExpiringSoon, remainingMs } from '../lib/serverClock.js'

const props = defineProps({ expiresAt: { type: [String, Number], default: 0 } })

const tick = ref(0)
// 每 30s 本地重算一次（不轮询服务器）；页面重新可见时立即重算
const timer = setInterval(() => (tick.value += 1), 30_000)
const onVisible = () => {
  if (document.visibilityState === 'visible') tick.value += 1
}
document.addEventListener('visibilitychange', onVisible)
onBeforeUnmount(() => {
  clearInterval(timer)
  document.removeEventListener('visibilitychange', onVisible)
})

const ms = computed(() => {
  void tick.value
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
