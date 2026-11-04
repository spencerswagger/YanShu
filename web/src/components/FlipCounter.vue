<script setup>
/**
 * 统计翻牌器：数字等宽（tabular-nums），变化时逐位翻转 ≤400ms，位数变化不抖动。
 * `prefers-reduced-motion` 下直接显示最终值（CSS 里关掉动画）。
 */
import { computed } from 'vue'

const props = defineProps({
  value: { type: [String, Number], default: 0 },
  size: { type: String, default: 'lg' }, // lg | sm
  suffix: { type: String, default: '' },
})

const chars = computed(() => [...String(props.value ?? 0), ...(props.suffix ? [...props.suffix] : [])])
</script>

<template>
  <span class="flip" :class="size">
    <span
      v-for="(ch, i) in chars"
      :key="`${i}-${ch}`"
      class="d"
      :style="{ animationDelay: `${i * 40}ms` }"
      >{{ ch }}</span
    >
  </span>
</template>
