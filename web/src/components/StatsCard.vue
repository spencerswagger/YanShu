<script setup>
import FlipCounter from './FlipCounter.vue'

defineProps({
  sent: { type: Number, default: 0 },
  received: { type: Number, default: 0 },
  rate: { type: String, default: '—' },
})
</script>

<template>
  <section class="card stats-card">
    <div class="stat">
      <div class="k">今日发送</div>
      <FlipCounter :value="sent" size="lg" />
    </div>
    <div class="stat">
      <div class="k">今日接收</div>
      <FlipCounter :value="received" size="lg" />
    </div>
    <div class="stat">
      <div class="k">成功率</div>
      <FlipCounter :value="rate" size="lg" />
    </div>
  </section>
</template>
