<script setup>
import { computed } from 'vue'
import FlipCounter from './FlipCounter.vue'
import { formatBytesTotal, formatCount } from '../net/stats.js'

const props = defineProps({
  sent: { type: Number, default: 0 },
  received: { type: Number, default: 0 },
  rate: { type: String, default: '—' },
  /** `/v1/stats` 的响应；null 表示拿不到 → 整块隐藏（静默降级） */
  platform: { type: Object, default: null },
})

const today = computed(() => props.platform?.today || null)
const total = computed(() => props.platform?.total || null)
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

    <template v-if="today && total">
      <div class="divider"></div>
      <div class="stat">
        <div class="k">今日已取走</div>
        <FlipCounter :value="formatCount(today.consumed)" size="sm" />
      </div>
      <div class="stat">
        <div class="k">今日流量</div>
        <FlipCounter :value="formatBytesTotal(today.consumed_bytes)" size="sm" />
      </div>
      <div class="stat">
        <div class="k">今日新建</div>
        <FlipCounter :value="formatCount(today.created)" size="sm" />
      </div>
      <div class="stat">
        <div class="k">累计已取走</div>
        <FlipCounter :value="formatCount(total.consumed)" size="sm" />
      </div>
      <div class="stat">
        <div class="k">累计流量</div>
        <FlipCounter :value="formatBytesTotal(total.consumed_bytes)" size="sm" />
      </div>
      <div class="stat">
        <div class="k">累计新建</div>
        <FlipCounter :value="formatCount(total.created)" size="sm" />
      </div>
    </template>
  </section>
</template>
