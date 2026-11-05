<script setup>
/** 最近传输：来自本机真实的发送记录（IndexedDB pending store），不编造数据。 */
import TtlPill from './TtlPill.vue'

const props = defineProps({ items: { type: Array, default: () => [] } })

const stateText = (s) => (s === 'READY' ? '完成' : s === 'UPLOADING' ? '传输中' : s === 'REVOKED' ? '已撤回' : '失败')
const stateClass = (s) => (s === 'READY' ? 'ok' : s === 'UPLOADING' ? 'run' : 'fail')
const fmt = (n) => {
  if (!n) return '—'
  const mb = n / 1048576
  return mb >= 1 ? `${mb.toFixed(mb >= 10 ? 0 : 1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`
}
const when = (t) => {
  if (!t) return ''
  const d = new Date(t)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}
</script>

<template>
  <section class="card">
    <div class="card-title">最近传输</div>
    <ul v-if="props.items.length" class="rlist">
      <li v-for="it in props.items" :key="it.transferId" class="ritem">
        <div>
          <div class="rname">{{ it.fileName }}</div>
          <div class="meta">
            {{ fmt(it.fileSize) }} · {{ when(it.createdAt) }}
            <TtlPill v-if="it.expiresAt" :expires-at="it.expiresAt" />
          </div>
        </div>
        <span class="pill" :class="stateClass(it.state)">{{ stateText(it.state) }}</span>
      </li>
    </ul>
    <p v-else class="meta" style="margin: 6px 0 0">还没有传输记录</p>
  </section>
</template>
