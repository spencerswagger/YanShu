<script setup>
import { ref } from 'vue'
import { describeError } from '../net/errors.js'
import { bytes as fmtBytes, clock, percent } from '../lib/format.js'
import ReportSheet from './ReportSheet.vue'

const props = defineProps({
  api: { type: Object, default: null },
  receive: { type: Function, required: true },
})

const items = ref([])
const loading = ref(false)
const errorText = ref('')
const notice = ref('')
const activeId = ref('')
const progress = ref({ done: 0, total: 0, message: '', verified: false, meta: null })

async function refresh() {
  if (!props.api) return
  loading.value = true
  errorText.value = ''
  try {
    const res = await props.api.inbox({ state: 'ready', limit: 20 })
    items.value = res?.items || []
  } catch (err) {
    const d = describeError(err)
    errorText.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
  } finally {
    loading.value = false
  }
}

async function take(item) {
  activeId.value = item.transfer_id
  errorText.value = ''
  notice.value = ''
  try {
    const result = await props.receive({
      transferId: item.transfer_id,
      onProgress: (p) => {
        progress.value = {
          done: p.done || 0,
          total: p.total || 0,
          message: p.message || '',
          verified: Boolean(p.verified),
          meta: p.meta || progress.value.meta,
        }
      },
    })
    notice.value = `已保存至本机：${result.name}（${fmtBytes(result.size)}）`
    items.value = items.value.filter((i) => i.transfer_id !== item.transfer_id)
  } catch (err) {
    const d = describeError(err)
    errorText.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
    if (d.terminal) items.value = items.value.filter((i) => i.transfer_id !== item.transfer_id)
  } finally {
    activeId.value = ''
    progress.value = { done: 0, total: 0, message: '', verified: false, meta: null }
  }
}

function focusDrop() {
  document.querySelector('.col-main .drop')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
}

defineExpose({ refresh })
refresh()
</script>

<template>
  <section class="card">
    <div class="spread" style="margin-bottom: 10px">
      <div class="card-title">{{ items.length ? `${items.length} 个文件待接收` : '暂无待接收文件' }}</div>
      <button type="button" class="icon-btn" :disabled="loading" aria-label="刷新" @click="refresh">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v5h-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
    </div>

    <p v-if="notice" class="banner info">{{ notice }}</p>
    <p v-if="errorText" class="banner warn">{{ errorText }}</p>

    <ul v-if="items.length" class="rlist">
      <li v-for="item in items" :key="item.transfer_id" class="ritem row-72">
        <div class="who">
          <div class="avatar">{{ (item.sender_nickname || item.sender_code || '?').slice(0, 1) }}</div>
          <div>
            <div class="rname">{{ item.sender_nickname || item.sender_code }}</div>
            <div class="meta">{{ fmtBytes(item.plaintext_size) }} · {{ item.chunk_count }} 块</div>
          </div>
        </div>
        <button
          type="button"
          class="icon-btn lg"
          :disabled="activeId === item.transfer_id"
          :aria-label="activeId === item.transfer_id ? '解密中' : '下载并解密'"
          @click="take(item)"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M12 4v10m0 0 4-4m-4 4-4-4M5 18h14" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </button>
        <ReportSheet :api="api" :transfer-id="item.transfer_id" icon-only />
        <div v-if="activeId === item.transfer_id" class="row-progress">
          <div class="progress"><span :style="{ width: percent(progress.done, progress.total) + '%' }" /></div>
        </div>
      </li>
    </ul>

    <div v-else class="empty-state">
      <svg width="96" height="96" viewBox="0 0 24 24" fill="none" aria-hidden="true" class="empty-art">
        <path d="M4 7h16v12H4z" stroke="currentColor" stroke-width="1.1" />
        <path d="M4 7l8 6 8-6" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round" />
        <circle cx="18" cy="6" r="2.2" fill="var(--tint)" stroke="var(--accent)" stroke-width="1" />
      </svg>
      <div class="empty-title">暂无待接收文件</div>
      <button type="button" class="primary block lg" @click="focusDrop">发送文件</button>
    </div>
  </section>
</template>
