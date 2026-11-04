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

defineExpose({ refresh })
refresh()
</script>

<template>
  <section class="card">
    <div class="row" style="justify-content: space-between">
      <h2 style="margin: 0">
        {{ items.length ? `${items.length} 个文件待接收` : '暂无待接收文件' }}
      </h2>
      <button type="button" class="sm" :disabled="loading" @click="refresh">
        {{ loading ? '刷新中…' : '刷新' }}
      </button>
    </div>

    <p v-if="notice" class="banner info">{{ notice }}</p>
    <p v-if="errorText" class="banner warn">{{ errorText }}</p>

    <ul v-if="items.length" class="list">
      <li v-for="item in items" :key="item.transfer_id">
        <div>
          <strong>{{ item.sender_nickname || item.sender_code }}</strong>
          <span class="meta">（{{ item.sender_code }}）</span>
          <span class="tag">{{ item.state }}</span>
        </div>
        <div class="meta">
          {{ fmtBytes(item.plaintext_size) }} · {{ item.chunk_count }} 块 · 到期
          {{ clock(item.expires_at) }}
        </div>
        <div class="row" style="margin-top: 8px; justify-content: space-between">
          <button
            type="button"
            class="primary"
            :disabled="activeId === item.transfer_id"
            @click="take(item)"
          >
            {{ activeId === item.transfer_id ? '解密中…' : '下载并解密' }}
          </button>
          <ReportSheet :api="api" :transfer-id="item.transfer_id" />
        </div>
        <div v-if="activeId === item.transfer_id">
          <div class="progress">
            <span :style="{ width: percent(progress.done, progress.total) + '%' }" />
          </div>
          <p class="meta">
            {{ progress.message }}
            <span v-if="progress.meta" class="tag" :class="progress.verified ? 'ok' : ''">
              {{ progress.verified ? '已校验' : '未校验' }}
            </span>
          </p>
        </div>
      </li>
    </ul>
    <p v-else-if="!loading" class="hint">暂无待接收文件</p>
  </section>
</template>
