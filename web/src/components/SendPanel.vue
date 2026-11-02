<script setup>
import { computed, ref } from 'vue'
import { decode as b64uDecode } from '../lib/base64url.js'
import { describeError } from '../net/errors.js'
import { bytes as fmtBytes, percent, clock } from '../lib/format.js'

const props = defineProps({
  api: { type: Object, default: null },
  kernel: { type: Object, default: null },
  session: { type: Object, required: true },
  sendFile: { type: Function, required: true },
  resumeSend: { type: Function, required: true },
  pendingBackend: { type: Object, default: null },
})

const emit = defineEmits(['log'])

const file = ref(null)
const codeInput = ref('')
const recipient = ref(null)
const lookupError = ref('')
const phase = ref('idle') // idle | packing | uploading | done | error
const progress = ref({ done: 0, total: 0, message: '' })
const errorText = ref('')
const lastTransfer = ref(null)
const busy = ref(false)
const abort = ref(null)
const pending = ref([])

/** 码的归一化口径由内核给（`ys_normalize_code`），前端不自己实现 Crockford。 */
const normalized = computed(() => {
  const raw = codeInput.value.trim()
  if (!raw || !props.kernel) return null
  return props.kernel.normalizeCode(raw)
})

const codeHint = computed(() => {
  if (!codeInput.value.trim()) return ''
  return normalized.value ? `将使用 ${normalized.value}` : '码格式不对（4 位 Crockford Base32，易混字符会自动纠正）'
})

async function lookup() {
  lookupError.value = ''
  recipient.value = null
  if (!normalized.value || !props.api) return
  try {
    const json = await props.api.getCode(normalized.value)
    recipient.value = {
      code: json.code,
      nickname: json.nickname,
      publicKey: b64uDecode(json.public_key),
    }
  } catch (err) {
    const d = describeError(err)
    lookupError.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
  }
}

function pickFile(event) {
  file.value = event.target.files?.[0] || null
  lastTransfer.value = null
  errorText.value = ''
  phase.value = 'idle'
  progress.value = { done: 0, total: 0, message: '' }
}

async function send() {
  if (!file.value || !recipient.value || !props.api) return
  busy.value = true
  errorText.value = ''
  lastTransfer.value = null
  phase.value = 'packing'
  abort.value = new AbortController()
  try {
    const result = await props.sendFile({
      file: file.value,
      recipient: recipient.value,
      onProgress: (p) => {
        phase.value = p.phase
        progress.value = { done: p.done, total: p.total, message: p.message }
      },
      signal: abort.value.signal,
    })
    lastTransfer.value = result
    phase.value = 'done'
    await loadPending()
  } catch (err) {
    phase.value = 'error'
    const d = describeError(err)
    errorText.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
    emit('log', d.title)
  } finally {
    busy.value = false
  }
}

function cancel() {
  abort.value?.abort()
}

async function revoke() {
  if (!lastTransfer.value || !props.api) return
  try {
    await props.api.revoke({ transferId: lastTransfer.value.transferId })
    lastTransfer.value = { ...lastTransfer.value, state: 'REVOKED' }
  } catch (err) {
    const d = describeError(err)
    errorText.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
  }
}

async function loadPending() {
  if (!props.pendingBackend?.all) return
  const all = await props.pendingBackend.all()
  pending.value = all.filter((r) => r?.kind === 'send' && r.state === 'UPLOADING')
}

async function resume(record) {
  busy.value = true
  errorText.value = ''
  try {
    await props.resumeSend({ record })
    await loadPending()
  } catch (err) {
    const d = describeError(err)
    errorText.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
  } finally {
    busy.value = false
  }
}

defineExpose({ loadPending })
loadPending()
</script>

<template>
  <section class="card">
    <h2>发文件</h2>
    <div class="stack">
      <div>
        <label for="file">选择文件</label>
        <input id="file" type="file" :disabled="busy" @change="pickFile" />
        <p v-if="file" class="meta">{{ file.name }} · {{ fmtBytes(file.size) }}</p>
      </div>

      <div>
        <label for="peer">对方 4 位码</label>
        <div class="row">
          <input
            id="peer"
            v-model="codeInput"
            type="text"
            inputmode="text"
            autocapitalize="characters"
            autocomplete="off"
            placeholder="如 AWQW"
            style="flex: 1"
            :disabled="busy"
            @blur="lookup"
          />
          <button type="button" :disabled="!normalized || busy" @click="lookup">查昵称</button>
        </div>
        <p v-if="codeHint" class="hint">{{ codeHint }}</p>
        <p v-if="recipient" class="meta">
          将发给：<strong>{{ recipient.nickname }}</strong>（{{ recipient.code }}）
        </p>
        <p v-if="lookupError" class="meta" style="color: var(--warn-ink)">{{ lookupError }}</p>
      </div>

      <div class="row">
        <button type="button" class="primary" :disabled="!file || !recipient || busy" @click="send">
          加密并发送
        </button>
        <button v-if="busy" type="button" @click="cancel">取消</button>
      </div>

      <div v-if="phase !== 'idle'">
        <div class="progress"><span :style="{ width: percent(progress.done, progress.total) + '%' }" /></div>
        <p class="meta">
          {{ progress.message }}
          <span v-if="progress.total">（{{ percent(progress.done, progress.total) }}%）</span>
        </p>
      </div>

      <div v-if="phase === 'done' && lastTransfer" class="banner info">
        已发送：{{ lastTransfer.fileName }} → {{ lastTransfer.recipientCode }}
        <span class="tag ok">{{ lastTransfer.state || 'READY' }}</span>
        <div class="row" style="margin-top: 6px">
          <button type="button" @click="revoke">撤回（让对方取不到）</button>
        </div>
      </div>

      <p v-if="errorText" class="banner warn">{{ errorText }}</p>

      <div v-if="pending.length" class="stack">
        <hr />
        <h2 style="margin: 0">未完成的上传</h2>
        <p class="hint">
          刷新后能续传的前提是本机还留着会话快照（≤8 MiB 的密文包）；超过这个大小只能在当前页面里续。
        </p>
        <ul class="list">
          <li v-for="record in pending" :key="record.transferId">
            <div class="meta">
              {{ record.fileName }} · {{ fmtBytes(record.fileSize) }} → {{ record.recipientCode }}
              <span class="tag">{{ record.chunkCount }} 块</span>
              <span class="tag">{{ clock(new Date(record.createdAt).toISOString()) }}</span>
            </div>
            <div class="row" style="margin-top: 8px">
              <button type="button" :disabled="busy || !record.session" @click="resume(record)">
                {{ record.session ? '继续上传' : '本机无会话快照，请重发' }}
              </button>
            </div>
          </li>
        </ul>
      </div>

      <hr />
      <div class="row" style="justify-content: space-between">
        <label style="margin: 0">直传（WebRTC）</label>
        <span class="tag">待第二晚</span>
      </div>
      <p class="hint">本轮只做中转：打洞开关与提示留位，不做真实直连，也不会自动切换路径。</p>
    </div>
  </section>
</template>
