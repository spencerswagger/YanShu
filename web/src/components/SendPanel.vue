<script setup>
import { computed, reactive, ref } from 'vue'
import { decode as b64uDecode } from '../lib/base64url.js'
import { describeError } from '../net/errors.js'
import { bytes as fmtBytes, percent, clock } from '../lib/format.js'
import { createSignaler } from '../net/signal.js'
import { config } from '../config.js'

const props = defineProps({
  api: { type: Object, default: null },
  kernel: { type: Object, default: null },
  session: { type: Object, required: true },
  sendFile: { type: Function, required: true },
  resumeSend: { type: Function, required: true },
  pendingBackend: { type: Object, default: null },
  /** 服务端下发的直连配置：{ wsUrl, stunUrls }；ws_url 为空则不尝试打洞 */
  p2pConfig: { type: Object, default: null },
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

/**
 * 直连状态：默认中转（体验不变）；打洞只在后台静默尝试，打通后由用户点一下才切。
 * 失败/超时一律回到 idle，不弹错——中转本来就是默认路径。
 */
const direct = reactive({ status: 'idle', enable: null, notice: '' })
const canSwitchDirect = computed(() => direct.status === 'ready' && typeof direct.enable === 'function')

function switchDirect() {
  if (!canSwitchDirect.value) return
  direct.enable()
  direct.status = 'direct'
  direct.notice = '已切换直连，剩余块走点对点'
}

/** 进度格：按"计划块数"画（服务端块 1 MiB），最多 12 格，避免长文件画几百个方块 */
const chunkTotal = computed(() => {
  if (!file.value) return 0
  return Math.min(12, Math.max(1, Math.ceil(file.value.size / config.chunkSize)))
})
const chunkDone = computed(() => {
  const pctv = percent(progress.value.done, progress.value.total)
  if (phase.value === 'done') return chunkTotal.value
  return Math.floor((pctv / 100) * chunkTotal.value)
})
const pct = computed(() => percent(progress.value.done, progress.value.total))

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
  let signaler = null
  const wsUrl = props.p2pConfig?.wsUrl || ''
  const stunUrls = props.p2pConfig?.stunUrls || []
  if (wsUrl && stunUrls.length) {
    // 打洞是"锦上添花"：连不上信令也照常走中转
    try {
      signaler = createSignaler({
        wsUrl,
        client: props.api.client,
        kernel: props.kernel,
        session: props.session,
      })
      direct.status = 'trying'
      await signaler.open()
    } catch {
      signaler = null
      direct.status = 'idle'
    }
  }
  try {
    const result = await props.sendFile({
      file: file.value,
      recipient: recipient.value,
      onProgress: (p) => {
        phase.value = p.phase
        progress.value = { done: p.done, total: p.total, message: p.message }
      },
      signal: abort.value.signal,
      p2p: signaler
        ? {
            signaler,
            stunUrls,
            onStatus: (status) => {
              if (status === 'direct') direct.status = 'direct'
              else if (status === 'fallback') {
                direct.status = 'fallback'
                direct.notice = '直连已断开，已回到中转继续'
              } else direct.status = 'idle'
            },
            onCandidate: ({ enable }) => {
              direct.enable = enable
              direct.status = 'ready'
            },
          }
        : null,
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
    signaler?.close()
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
    <h2>{{ phase === 'done' ? '已发送，等待对方接收' : phase === 'packing' || phase === 'uploading' ? '加密并上传中' : '发送文件' }}</h2>

    <div class="stack">
      <div>
        <label for="peer">输入对方接收码</label>
        <div class="row" style="flex-wrap: nowrap">
          <input
            id="peer"
            v-model="codeInput"
            type="text"
            inputmode="text"
            autocapitalize="characters"
            autocomplete="off"
            placeholder="如 AWQW"
            :disabled="busy"
            @blur="lookup"
          />
          <button type="button" class="sm" :disabled="!normalized || busy" @click="lookup">
            查询接收方
          </button>
        </div>
        <p v-if="codeHint" class="hint" style="text-align: left">{{ codeHint }}</p>
        <p v-if="lookupError" class="meta" style="color: var(--warn-ink)">{{ lookupError }}</p>
      </div>

      <div v-if="recipient" class="confirm">
        <div class="avatar">{{ (recipient.nickname || recipient.code).slice(0, 1) }}</div>
        <div>
          <b>{{ recipient.nickname }}</b>
          <div class="meta" style="font-family: ui-monospace, monospace">{{ recipient.code }}</div>
        </div>
      </div>

      <div>
        <label for="file">选择文件</label>
        <input id="file" type="file" :disabled="busy" @change="pickFile" />
        <div v-if="file" class="file" style="margin-top: 8px">
          <div class="meta">
            <b>{{ file.name }}</b>
            <div class="meta">{{ fmtBytes(file.size) }} · {{ chunkTotal }} 块</div>
          </div>
        </div>
      </div>

      <button
        type="button"
        class="primary block lg"
        :disabled="!file || !recipient || busy"
        @click="send"
      >
        {{ busy ? '发送中…' : '发送文件' }}
      </button>
      <button v-if="busy" type="button" class="block" style="min-height: 44px" @click="cancel">
        取消
      </button>

      <div v-if="phase !== 'idle' && phase !== 'done'">
        <div class="progress"><span :style="{ width: pct + '%' }" /></div>
        <div class="spread">
          <div class="pct">{{ pct }}%</div>
          <div class="meta">{{ progress.message }}</div>
        </div>
        <div v-if="chunkTotal" class="chunks">
          <i
            v-for="n in chunkTotal"
            :key="n"
            :class="{ done: n <= chunkDone, busy: n === chunkDone + 1 }"
          />
        </div>
      </div>

      <div v-if="canSwitchDirect || direct.notice" class="banner info">
        <span v-if="direct.notice">{{ direct.notice }}</span>
        <span v-else>当前链路已可直连，切换后剩余块不再经过中转。</span>
        <div v-if="canSwitchDirect" class="row" style="margin-top: 6px">
          <button type="button" class="sm" @click="switchDirect">改用直连，速度更快</button>
        </div>
      </div>

      <div v-if="phase === 'done' && lastTransfer" class="done">
        <svg class="seal" viewBox="0 0 64 64" aria-hidden="true" fill="none">
          <circle cx="32" cy="32" r="27" stroke-width="2.5" />
          <path
            d="M20 33.5 28.5 42 45 24"
            stroke-width="3.4"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
        <div style="font-weight: 700">已发送，等待对方接收</div>
        <div class="meta" style="margin-top: 2px">
          码 <b style="font-family: ui-monospace, monospace">{{ lastTransfer.recipientCode }}</b> ·
          24 小时后自动删除
        </div>
        <div class="row" style="margin-top: 10px; justify-content: center">
          <button type="button" class="sm" @click="revoke">撤回传输</button>
        </div>
      </div>

      <p v-if="errorText" class="banner warn">{{ errorText }}</p>

      <div v-if="pending.length" class="stack">
        <hr />
        <h2 style="margin: 0">未完成的上传 {{ pending.length }} 个</h2>
        <ul class="list">
          <li v-for="record in pending" :key="record.transferId">
            <div class="meta">
              {{ record.fileName }} · {{ fmtBytes(record.fileSize) }} → {{ record.recipientCode }}
              <span class="tag">{{ record.chunkCount }} 块</span>
              <span class="tag">{{ clock(new Date(record.createdAt).toISOString()) }}</span>
            </div>
            <div class="row" style="margin-top: 8px">
              <button
                type="button"
                class="sm"
                :disabled="busy || !record.session"
                @click="resume(record)"
              >
                {{ record.session ? '继续上传' : '本机无会话快照，请重发' }}
              </button>
            </div>
          </li>
        </ul>
      </div>
    </div>
  </section>
</template>
