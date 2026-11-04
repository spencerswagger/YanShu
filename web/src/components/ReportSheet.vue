<script setup>
/**
 * 举报某个待收文件（契约 §11.5）：入口只在"查看某个文件"的卡片里，收成一个次要文字动作，
 * 不放到首屏主流程、不弹窗打扰。
 *
 * 交互：点「举报」→ 底部弹层选原因（四选一）+ 可选备注 → 提交 → 成功一句提示 → 关闭。
 * 幂等：同一 (举报人, 传输) 重复提交，服务端返回**同一个** `report_id`，界面按成功处理、不报错。
 */
import { computed, ref } from 'vue'
import { describeError } from '../net/errors.js'

const REASONS = [
  { value: 'ABUSE', label: '骚扰或辱骂' },
  { value: 'CSAM', label: '涉及未成年人' },
  { value: 'MALWARE', label: '疑似恶意软件' },
  { value: 'OTHER', label: '其他原因' },
]
const NOTE_MAX = 200

const props = defineProps({
  api: { type: Object, default: null },
  transferId: { type: String, default: '' },
  iconOnly: { type: Boolean, default: false },
})

const open = ref(false)
const reason = ref('ABUSE')
const note = ref('')
const busy = ref(false)
const result = ref(null) // { kind: 'ok' | 'bad', text }

const noteLen = computed(() => [...note.value].length)
const canSubmit = computed(() => Boolean(props.api && props.transferId && reason.value) && !busy.value)

function start() {
  open.value = true
  result.value = null
}

function close() {
  open.value = false
  busy.value = false
}

/** 把失败翻成人话：四类常见错误各一句，其余走统一文案。 */
function humanError(err) {
  const code = err?.code || ''
  if (code === 'AUTH_CODE_MISMATCH') return '签名里的码与请求不一致，请刷新页面后重试'
  if (code === 'AUTH_SIGNATURE_INVALID') return '签名校验未通过，请刷新页面后重试'
  if (err?.status === 429) {
    const wait = Number(err.retryAfter) || 0
    return wait > 0 ? `请求过于频繁，请 ${wait} 秒后再试` : '请求过于频繁，请稍后再试'
  }
  const d = describeError(err)
  return `${d.title}${d.hint ? '：' + d.hint : ''}`
}

async function submit() {
  if (!canSubmit.value) return
  busy.value = true
  result.value = null
  try {
    const json = await props.api.reportTransfer({
      transferId: props.transferId,
      reason: reason.value,
      note: note.value.trim() || undefined,
    })
    result.value = { kind: 'ok', text: `已记录，我们会处理（编号 ${json.report_id}）` }
    note.value = ''
  } catch (err) {
    result.value = { kind: 'bad', text: humanError(err) }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="report">
    <button
      v-if="iconOnly"
      type="button"
      class="icon-btn"
      aria-label="举报"
      @click="start"
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M6 21V4h10l-1.5 4L16 12H6" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" />
      </svg>
    </button>
    <button v-else type="button" class="link" @click="start">举报</button>

    <div v-if="open" class="sheet-mask" @click.self="close">
      <div class="sheet" role="dialog" aria-label="举报此文件">
        <h2>举报此文件</h2>
        <div class="reasons">
          <label v-for="r in REASONS" :key="r.value" class="reason">
            <input v-model="reason" type="radio" name="reason" :value="r.value" />
            <span>{{ r.label }}</span>
          </label>
        </div>
        <label for="report-note">备注（可选）</label>
        <input
          id="report-note"
          v-model="note"
          type="text"
          :maxlength="NOTE_MAX"
          placeholder="补充说明，可留空"
        />
        <div class="row" style="justify-content: space-between; margin-top: 6px">
          <small>{{ noteLen }} / {{ NOTE_MAX }}</small>
        </div>

        <div v-if="result" class="note" :class="result.kind">{{ result.text }}</div>

        <div class="row" style="margin-top: 12px">
          <button type="button" class="primary" :disabled="!canSubmit" @click="submit">
            {{ busy ? '提交中…' : '提交举报' }}
          </button>
          <button type="button" @click="close">取消</button>
        </div>
        <p class="hint">举报只做记录，不会删除对方文件，也不会改变传输状态。</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.report {
  margin-top: 8px;
}
.sheet-mask {
  position: fixed;
  inset: 0;
  background: #00000066;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  z-index: 50;
}
.sheet {
  width: 100%;
  max-width: 430px;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 18px 18px 0 0;
  padding: 16px;
  box-shadow: 0 -12px 32px -20px #00000088;
}
.sheet h2 {
  margin: 0 0 10px;
}
.reasons {
  display: grid;
  gap: 6px;
  margin-bottom: 10px;
}
.reason {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 44px;
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 0 12px;
  margin: 0;
  font-size: 0.95rem;
  color: var(--ink);
}
.note {
  margin-top: 10px;
  border-radius: 12px;
  padding: 10px 12px;
  font-size: 0.9rem;
}
.note.ok {
  background: var(--info-bg);
  color: var(--info-ink);
}
.note.bad {
  background: var(--warn-bg);
  color: var(--warn-ink);
}
</style>
