<script setup>
/**
 * 「你的接收码」卡片：码 + 昵称就地编辑。
 *
 * 昵称之前全站没有入口（后端 `PATCH /v1/codes/{code}` + 签名挑战都已实现，
 * `api.patchNickname()` 写好了但没人调用）。这里补上：
 *   POST /v1/challenges(purpose=NICKNAME_UPDATE) → 端侧 SM2 签名 → PATCH /v1/codes/{code}
 * 失败态必须能看出原因（挑战过期 / 昵称过长 / 其他），不许只显示"保存失败"。
 */
import { computed, ref } from 'vue'
import { copyText } from '../lib/save.js'

const NICK_MAX = 16

const props = defineProps({
  code: { type: String, default: '' },
  nickname: { type: String, default: '' },
  registered: { type: Boolean, default: false },
  realCrypto: { type: Boolean, default: false },
  kernelMode: { type: String, default: 'loading' },
  kernelLayout: { type: String, default: '' },
  /** 保存昵称：由 App 注入（内部走 api.patchNickname + 挑战过期自动重取一次） */
  saveNickname: { type: Function, required: true },
})

const editing = ref(false)
const draft = ref('')
const busy = ref(false)
const notice = ref(null) // { kind: 'ok' | 'bad', title, detail }
const copied = ref(false)

const display = computed(() => props.code || '——')
const draftLen = computed(() => [...draft.value].length)
const canSave = computed(() => draftLen.value > 0 && draftLen.value <= NICK_MAX && !busy.value)

function startEdit() {
  draft.value = props.nickname || ''
  notice.value = null
  editing.value = true
}

function cancelEdit() {
  editing.value = false
  notice.value = null
}

async function save() {
  if (busy.value) return
  const value = draft.value.trim()
  const len = [...value].length
  if (!len) {
    notice.value = { kind: 'bad', title: '昵称不能为空', detail: '请先输入昵称再保存。' }
    return
  }
  if (len > NICK_MAX) {
    notice.value = {
      kind: 'bad',
      title: '昵称过长',
      detail: `上限 ${NICK_MAX} 字符，当前 ${len}，请删减后保存。`,
    }
    return
  }
  busy.value = true
  notice.value = null
  try {
    const result = await props.saveNickname(value)
    editing.value = false
    notice.value = result?.retried
      ? { kind: 'ok', title: '昵称已更新', detail: '签名挑战曾过期，已自动重新获取并保存。' }
      : { kind: 'ok', title: '昵称已更新', detail: `对方将看到「${value}」。` }
  } catch (err) {
    if (err?.code === 'AUTH_CHALLENGE_INVALID' || err?.code === 'AUTH_CHALLENGE_EXPIRED') {
      notice.value = {
        kind: 'bad',
        title: '签名挑战已过期，已重新获取，请重试',
        detail: '挑战 60 秒有效，已自动重取一次；再点保存即可。',
      }
    } else if (
      err?.code === 'NICKNAME_INVALID' ||
      err?.code === 'NICKNAME_TOO_LONG' ||
      err?.code === 'BAD_REQUEST'
    ) {
      notice.value = {
        kind: 'bad',
        title: '昵称过长',
        detail: `上限 ${NICK_MAX} 字符，当前 ${len}，请删减后保存。`,
      }
    } else {
      notice.value = {
        kind: 'bad',
        title: '昵称未保存',
        detail: err?.message || '签名校验未通过，请重试。',
      }
    }
  } finally {
    busy.value = false
  }
}

async function copy() {
  if (!props.code) return
  await copyText(props.code)
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}
</script>

<template>
  <section class="card">
    <h2>你的接收码</h2>
    <div class="codebox">
      <div class="code">{{ display }}</div>
      <div v-if="code" class="check">校验 {{ kernelLayout === 'contract' ? 'X' : '—' }}</div>
    </div>

    <div class="row" style="margin-top: 6px">
      <button v-if="!editing" type="button" class="nick" :disabled="!code" @click="startEdit">
        <span>{{ nickname || '设置昵称' }}</span>
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M4 20h4l10-10-4-4L4 16v4Z"
            stroke="currentColor"
            stroke-width="1.6"
            stroke-linejoin="round"
          />
          <path d="M13.5 6.5 17.5 10.5" stroke="currentColor" stroke-width="1.6" />
        </svg>
      </button>
      <button type="button" class="sm" :disabled="!code" @click="copy">
        {{ copied ? '已复制' : '复制码' }}
      </button>
      <span v-if="!editing" class="hint" style="margin: 0; text-align: left">点昵称即可修改</span>
    </div>

    <div v-if="editing" class="nickedit">
      <div class="row" style="flex-wrap: nowrap">
        <input
          v-model="draft"
          type="text"
          :maxlength="NICK_MAX"
          aria-label="昵称"
          :disabled="busy"
          @keyup.enter="save"
        />
        <button type="button" class="primary" :disabled="!canSave" @click="save">
          {{ busy ? '保存中…' : '保存昵称' }}
        </button>
      </div>
      <div class="row" style="justify-content: space-between; margin-top: 6px">
        <small>{{ draftLen }} / {{ NICK_MAX }}</small>
        <button type="button" class="link" :disabled="busy" @click="cancelEdit">取消</button>
      </div>
    </div>

    <div v-if="notice" class="note" :class="notice.kind">
      <span class="t">{{ notice.title }}</span>{{ notice.detail }}
    </div>

    <p v-if="!registered" class="hint">正在向中转登记这个码…</p>
    <p v-else-if="kernelMode === 'stub-fake'" class="hint">开发桩（未加密），此码仅用于本地联调。</p>
    <p v-else-if="!realCrypto" class="hint">端侧加密内核未就绪，此码暂不可用于真实传输。</p>
    <p v-else-if="kernelLayout !== 'contract'" class="hint">当前内核非契约布局，结果不能作为 YSPK/1.0 验收。</p>
  </section>
</template>
