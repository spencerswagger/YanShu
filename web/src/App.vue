<script setup>
import { computed, onMounted, reactive, ref, shallowRef } from 'vue'
import { createKernel, describeKernel } from './crypto/index.js'
import { createClient } from './net/client.js'
import { createApi } from './net/api.js'
import { createIdentityManager } from './store/identity.js'
import { defaultBackend } from './store/db.js'
import { config } from './config.js'
import { sendFile, resumeSend } from './net/upload.js'
import { receiveTransfer } from './net/download.js'
import { describeError } from './net/errors.js'
import { updateNickname } from './net/nickname.js'
import { saveBlob } from './lib/save.js'
import { defaultSinkFactory } from './lib/saveStream.js'
import { decode as b64uDecode } from './lib/base64url.js'
import { info } from './lib/log.js'
import MyCodeCard from './components/MyCodeCard.vue'
import SendPanel from './components/SendPanel.vue'
import InboxPanel from './components/InboxPanel.vue'
import LogPanel from './components/LogPanel.vue'

const kernel = shallowRef(null)
const api = shallowRef(null)
const identityManager = shallowRef(null)
const pendingBackend = shallowRef(null)
const kernelMode = ref('loading')
const bootError = ref('')
const booting = ref(true)
const tab = ref('send')
const regBusy = ref(false)
const regError = ref('')
const regNotice = ref('')
const rekeyNotice = ref('')
const serverConfig = ref(null)
const kernelBuild = ref(null)
const kernelSelfTest = ref(null)
const kernelInfo = ref(describeKernel(null))
const manualAttempts = ref(0)
const inboxRef = ref(null)
/** 本次会话的真实计数（不做假数字）：成功发送 / 成功接收 / 失败 */
const counts = reactive({ sent: 0, received: 0, failed: 0 })

/** 模板用的会话镜像（身份对象在 identityManager 里是活的，撞码重生成时会换） */
const session = reactive({
  privateKey: null,
  publicKey: null,
  code: '',
  nickname: '',
  registered: false,
})

const realCrypto = computed(() => Boolean(kernel.value?.isRealCrypto))
const kernelLayout = computed(() => kernel.value?.layout || '')
/** 标签必须如实区分：契约布局 / 旧布局 / 桩 / 未就绪，别让人把旧布局当契约验收。 */
const kernelLabel = computed(() => kernelInfo.value?.label || '加载中')
const layoutFailed = computed(() => kernel.value?.layoutFailedSignals || [])
const layoutWarning = computed(() => {
  if (kernelMode.value !== 'wasm-noncontract') return ''
  const why = layoutFailed.value.length ? `未通过：${layoutFailed.value.join('、')}` : '自检未通过'
  return `当前内核未通过契约布局判据（${why}）：加密是真的，但结果不能作为 YSPK/1.0 契约的验收。`
})

function syncSession() {
  const s = identityManager.value?.session
  if (!s) return
  session.privateKey = s.privateKey
  session.publicKey = s.publicKey
  session.code = s.code
  session.nickname = s.nickname
  session.registered = s.registered
}

onMounted(async () => {
  try {
    kernel.value = await createKernel()
    kernelMode.value = kernel.value.mode
    if (!kernel.value.isRealCrypto && kernelMode.value !== 'stub-fake') {
      bootError.value = kernel.value.reason || '端侧加密内核（WASM）未就绪'
      booting.value = false
      return
    }

    if (kernel.value.mode === 'wasm') {
      // 标签的事实依据：真跑一遍打包→解包 + 版本闸门（契约 §2.3）
      kernelSelfTest.value = kernel.value.selfTest()
    }
    kernelInfo.value = describeKernel(kernel.value, kernelSelfTest.value)
    kernelMode.value = kernelInfo.value.mode

    pendingBackend.value = defaultBackend('pending')
    identityManager.value = createIdentityManager({
      kernel: kernel.value,
      backend: defaultBackend('identity'),
    })
    await identityManager.value.loadOrCreate()
    syncSession()
    if (identityManager.value.session.rekeyed) {
      rekeyNotice.value = '本机码已按当前内核重新派生（旧码作废），请重新告知对方新码。'
    }

    // 内核构建溯源（由 `npm run wasm:rebuild` 写入 public/ys_kernel.build.json）
    try {
      const res = await fetch('/ys_kernel.build.json', { cache: 'no-cache' })
      if (res.ok) kernelBuild.value = await res.json()
    } catch {
      kernelBuild.value = null
    }

    const client = createClient({ baseUrl: config.apiBase })
    api.value = createApi({ client, kernel: kernel.value, session: identityManager.value.session })

    try {
      const cfg = await client.get('/config', { retry: true })
      serverConfig.value = cfg.json
      info('已连接中转', { path: '/config', status: cfg.status })
    } catch (err) {
      const d = describeError(err)
      bootError.value = `连不上中转（${d.title}）。本地码已生成，但发不了也收不到。`
    }

    await ensureRegistered()
  } catch (err) {
    const d = describeError(err)
    bootError.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
  } finally {
    booting.value = false
  }
})

async function ensureRegistered({ manual = false } = {}) {
  if (!api.value || !identityManager.value) return
  if (manual && manualAttempts.value >= 8) {
    regError.value = '已经试了 8 次，先歇一会儿再试（契约上限 8 次）。'
    return
  }
  regBusy.value = true
  regError.value = ''
  if (manual) manualAttempts.value += 1
  try {
    if (identityManager.value.session.registered) {
      try {
        await api.value.getCode(identityManager.value.session.code)
        syncSession()
        return
      } catch (err) {
        if (err.code !== 'CODE_NOT_FOUND') throw err
        // 中转不认这个码了（例如本地中转重启）：用同一对密钥重登记
        identityManager.value.session.registered = false
      }
    }
    const result = await identityManager.value.register({
      api: api.value,
      autoRetries: manual ? 0 : config.autoCodeRetries,
      nickname: identityManager.value.session.nickname || `雁${identityManager.value.session.code}`,
    })
    if (result.collisions > 0) {
      regNotice.value = `码被占用，已自动换密钥对重试 ${result.collisions} 次（新码 ${identityManager.value.session.code}）`
    }
    syncSession()
  } catch (err) {
    const d = describeError(err)
    regError.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
  } finally {
    regBusy.value = false
  }
}

/**
 * 保存昵称：`PATCH /v1/codes/{code}`（内部走签名挑战）。
 * 挑战过期（AUTH_CHALLENGE_INVALID）自动重取一次再试，仍失败就把错误交给界面显示原因。
 */
async function saveNickname(nickname) {
  if (!api.value || !identityManager.value) throw new Error('中转未连接')
  const result = await updateNickname({
    api: api.value,
    identity: identityManager.value,
    nickname,
  })
  syncSession()
  info('昵称已更新', { code: identityManager.value.session.code, retried: result.retried })
  return result
}

async function doSend({ file, recipient, onProgress, signal }) {
  try {
    const r = await sendFile({
      api: api.value,
      kernel: kernel.value,
      session: identityManager.value.session,
      file,
      recipient,
      onProgress,
      signal,
      pendingStore: pendingBackend.value,
    })
    counts.sent += 1
    return r
  } catch (err) {
    counts.failed += 1
    throw err
  }
}

async function doResume({ record }) {
  return resumeSend({
    api: api.value,
    kernel: kernel.value,
    session: identityManager.value.session,
    record,
    pendingStore: pendingBackend.value,
  })
}

/** 内核当前把发送方公钥当入参（契约要求公钥在包内）：先从码取，再验签。 */
const senderPublicCache = new Map()
async function fetchSenderPublic(code) {
  if (senderPublicCache.has(code)) return senderPublicCache.get(code)
  const json = await api.value.getCode(code)
  const pub = b64uDecode(json.public_key)
  senderPublicCache.set(code, pub)
  return pub
}

async function doReceive({ transferId, onProgress }) {
  try {
    const r = await receiveTransfer({
      api: api.value,
      kernel: kernel.value,
      session: identityManager.value.session,
      transferId,
      senderPublic: fetchSenderPublic,
      onProgress,
      save: saveBlob,
      sinkFactory: defaultSinkFactory,
    })
    counts.received += 1
    return r
  } catch (err) {
    counts.failed += 1
    throw err
  }
}
</script>

<template>
  <div class="app-top">
    <h1 class="brand">
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path
          d="M3 13c4.5 0 6-1.5 7.5-4C12 6 13 4 15 4c3 0 6 3 6 7s-3 7-6 7c-2 0-3-1-4.5-2.5"
          stroke="currentColor"
          stroke-width="1.6"
          stroke-linecap="round"
        />
        <circle cx="16.4" cy="9.4" r="1.1" fill="var(--accent)" />
      </svg>
      雁书
    </h1>
    <span class="tag">{{ kernelLabel }}</span>
  </div>

  <p class="lede">你的接收码，告知对方即可收文件。<em>私钥不出本机</em></p>

  <div v-if="booting" class="banner info">正在准备本机密钥与中转连接…</div>

  <div v-if="bootError" class="banner warn">
    {{ bootError }}
    <div class="hint" style="margin-top: 6px; text-align: left">
      加密内核未到位时不会伪造“加密成功”，所有加密操作都会如实报错。
    </div>
  </div>

  <div v-if="layoutWarning" class="banner warn">{{ layoutWarning }}</div>

  <div v-if="kernelMode === 'stub-fake'" class="banner warn">
    开发桩模式：<strong>数据没有加密</strong>，只用于打通界面与传输流程，禁止传真实文件。
  </div>

  <div v-if="regNotice" class="banner info">{{ regNotice }}</div>
  <div v-if="rekeyNotice" class="banner warn">{{ rekeyNotice }}</div>
  <div v-if="regError" class="banner warn">
    {{ regError }}
    <div class="row" style="margin-top: 8px">
      <button type="button" :disabled="regBusy" @click="ensureRegistered({ manual: true })">
        {{ regBusy ? '重试中…' : '重试' }}
      </button>
    </div>
  </div>

  <MyCodeCard
    :code="session.code"
    :nickname="session.nickname"
    :registered="session.registered"
    :real-crypto="realCrypto"
    :kernel-mode="kernelMode"
    :kernel-layout="kernelLayout"
    :save-nickname="saveNickname"
  />

  <section class="card">
    <h2>选择操作</h2>
    <button type="button" class="primary block lg" @click="tab = 'send'">发送文件</button>
    <button
      type="button"
      class="block"
      style="margin-top: 8px; min-height: 44px"
      @click="tab = 'inbox'"
    >
      接收文件
    </button>
  </section>

  <section v-show="tab === 'send'" class="screen" :class="{ on: tab === 'send' }">
    <SendPanel
      ref="sendRef"
      :api="api"
      :kernel="kernel"
      :session="session"
      :send-file="doSend"
      :resume-send="doResume"
      :pending-backend="pendingBackend"
    />
  </section>

  <section v-show="tab === 'inbox'" class="screen" :class="{ on: tab === 'inbox' }">
    <InboxPanel ref="inboxRef" :api="api" :receive="doReceive" />
  </section>

  <section class="card">
    <h2>今日已完成 {{ counts.sent + counts.received }} 次</h2>
    <div class="stats">
      <div class="stat"><b>{{ counts.sent }}</b><span>已发送</span></div>
      <div class="stat"><b>{{ counts.received }}</b><span>已接收</span></div>
      <div class="stat"><b>{{ counts.failed }}</b><span>失败</span></div>
    </div>
    <p class="hint">仅统计本次打开页面的真实操作</p>
  </section>

  <LogPanel />

  <details class="safety">
    <summary><span class="ug"></span>端到端加密，私钥仅存于本机浏览器 · 安全说明</summary>
    <div class="body">
      <dl>
        <dt>威胁模型</dt>
        <dd>防范传输途中被窃取与服务器留底；不防范接收方主动截图或转发。</dd>
        <dt>信任边界</dt>
        <dd>服务器仅见密文与 4 位码，但未做指纹核对，理论上可被替换代码。</dd>
        <dt>私钥不备份</dt>
        <dd>私钥仅存本机（IndexedDB），清除浏览器数据即等同于更换身份，无法找回。</dd>
        <dt>码不是密码</dt>
        <dd>4 位码仅用于寻址，先到先得；敏感文件请另行约定。</dd>
      </dl>
    </div>
  </details>

  <details class="footer">
    <summary>内核与中转信息</summary>
    <p v-if="kernelSelfTest">
      内核自检（契约 §2.3 四条）：{{ kernelSelfTest.ok ? '版本 / 包头 / V1 样例解包 / 版本闸门 全过' : '未通过 → ' + Object.entries(kernelSelfTest.checks).filter(([, v]) => !v).map(([k]) => k).join('、') }}
    </p>
    <p v-if="kernelBuild">
      端侧内核：commit {{ kernelBuild.commit.slice(0, 7) }} · {{ kernelBuild.ysVersion }} · HEADER
      {{ kernelBuild.headerLen }} · {{ kernelBuild.exports }} 导出 / {{ kernelBuild.imports }} import ·
      sha256 {{ kernelBuild.sha256.slice(0, 12) }}…
    </p>
    <p v-else-if="realCrypto">端侧内核来源未记录（未找到 ys_kernel.build.json）。</p>
    <p v-if="serverConfig">
      中转：{{ config.apiBase }} · 包版本 {{ serverConfig.crypto_pack_version }} · 块
      {{ serverConfig.chunk_size }} 字节
    </p>
  </details>
</template>
