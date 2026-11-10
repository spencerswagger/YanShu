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
import { createSignaler } from './net/signal.js'
import { fetchStats } from './net/stats.js'
import { syncServerTime } from './lib/serverClock.js'
import { refreshExpiryClock } from './lib/expiryTicker.js'
import { createResponder } from './net/p2pResponder.js'
import { createDirectBuffer } from './net/p2pChunks.js'
import MyCodeCard from './components/MyCodeCard.vue'
import SendPanel from './components/SendPanel.vue'
import InboxPanel from './components/InboxPanel.vue'
import StatsCard from './components/StatsCard.vue'
import RecentList from './components/RecentList.vue'

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
const recentSends = ref([])
const platformStats = ref(null)
const safetyOpen = ref(false)
const successRate = computed(() => {
  const total = counts.sent + counts.received + counts.failed
  if (!total) return '—'
  return `${Math.round(((counts.sent + counts.received) / total) * 100)}%`
})
function focusSend() {
  sendRef.value?.focusDrop?.()
  document.querySelector('.col-main')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
function focusInbox() {
  inboxRef.value?.refresh?.()
  document.querySelector('.col-right')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
async function refreshRecent() {
  try {
    const all = (await pendingBackend.value?.all?.()) || []
    recentSends.value = all
      .filter((r) => r?.kind === 'send')
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
      .slice(0, 6)
  } catch {
    recentSends.value = []
  }
}

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
  return `加密组件与预期不一致（${why}）：结果暂不作为正式验收。`
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
      bootError.value = kernel.value.reason || '加密组件未就绪'
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
      // 用服务端时间基准初始化倒计时（Date 头或 server_time 都可）
      const dateHeader = cfg.headers?.get?.('date')
      syncServerTime(cfg.json?.server_time ? Date.parse(cfg.json.server_time) : dateHeader ? Date.parse(dateHeader) : Date.now())
      refreshExpiryClock() // 时间基准变了，TTL 的共享 tick 立刻重算
      info('已连接中转', { path: '/config', status: cfg.status })
    } catch (err) {
      const d = describeError(err)
      bootError.value = `连不上中转（${d.title}）。本地码已生成，但发不了也收不到。`
    }

    await ensureRegistered()
    await refreshRecent()
    // 全平台统计：失败静默降级（不显示该区块）
    platformStats.value = await fetchStats(client)
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
    await refreshRecent()
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
  // 接收侧直连（answerer）：有 ws_url 才起信令；任何失败都静默回落中转，下载本身不依赖它
  let signaler = null
  let responder = null
  const directBuffer = createDirectBuffer()
  const wsUrl = serverConfig.value?.ws_url || ''
  const stunUrls = serverConfig.value?.stun_urls || []
  if (wsUrl && stunUrls.length && api.value && kernel.value) {
    try {
      signaler = createSignaler({
        wsUrl,
        client: api.value.client,
        kernel: kernel.value,
        session: identityManager.value.session,
      })
      await signaler.open()
      if (signaler.authed) {
        responder = createResponder({
          signaler,
          transferId,
          selfCode: identityManager.value.session.code,
          peerCode: undefined, // 对端码以服务端帧里的 from_code 为准，这里不强校验
          stunUrls,
          buffer: directBuffer,
        })
      }
    } catch {
      signaler = null
      responder = null
    }
  }
  try {
    const r = await receiveTransfer({
      api: api.value,
      kernel: kernel.value,
      session: identityManager.value.session,
      transferId,
      senderPublic: fetchSenderPublic,
      onProgress,
      save: saveBlob,
      // 默认路径：流式边解边写（常量内存）；直连块也灌进同一个 sink
      sinkFactory: defaultSinkFactory,
      directBuffer,
    })
    counts.received += 1
    return r
  } catch (err) {
    counts.failed += 1
    throw err
  } finally {
    responder?.close()
    signaler?.close()
  }
}

</script>

<template>
  <div class="app-shell">
    <header class="app-top">
      <h1 class="brand">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M3 13c4.5 0 6-1.5 7.5-4C12 6 13 4 15 4c3 0 6 3 6 7s-3 7-6 7c-2 0-3-1-4.5-2.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
          <circle cx="16.4" cy="9.4" r="1.1" fill="var(--accent)" />
        </svg>
        雁书
      </h1>
      <button type="button" class="icon-btn" aria-label="安全说明" @click="safetyOpen = !safetyOpen">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6l-7-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" />
        </svg>
      </button>
    </header>

    <div v-if="booting" class="banner info">正在准备本机密钥与中转连接…</div>
    <div v-if="bootError" class="banner warn">{{ bootError }}</div>
    <div v-if="kernelMode === 'stub-fake'" class="banner warn">当前未加密，仅用于本地联调</div>
    <div v-if="regNotice" class="banner info">{{ regNotice }}</div>
    <div v-if="rekeyNotice" class="banner warn">{{ rekeyNotice }}</div>
    <div v-if="regError" class="banner warn">
      {{ regError }}
      <button type="button" class="icon-btn" style="margin-left: 8px" aria-label="重试" @click="ensureRegistered({ manual: true })">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v5h-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
    </div>

    <main class="grid">
      <aside class="col-left">
        <MyCodeCard
          :code="session.code"
          :nickname="session.nickname"
          :registered="session.registered"
          :real-crypto="realCrypto"
          :kernel-mode="kernelMode"
          :kernel-layout="kernelLayout"
          :save-nickname="saveNickname"
        />
        <StatsCard :sent="counts.sent" :received="counts.received" :rate="successRate" :platform="platformStats" />
        <div class="safety-line">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <rect x="5" y="10" width="14" height="10" rx="2" stroke="currentColor" stroke-width="1.6" />
            <path d="M8 10V7a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.6" />
          </svg>
          <button type="button" class="link-inline" @click="safetyOpen = !safetyOpen">端到端加密 · 私钥仅存本机</button>
        </div>
      </aside>

      <section class="col-main">
        <SendPanel
          ref="sendRef"
          :api="api"
          :kernel="kernel"
          :session="session"
          :send-file="doSend"
          :resume-send="doResume"
          :pending-backend="pendingBackend"
          :p2p-config="{ wsUrl: serverConfig?.ws_url || '', stunUrls: serverConfig?.stun_urls || [] }"
        />
      </section>

      <aside class="col-right">
        <InboxPanel ref="inboxRef" :api="api" :receive="doReceive" />
        <RecentList :items="recentSends" />
      </aside>
    </main>

    <div v-if="safetyOpen" class="safety-sheet" role="dialog" aria-label="安全说明" @click.self="safetyOpen = false">
      <div class="sheet-body">
        <div class="spread">
          <strong>安全说明</strong>
          <button type="button" class="icon-btn" aria-label="关闭" @click="safetyOpen = false">✕</button>
        </div>
        <dl>
          <dt>威胁模型</dt><dd>防传输被窃与服务器留底；不防对方截图转发。</dd>
          <dt>信任边界</dt><dd>服务器只见密文与 4 位码，不做指纹核对。</dd>
          <dt>私钥</dt><dd>只在本机，清除浏览器数据等于换人。</dd>
          <dt>码</dt><dd>只是寻址，先到先得。</dd>
        </dl>
      </div>
    </div>

    <nav class="bottom-bar">
      <button type="button" class="primary" @click="focusSend">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 12 20 4l-6 16-3-6-7-2Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" />
        </svg>
        发送文件
      </button>
      <button type="button" class="ghost" @click="focusInbox">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 4v10m0 0 4-4m-4 4-4-4M5 18h14" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        接收文件
      </button>
    </nav>
  </div>
</template>
