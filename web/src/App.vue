<script setup>
import { computed, onMounted, reactive, ref, shallowRef } from 'vue'
import { createKernel } from './crypto/index.js'
import { createClient } from './net/client.js'
import { createApi } from './net/api.js'
import { createIdentityManager } from './store/identity.js'
import { defaultBackend } from './store/db.js'
import { config } from './config.js'
import { sendFile, resumeSend } from './net/upload.js'
import { receiveTransfer } from './net/download.js'
import { describeError } from './net/errors.js'
import { saveBlob } from './lib/save.js'
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
const serverConfig = ref(null)
const manualAttempts = ref(0)
const inboxRef = ref(null)

/** 模板用的会话镜像（身份对象在 identityManager 里是活的，撞码重生成时会换） */
const session = reactive({
  privateKey: null,
  publicKey: null,
  code: '',
  nickname: '',
  registered: false,
})

const realCrypto = computed(() => Boolean(kernel.value?.isRealCrypto))
const kernelLabel = computed(() => {
  if (kernelMode.value === 'wasm') return '真内核（YSPK/1.0）'
  if (kernelMode.value === 'stub-fake') return '开发桩（未加密）'
  if (kernelMode.value === 'unavailable') return '内核未就绪'
  return '加载中'
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

    pendingBackend.value = defaultBackend('pending')
    identityManager.value = createIdentityManager({
      kernel: kernel.value,
      backend: defaultBackend('identity'),
    })
    await identityManager.value.loadOrCreate()
    syncSession()

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

async function doSend({ file, recipient, onProgress, signal }) {
  return sendFile({
    api: api.value,
    kernel: kernel.value,
    session: identityManager.value.session,
    file,
    recipient,
    onProgress,
    signal,
    pendingStore: pendingBackend.value,
  })
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
  return receiveTransfer({
    api: api.value,
    kernel: kernel.value,
    session: identityManager.value.session,
    transferId,
    senderPublic: fetchSenderPublic,
    onProgress,
    save: saveBlob,
  })
}
</script>

<template>
  <header>
    <h1>雁书</h1>
    <p class="hint">
      一次性加密文件互传：端侧加密 → 中转只存密文 → 对方端侧解密。
      <span class="tag">{{ kernelLabel }}</span>
    </p>
  </header>

  <div v-if="booting" class="banner info">正在准备本机密钥与中转连接…</div>

  <div v-if="bootError" class="banner warn">
    {{ bootError }}
    <div class="hint" style="margin-top: 6px">
      加密内核没到位时，页面不会伪造"加密成功"：所有加密操作都会如实报错。
    </div>
  </div>

  <div v-if="kernelMode === 'stub-fake'" class="banner warn">
    开发桩模式：<strong>数据没有加密</strong>（可逆异或 + 明文密钥），只用于打通 UI 与传输流程，
    禁止传真实文件。生产构建里这个模式会被拒绝。
  </div>

  <div v-if="regNotice" class="banner info">{{ regNotice }}</div>
  <div v-if="regError" class="banner warn">
    {{ regError }}
    <div class="row" style="margin-top: 8px">
      <button type="button" :disabled="regBusy" @click="ensureRegistered({ manual: true })">
        {{ regBusy ? '重试中…' : '再试一次' }}
      </button>
    </div>
  </div>

  <MyCodeCard
    :code="session.code"
    :nickname="session.nickname"
    :registered="session.registered"
    :real-crypto="realCrypto"
    :kernel-mode="kernelMode"
  />

  <div class="tabs" role="tablist">
    <button type="button" role="tab" :aria-selected="tab === 'send'" @click="tab = 'send'">发文件</button>
    <button type="button" role="tab" :aria-selected="tab === 'inbox'" @click="tab = 'inbox'">待收</button>
  </div>

  <SendPanel
    v-show="tab === 'send'"
    ref="sendRef"
    :api="api"
    :kernel="kernel"
    :session="session"
    :send-file="doSend"
    :resume-send="doResume"
    :pending-backend="pendingBackend"
  />

  <InboxPanel v-show="tab === 'inbox'" ref="inboxRef" :api="api" :receive="doReceive" />

  <LogPanel />

  <footer class="hint" style="margin-top: 18px">
    <p v-if="serverConfig">
      中转：{{ config.apiBase }} · 包版本 {{ serverConfig.crypto_pack_version }} · 块
      {{ serverConfig.chunk_size }} 字节
    </p>
    <p>
      私钥只在本机浏览器（IndexedDB），不上传、不备份；清缓存等于换人。
      服务器可信，但它看不到文件名与明文。
    </p>
  </footer>
</template>
