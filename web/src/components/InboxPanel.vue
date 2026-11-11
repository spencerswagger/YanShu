<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { describeError } from '../net/errors.js'
import { bytes as fmtBytes, percent } from '../lib/format.js'
import { createSpeedMeter, stageLabel } from '../lib/speed.js'
import { isExpired, remainingMs } from '../lib/serverClock.js'
import { expiryNow, refreshExpiryClock } from '../lib/expiryTicker.js'
import { createPoller } from '../lib/poller.js'
import ReportSheet from './ReportSheet.vue'
import SpeedLine from './SpeedLine.vue'
import TtlPill from './TtlPill.vue'

const props = defineProps({
  api: { type: Object, default: null },
  receive: { type: Function, required: true },
})

const items = ref([])
const loading = ref(false)
const errorText = ref('')
const notice = ref('')
const activeId = ref('')
const progress = ref({ phase: '', done: 0, total: 0, decrypted: null, message: '', verified: false, meta: null })
/** 接收侧速度表：只吃真实字节进度（下载中），解密的最终校验没有增量、不编百分比 */
const rxSpeed = ref({ speedBps: 0, etaSec: null, state: 'ok' })
const rxMeter = createSpeedMeter()

/** S3 两段：`下载中 62%` / `解密中`（最终验签没有增量进度，故不给假百分比） */
const stageText = computed(() =>
  stageLabel(progress.value.phase, progress.value.done, progress.value.total, progress.value.decrypted),
)

/**
 * `quiet` = 后台自动刷新：不转圈、不清错误（避免每 8 秒闪一下把用户正在看的提示抹掉）。
 * 手动点「刷新」才清错误并显示 loading。
 */
async function refresh({ quiet = false } = {}) {
  if (!props.api) return false
  if (quiet && activeId.value) return false // 正在下载时不打扰（进度那条不能被列表刷新打断）
  if (!quiet) {
    loading.value = true
    errorText.value = ''
  }
  try {
    const res = await props.api.inbox({ state: 'ready', limit: 20 })
    items.value = res?.items || []
  } catch (err) {
    if (!quiet) {
      const d = describeError(err)
      errorText.value = `${d.title}${d.hint ? '：' + d.hint : ''}`
    }
  } finally {
    if (!quiet) loading.value = false
  }
  return true
}

/**
 * 自动刷新：v0.2.4 的缺陷是「必须手点刷新才看得到待收文件」（16 MiB / 1 GiB 都复现）。
 * 可见时 8 秒一轮、后台 30 秒一轮，切回页面立刻补一次；`lastSyncText` 让用户知道列表是活的。
 */
const lastSync = ref(0)
/** 「多久没有新进展」——v0.2.4 的教训：页面纯静默转圈 10 分钟，用户/测试都以为在下载 */
const lastProgressAt = ref(0)
const stallSec = ref(0)
/** 「自动更新 hh:mm:ss」里的"刚刚"要自己会老化，否则一次渲染后 15 秒还写"刚刚" */
const nowTick = ref(Date.now())
const lastSyncText = computed(() => {
  if (!lastSync.value) return ''
  const d = new Date(lastSync.value)
  const p = (n) => String(n).padStart(2, '0')
  void nowTick.value
  const fresh = Date.now() - lastSync.value < 15000
  return `${fresh ? '自动更新' : '上次更新'} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
})

const poller = createPoller({
  task: () => refresh({ quiet: true }),
  intervalMs: 8000,
  hiddenMs: 30000,
  onRun: (t) => {
    lastSync.value = t
  },
})
const onVisible = () => {
  if (!document.hidden) poller.kick()
}
const onFocus = () => poller.kick()

async function take(item) {
  // 兜底：万一定时器被节流没翻，这里按 serverClock 再判一次，直接置成过期态、不发请求（别去吃 410）
  if (isExpiredItem(item)) {
    refreshExpiryClock()
    return
  }
  activeId.value = item.transfer_id
  lastProgressAt.value = Date.now()
  stallSec.value = 0
  errorText.value = ''
  notice.value = ''
  rxMeter.reset()
  rxSpeed.value = { speedBps: 0, etaSec: null, state: 'ok' }
  try {
    const result = await props.receive({
      transferId: item.transfer_id,
      onProgress: (p) => {
        lastProgressAt.value = Date.now()
        progress.value = {
          phase: p.phase || '',
          done: p.done || 0,
          total: p.total || 0,
          decrypted: Number.isFinite(p.decrypted) ? p.decrypted : null,
          message: p.message || '',
          verified: Boolean(p.verified),
          meta: p.meta || progress.value.meta,
        }
        if (p.phase === 'downloading') {
          rxSpeed.value = rxMeter.update(p.done || 0, p.total || 0)
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
    progress.value = { phase: '', done: 0, total: 0, decrypted: null, message: '', verified: false, meta: null }
    rxMeter.reset()
  }
}

/** 过期项：整行灰化 + 下载置灰；时间来自共享的单一定时器（与胶囊同一帧翻），不碰本机时钟 */
const now = expiryNow()
function isExpiredItem(item) {
  void now.value // 依赖共享 tick：到点后行与胶囊同帧重渲染
  return Boolean(item.expires_at) && isExpired(remainingMs(item.expires_at))
}

function focusDrop() {
  document.querySelector('.col-main .drop')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
}

defineExpose({ refresh })
// api 由父层在内核/身份就绪后才注入：首屏拿不到 api 时必须等它到场再拉列表，
// 否则「待收列表」首屏永远是空的（点刷新才出现）。
watch(
  () => props.api,
  (api) => {
    if (api) refresh()
  },
  { immediate: true },
)

const stallTimer = setInterval(() => {
  nowTick.value = Date.now()
  stallSec.value = lastProgressAt.value ? Math.max(0, Math.floor((Date.now() - lastProgressAt.value) / 1000)) : 0
}, 5000)

onMounted(() => {
  poller.start()
  document.addEventListener('visibilitychange', onVisible)
  window.addEventListener('focus', onFocus)
})
onUnmounted(() => {
  clearInterval(stallTimer)
  poller.stop()
  document.removeEventListener('visibilitychange', onVisible)
  window.removeEventListener('focus', onFocus)
})
</script>

<template>
  <section class="card">
    <div class="spread" style="margin-bottom: 10px">
      <div class="card-title">{{ items.length ? `${items.length} 个文件待接收` : '暂无待接收文件' }}</div>
      <button type="button" class="icon-btn" :disabled="loading" aria-label="刷新" @click="refresh()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v5h-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
    </div>

    <p v-if="lastSyncText && !errorText" class="meta sync">{{ lastSyncText }}（新文件会自动出现在这里）</p>
    <p v-if="activeId && stallSec >= 30" class="banner warn">
      已 {{ stallSec }} 秒没有新进展 —— 不是卡在「已保存」，本次仍在进行；若持续不动可刷新后重试（服务端不会删未确认的密文）。
    </p>
    <p v-if="notice" class="banner info">{{ notice }}</p>
    <p v-if="errorText" class="banner warn">{{ errorText }}</p>

    <ul v-if="items.length" class="rlist">
      <li v-for="item in items" :key="item.transfer_id" class="ritem row-72" :class="{ expired: isExpiredItem(item) }">
        <div class="who">
          <div class="avatar">{{ (item.sender_nickname || item.sender_code || '?').slice(0, 1) }}</div>
          <div>
            <div class="rname">{{ item.sender_nickname || item.sender_code }}</div>
            <div class="meta">
              {{ fmtBytes(item.plaintext_size) }} · {{ item.chunk_count }} 块
              <TtlPill v-if="item.expires_at" :expires-at="item.expires_at" />
            </div>
          </div>
        </div>
        <button
          type="button"
          class="icon-btn lg"
          :disabled="activeId === item.transfer_id || isExpiredItem(item)"
          :aria-label="activeId === item.transfer_id ? '解密中' : '下载并解密'"
          @click="take(item)"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M12 4v10m0 0 4-4m-4 4-4-4M5 18h14" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </button>
        <ReportSheet :api="api" :transfer-id="item.transfer_id" icon-only />
        <div v-if="activeId === item.transfer_id" class="row-progress">
          <div v-if="stageText" class="meta stage">{{ stageText }}</div>
          <SpeedLine
            v-if="progress.phase === 'downloading'"
            :speed-bps="rxSpeed.speedBps"
            :eta-sec="rxSpeed.etaSec"
            :state="rxSpeed.state"
            :done="progress.done"
            :total="progress.total"
          />
          <div class="progress"><span :style="{ width: percent(progress.done, progress.total) + '%' }" /></div>
          <div class="meta">{{ progress.message }}</div>
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
