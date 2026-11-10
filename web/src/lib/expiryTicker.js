/**
 * TTL 的**单一定时器**：胶囊文字与整行状态（灰化 / 删除线 / 下载置灰）都由这一个
 * `now` 驱动，同一帧一起翻，不会出现「文字已过期、按钮还能点」的 30s 窗口。
 *
 * 调度规则（不忙轮询）：
 * - 平时 30s 粒度（文案最细是「N 分钟后过期」，够了）；
 * - 任何截止时刻进入 ≤60s 窗口后，直接 `setTimeout` 到那一刻 +20ms，翻转滞后 <1s；
 * - 没有截止时刻时只挂一个 30s 定时器，不做任何轮询。
 *
 * 后台标签页会被浏览器节流（定时器最小间隔抬到 1s 甚至 1min）→ 翻转可能延后；
 * 页面回到前台（`visibilitychange`）与每次 `syncServerTime` 之后都会立刻重算一次补偿。
 */
import { ref } from 'vue'
import { serverNow } from './serverClock.js'

export const IDLE_MS = 30_000
export const NEAR_MS = 60_000
const EPS_MS = 20

/** 服务端「现在」的快照：所有 TTL 展示共用一个值 */
const now = ref(serverNow())
/** 截止时刻 → 引用计数（多个组件可能盯同一时刻） */
const deadlines = new Map()
let timer = null

/** 下一次 tick 的延迟（纯函数，便于单测）：取最近的临近截止，否则退到 idle 粒度 */
export function nextDelayFor(nowMs, list, { idleMs = IDLE_MS, nearMs = NEAR_MS } = {}) {
  let delay = idleMs
  for (const d of list) {
    const left = d - nowMs
    if (!Number.isFinite(left) || left <= 0) continue
    if (left <= nearMs) delay = Math.min(delay, left + EPS_MS)
  }
  return Math.max(EPS_MS, Math.round(delay))
}

function schedule() {
  if (typeof window === 'undefined') return
  if (timer) clearTimeout(timer)
  timer = setTimeout(() => {
    now.value = serverNow()
    schedule()
  }, nextDelayFor(serverNow(), deadlines.keys()))
}

/** 共享的「现在」；模板/计算属性里读它即可获得响应式 */
export function expiryNow() {
  return now
}

/** 登记一个截止时刻；返回取消登记的函数 */
export function trackDeadline(at) {
  const ms = Number(at)
  if (!Number.isFinite(ms) || ms <= 0) return () => {}
  deadlines.set(ms, (deadlines.get(ms) || 0) + 1)
  schedule()
  return () => {
    const n = (deadlines.get(ms) || 0) - 1
    if (n > 0) deadlines.set(ms, n)
    else deadlines.delete(ms)
    schedule()
  }
}

/** 立刻重算一次（服务端时间基准更新后 / 页面回到前台） */
export function refreshExpiryClock() {
  now.value = serverNow()
  schedule()
}

/** 测试用：清空登记与定时器 */
export function resetExpiryClock() {
  if (timer) clearTimeout(timer)
  timer = null
  deadlines.clear()
  now.value = serverNow()
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refreshExpiryClock()
  })
}
