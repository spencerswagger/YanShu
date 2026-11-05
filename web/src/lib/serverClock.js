/**
 * 服务端时间基准 + 单调推进（TTL 倒计时的唯一正确做法）。
 *
 * 为什么不能 `Date.parse(expires_at) - Date.now()`：设备时钟可能差几分钟到几小时，
 * 用户会看到「还剩 3 小时」其实早就过期了。
 *
 * 做法：用一次响应头 `Date`（或 `/v1/config` 的 `server_time`）算出 offset，
 * 之后用 `performance.now()`（单调、不受系统改时间影响）推进；`visibilitychange` 时重算。
 */
let offsetMs = null

/** 记录一次服务端时间基准（响应头 Date 或 server_time） */
export function syncServerTime(serverNowMs) {
  const n = Number(serverNowMs)
  if (!Number.isFinite(n) || n <= 0) return false
  offsetMs = n - performance.now()
  return true
}

/** 服务端"现在"的毫秒时间戳；未同步时退化为本地时间（并标记 unsynced） */
export function serverNow() {
  if (offsetMs === null) return Date.now()
  return performance.now() + offsetMs
}

export function hasServerTime() {
  return offsetMs !== null
}

export function resetServerTime() {
  offsetMs = null
}

/** 距离过期的毫秒数（≤0 表示已过期） */
export function remainingMs(expiresAt, now = serverNow()) {
  const t = typeof expiresAt === 'number' ? expiresAt : Date.parse(expiresAt)
  if (!Number.isFinite(t)) return 0
  return t - now
}

const HOUR = 3600_000
const DAY = 24 * HOUR
const MIN = 60_000

/**
 * TTL 文案（照 v5 稿，与「预计剩余时间」区分开）：
 *   已过期 → `已过期，无法取回`
 *   ≥1 天  → `N 天后过期`（向上取整，避免「0 天后过期」）
 *   ≥1 小时 → `N 小时后过期`
 *   其余    → `N 分钟后过期`（<1 分钟 → `1 分钟后过期`）
 */
export function formatTtl(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '已过期，无法取回'
  if (ms >= DAY) return `${Math.max(1, Math.floor(ms / DAY))} 天后过期`
  if (ms >= HOUR) return `${Math.max(1, Math.floor(ms / HOUR))} 小时后过期`
  return `${Math.max(1, Math.floor(ms / MIN))} 分钟后过期`
}

/** 是否临近过期（≤1 小时）——只影响视觉（警示色/沙漏），不加进度条、不闪烁 */
export function isExpiringSoon(ms) {
  return Number.isFinite(ms) && ms > 0 && ms <= HOUR
}

export function isExpired(ms) {
  return !Number.isFinite(ms) || ms <= 0
}
