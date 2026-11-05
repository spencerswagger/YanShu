/**
 * 全平台统计（`GET /v1/stats`，后端形状已定）：
 *   `{ today:{consumed, consumed_bytes, created}, total:{...}, generated_at }`
 *
 * 约定：**失败/超时静默降级**——返回 `null`，界面隐藏该区块，不弹错、不阻塞主流程。
 * 数值只做格式化（四舍五入到千/万），口径由后端决定。
 */
const TIMEOUT_MS = 4000

export function formatCount(n) {
  const v = Number(n) || 0
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)}M`
  if (v >= 100_000) return `${Math.round(v / 10_000)} 万`
  if (v >= 1000) return `${(v / 1000).toFixed(1)}K`
  return String(v)
}

export function formatBytesTotal(n) {
  const v = Number(n) || 0
  const tb = v / 1099511627776
  if (tb >= 1) return `${tb.toFixed(1)} TB`
  const gb = v / 1073741824
  if (gb >= 1) return `${gb.toFixed(gb >= 100 ? 0 : 1)} GB`
  const mb = v / 1048576
  return `${mb.toFixed(0)} MB`
}

/** 取统计；任何失败（网络/超时/形状不对）都返回 null，由界面隐藏区块 */
export async function fetchStats(client, { timeoutMs = TIMEOUT_MS } = {}) {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await client.get('/stats', { retry: false, signal: ctrl.signal })
    const json = res?.json
    if (!json || !json.today || !json.total) return null
    const need = ['consumed', 'consumed_bytes', 'created']
    if (!need.every((k) => k in json.today) || !need.every((k) => k in json.total)) return null
    return json
  } catch {
    return null // 静默降级
  } finally {
    clearTimeout(timer)
  }
}
