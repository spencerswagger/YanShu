/** 展示用格式化（纯函数，便于单测）。 */

export function bytes(n) {
  if (!Number.isFinite(n)) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`
}

export function percent(done, total) {
  if (!total) return 0
  return Math.max(0, Math.min(100, Math.round((done / total) * 100)))
}

export function timeLeft(ms) {
  if (ms === null || ms === undefined) return ''
  const s = Math.max(0, Math.round(ms / 1000))
  if (s < 60) return `${s} 秒`
  const m = Math.round(s / 60)
  if (m < 60) return `${m} 分钟`
  return `${Math.round(m / 60)} 小时`
}

export function clock(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (x) => String(x).padStart(2, '0')
  return `${d.getMonth() + 1}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}
