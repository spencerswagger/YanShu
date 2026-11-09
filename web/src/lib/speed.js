/**
 * 速度 / ETA：EWMA 平滑 + 四档文案 + 两个异常态（网络较慢 / 连接停滞）。
 *
 * 规则（照 v5 稿）：
 * - ≥2s 采样窗口 + EWMA（α≈0.3）；刷新 ≤2 次/秒（由调用方用 rAF 节流）；
 * - `ETA = 剩余字节 / 平滑速度`，floor 到秒；
 * - 文案：<10s 即将完成；<60s 剩 N 秒；<1h 剩 N 分；≥1h 剩 1 小时以上；
 * - 速度 <10 KB/s 持续 3s → `网络较慢`；
 * - 3s 无字节进展 → `连接停滞，重试中` 且 **ETA 隐藏**。
 */
export const EWMA_ALPHA = 0.3
export const SLOW_BPS = 10 * 1024
export const SLOW_HOLD_MS = 3000
export const STALL_MS = 3000
export const MIN_SAMPLE_MS = 500 // 刷新 ≤2 次/秒

export function createSpeedMeter({ alpha = EWMA_ALPHA, now = () => performance.now() } = {}) {
  let lastAt = 0
  let lastBytes = 0
  let ewma = 0
  let lastProgressAt = 0
  let slowSince = 0
  let started = false

  return {
    /** 喂一次进度；返回 { speedBps, etaSec, label, state } */
    update(bytes, total) {
      const t = now()
      if (!started) {
        started = true
        lastAt = t
        lastBytes = bytes
        lastProgressAt = t
        return this.snapshot(bytes, total)
      }
      const dt = (t - lastAt) / 1000
      if (dt * 1000 < MIN_SAMPLE_MS) return this.snapshot(bytes, total) // 节流
      const delta = bytes - lastBytes
      const inst = delta > 0 ? delta / dt : 0
      ewma = ewma > 0 ? ewma * (1 - alpha) + inst * alpha : inst
      lastAt = t
      lastBytes = bytes
      if (delta > 0) lastProgressAt = t
      if (inst > 0 && inst < SLOW_BPS) {
        if (!slowSince) slowSince = t
      } else if (inst >= SLOW_BPS) {
        slowSince = 0
      }
      return this.snapshot(bytes, total)
    },
    snapshot(bytes, total) {
      const t = now()
      const stalled = lastProgressAt > 0 && t - lastProgressAt >= STALL_MS
      const slow = !stalled && slowSince > 0 && t - slowSince >= SLOW_HOLD_MS
      const remaining = Math.max(0, (total || 0) - (bytes || 0))
      const etaSec = stalled || !ewma ? null : Math.floor(remaining / ewma)
      return {
        speedBps: ewma,
        etaSec,
        state: stalled ? 'stalled' : slow ? 'slow' : 'ok',
        label: stalled ? '连接停滞，重试中' : slow ? '网络较慢' : formatSpeed(ewma),
      }
    },
    reset() {
      started = false
      ewma = 0
      slowSince = 0
      lastProgressAt = 0
      lastBytes = 0
      lastAt = 0
    },
  }
}

/** 12.4 MB/s / 820 KB/s / 0 B/s */
export function formatSpeed(bps) {
  if (!Number.isFinite(bps) || bps <= 0) return '0 B/s'
  const mb = bps / 1048576
  if (mb >= 1) return `${mb.toFixed(1)} MB/s`
  const kb = bps / 1024
  if (kb >= 1) return `${Math.round(kb)} KB/s`
  return `${Math.round(bps)} B/s`
}

/** ETA 四档文案；`null` 表示暂时隐藏（停滞） */
export function formatEta(etaSec) {
  if (etaSec === null || !Number.isFinite(etaSec)) return ''
  if (etaSec < 10) return '即将完成'
  if (etaSec < 60) return `剩 ${etaSec} 秒`
  if (etaSec < 3600) return `剩 ${Math.ceil(etaSec / 60)} 分`
  return '剩 1 小时以上'
}

/** 已传 / 总大小（等宽数字由 CSS 保证） */
export function formatBytesPair(done, total) {
  const f = (n) => {
    if (!Number.isFinite(n) || n <= 0) return '0 MB'
    const mb = n / 1048576
    if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`
    return `${mb.toFixed(mb >= 10 ? 0 : 1)} MB`
  }
  return `${f(done)} / ${f(total)}`
}

/**
 * 接收侧两段进度文案（S3）：`下载中 62%` · `解密中 18%`。
 *
 * 两个百分比都是**真数字**：`done` = 已取到的密文字节，`decrypted` = 已解密并写出的明文字节
 * （流式接收按块边下边解，两者会差一块左右）。拿不到 `decrypted` 时只显示「下载中 N%」。
 * 非流式回退路径的最终验签是一次性的，没有增量进度 → 只显示「解密中」，不编百分比。
 */
export function stageLabel(phase, done, total, decrypted = null) {
  if (phase === 'downloading') {
    const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0
    const base = `下载中 ${pct}%`
    if (Number.isFinite(decrypted) && decrypted > 0) {
      const dpct = total > 0 ? Math.min(100, Math.round((decrypted / total) * 100)) : 0
      return `${base} · 解密中 ${dpct}%`
    }
    return base
  }
  if (phase === 'decrypting') return '解密中'
  return ''
}
