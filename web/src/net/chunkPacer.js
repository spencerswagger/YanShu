/**
 * 块下载的客户端限速器（AIMD，按服务端额度自适应）。
 *
 * 为什么需要：契约 §11.1 把内容端点限到「按传输 600 次/分」「按 IP 120 次/分」——
 * 也就是**最紧的一档只有 2 次/秒**。v0.2.4 现场实测：客户端在限速天花板上跑（有效吞吐
 * 2.07 块/秒），每撞一次 429 就被 `withRetry` 的 5 秒地板拖成约 5.6 秒一块
 * （81 条 429，中位间隔 5.6 秒）——长文件因此在测试窗口内没跑完。
 *
 * 所以客户端必须自己排队：
 * - 常态按 `ratePerSec` 发令牌（默认 2.5/s，略高于最紧的 2/s 用于探测，超了会自己降）；
 * - 吃到 429：立刻把速率减半（不低于 `minRatePerSec`），并按 `Retry-After` 等（**不再套 5s 地板**）；
 * - 连续成功 `rampAfter` 次：速率加回一档（不超过 `maxRatePerSec`）。
 *
 * 纯逻辑、可注入时钟与定时器，便于单测（真实浏览器里就是 setTimeout）。
 */

export const DEFAULT_PACING = {
  ratePerSec: 2.5,
  minRatePerSec: 0.5,
  maxRatePerSec: 8,
  /** 桶容量：允许一点点突发，别把 RTT 全花在等令牌上 */
  burst: 3,
  /** 连续成功多少次加一档（AIMD 的 AI） */
  rampAfter: 24,
  /** 429 时的最小等待（秒）；`Retry-After` 缺失时用它 */
  minBackoffSec: 1,
}

export function createChunkPacer(options = {}) {
  const cfg = { ...DEFAULT_PACING, ...options }
  const now = options.now || (() => Date.now())
  const sleep = options.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)))

  let rate = clamp(cfg.ratePerSec, cfg.minRatePerSec, cfg.maxRatePerSec)
  let tokens = cfg.burst
  let lastRefill = now()
  let okStreak = 0
  /** 被限速的次数与累计等待，用于进度提示（用户必须看得见） */
  let throttled = 0
  let waitedMs = 0

  function clamp(v, lo, hi) {
    return Math.min(hi, Math.max(lo, v))
  }

  function refill() {
    const t = now()
    const dt = Math.max(0, t - lastRefill) / 1000
    if (dt > 0) {
      tokens = Math.min(cfg.burst, tokens + dt * rate)
      lastRefill = t
    }
  }

  /** 等一个令牌（发一块前调用） */
  async function acquire() {
    for (;;) {
      refill()
      if (tokens >= 1) {
        tokens -= 1
        return
      }
      const needMs = Math.max(20, Math.ceil(((1 - tokens) / rate) * 1000))
      await sleep(needMs)
    }
  }

  /**
   * 吃到 429：降速 + 返回该等多久（毫秒）。
   * `retryAfterSec` 来自响应头 / body，服务端说了算；没有才用兜底。
   */
  function onThrottled(retryAfterSec) {
    rate = clamp(rate / 2, cfg.minRatePerSec, cfg.maxRatePerSec)
    tokens = 0
    lastRefill = now()
    okStreak = 0
    throttled += 1
    const sec = Number(retryAfterSec) > 0 ? Number(retryAfterSec) : cfg.minBackoffSec
    const waitMs = Math.ceil(sec * 1000)
    waitedMs += waitMs
    return waitMs
  }

  function onSuccess() {
    okStreak += 1
    if (okStreak >= cfg.rampAfter) {
      okStreak = 0
      rate = clamp(rate * 1.5, cfg.minRatePerSec, cfg.maxRatePerSec)
    }
  }

  return {
    acquire,
    onThrottled,
    onSuccess,
    get ratePerSec() {
      return rate
    },
    get throttledCount() {
      return throttled
    },
    get waitedMs() {
      return waitedMs
    },
    /** 供 UI 一句话说清：`被限速 12 次，已等 1 分 05 秒` */
    summary() {
      if (!throttled) return ''
      const s = Math.round(waitedMs / 1000)
      return `服务端限速 ${throttled} 次，已等待 ${s >= 60 ? `${Math.floor(s / 60)} 分 ${s % 60} 秒` : `${s} 秒`}`
    },
  }
}
