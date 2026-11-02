/**
 * 退避重试策略（API.md §11.2 / 团队统一口径：5s → 20s → 60s，最多 3 次）。
 *
 * - 429：以 `Retry-After` 为准，取「退避值」与 `Retry-After` 的较大值，**不得**在窗口内重试。
 * - 503 / 500 / 507 / 网络超时：按退避序列重试。
 * - 其它 4xx（业务错误）：不重试，直接交给上层。
 *
 * `sleep` 可注入，便于测试（生产用真实定时器）。
 */

export class RetryableError extends Error {
  constructor(message, { code, status, retryAfter } = {}) {
    super(message)
    this.name = 'RetryableError'
    this.code = code
    this.status = status
    this.retryAfter = retryAfter
  }
}

export const RETRYABLE_STATUS = new Set([500, 502, 503, 504, 507])

export function isRetryable(err) {
  if (err && err.name === 'AbortError') return false
  if (err instanceof RetryableError) return true
  if (!err) return false
  // 网络层失败（fetch 抛 TypeError）
  if (err.name === 'TypeError') return true
  return RETRYABLE_STATUS.has(err.status) || err.status === 429
}

export function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * @param {() => Promise<any>} task
 * @param {object} opts
 * @param {number[]} [opts.backoffMs] 退避序列（每次重试前等待）
 * @param {number} [opts.maxAttempts] 总尝试次数（含首次）
 * @param {(info:{attempt:number, delayMs:number, error:any}) => void} [opts.onWait]
 * @param {(ms:number) => Promise<void>} [opts.sleep]
 * @param {(err:any) => boolean} [opts.shouldRetry]
 */
export async function withRetry(task, opts = {}) {
  const backoffMs = opts.backoffMs || [5000, 20000, 60000]
  const maxAttempts = opts.maxAttempts ?? backoffMs.length + 1
  const sleep = opts.sleep || defaultSleep
  const shouldRetry = opts.shouldRetry || isRetryable
  let attempt = 0
  let lastError
  while (attempt < maxAttempts) {
    attempt += 1
    try {
      return await task(attempt)
    } catch (err) {
      lastError = err
      if (attempt >= maxAttempts || !shouldRetry(err)) throw err
      const base = backoffMs[Math.min(attempt - 1, backoffMs.length - 1)]
      const retryAfterMs = Number(err.retryAfter) > 0 ? Number(err.retryAfter) * 1000 : 0
      const delayMs = Math.max(base, retryAfterMs)
      if (opts.onWait) opts.onWait({ attempt, delayMs, error: err })
      await sleep(delayMs)
    }
  }
  throw lastError
}
