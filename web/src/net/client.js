/**
 * HTTP 客户端：只做"字节怎么进出"，不含业务。
 *
 * 契约要点（API.md §0）：
 * - 错误按 `error.code` 分支，**不匹配 message 文案**；
 * - 429 以 `Retry-After` 为准，5s→20s→60s 退避（取较大值，最多 3 次）；
 * - 二进制端点只发/收 `application/octet-stream`，不碰 multipart；
 * - 请求带 `X-YS-Request-Id`（≤64 可打印 ASCII），服务端原样回显。
 */
import { withRetry } from '../lib/retry.js'
import { config } from '../config.js'
import { info } from '../lib/log.js'

export class ApiError extends Error {
  constructor({ code, status, message, retryAfter, scope, requestId, body }) {
    super(message || code || 'request failed')
    this.name = 'ApiError'
    this.code = code || 'NETWORK_ERROR'
    this.status = status || 0
    this.retryAfter = retryAfter || 0
    this.scope = scope || null
    this.requestId = requestId || null
    this.body = body || null
  }

  get retryable() {
    return this.status === 429 || [500, 502, 503, 504, 507].includes(this.status)
  }
}

function requestId() {
  const bytes = new Uint8Array(8)
  crypto.getRandomValues(bytes)
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function createClient({ baseUrl = config.apiBase, fetchImpl, timeoutMs = 30000, backoffMs = config.backoffMs } = {}) {
  const doFetch = fetchImpl || globalThis.fetch.bind(globalThis)

  async function once(method, path, opts) {
    const url = path.startsWith('http') ? path : baseUrl + path
    const headers = { Accept: 'application/json', 'X-YS-Request-Id': requestId(), ...(opts.headers || {}) }
    let body
    if (opts.bytes !== undefined && opts.bytes !== null) {
      body = opts.bytes
      headers['Content-Type'] = headers['Content-Type'] || 'application/octet-stream'
    } else if (opts.json !== undefined) {
      body = JSON.stringify(opts.json)
      headers['Content-Type'] = 'application/json'
    }

    const signals = []
    if (opts.signal) signals.push(opts.signal)
    if (timeoutMs) signals.push(AbortSignal.timeout(timeoutMs))
    const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals)

    const started = Date.now()
    let res
    try {
      res = await doFetch(url, { method, headers, body, signal })
    } catch (err) {
      if (err.name === 'AbortError' && opts.signal?.aborted) throw err
      throw new ApiError({ code: 'NETWORK_ERROR', status: 0, message: `网络不可达：${err.message}` })
    }

    const ms = Date.now() - started
    info(`${method} ${path}`, { method, path, status: res.status, ms })
    const requestIdHeader = res.headers.get('X-YS-Request-Id') || undefined

    if (!res.ok) {
      let payload = null
      try {
        payload = await res.json()
      } catch {
        payload = null
      }
      const err = payload?.error || {}
      throw new ApiError({
        code: err.code || `HTTP_${res.status}`,
        status: res.status,
        message: err.message || `HTTP ${res.status}`,
        retryAfter: Number(res.headers.get('Retry-After')) || Number(err.retry_after) || 0,
        scope: err.scope || null,
        requestId: err.request_id || requestIdHeader,
        body: payload,
      })
    }

    if (opts.raw) {
      const buffer = await res.arrayBuffer()
      return { status: res.status, headers: res.headers, bytes: new Uint8Array(buffer) }
    }
    if (res.status === 204) return { status: res.status, headers: res.headers, json: null }
    const text = await res.text()
    return {
      status: res.status,
      headers: res.headers,
      json: text ? JSON.parse(text) : null,
      bytes: opts.keepBytes ? new TextEncoder().encode(text) : undefined,
    }
  }

  /**
   * @param {string} method
   * @param {string} path
   * @param {object} [opts] { json, bytes, headers, signal, raw, retry, onRetry }
   */
  async function request(method, path, opts = {}) {
    if (!opts.retry) return once(method, path, opts)
    return withRetry(() => once(method, path, opts), {
      backoffMs,
      onWait: ({ attempt, delayMs, error }) => {
        info('退避重试', { retryAfter: Math.round(delayMs / 1000), status: error?.status })
        opts.onRetry?.({ attempt, delayMs, error })
      },
    })
  }

  return {
    baseUrl,
    get: (path, opts) => request('GET', path, opts),
    head: (path, opts) => request('HEAD', path, opts),
    post: (path, opts) => request('POST', path, opts),
    put: (path, opts) => request('PUT', path, opts),
    patch: (path, opts) => request('PATCH', path, opts),
    request,
  }
}
