/**
 * `/v1/ws` 信令客户端（服务端见 PR #27）。
 *
 * 协议要点（照服务端实现）：
 * - 连上后 **10 秒内**必须发 `HELLO`（复用 `WS_HELLO` 挑战签名），否则服务端关 `4408`；
 * - 认证前发任何其它帧 → `4401`；验签失败 → `4401`；
 * - 之后可 `PING`/`PONG`、`PRESENCE_SUBSCRIBE`（≤32）、`RTC_OFFER`/`ANSWER`/`ICE`/`BYE` 原样转发；
 * - 限速 40 帧/秒（突发 80）→ `ERROR{RATE_LIMITED}`；帧上限 64 KiB → `SIGNAL_TOO_LARGE`；
 * - 非当事人 → `ERROR{SIGNAL_PEER_MISMATCH}`；对端离线 → `PEER_UNREACHABLE`。
 *
 * 本模块只负责"连、认证、收发帧"，不做任何 UI 决策：打洞成不成由 `p2p.js` 判定，
 * 失败一律静默（默认路径本来就是中转，打洞只是加速）。
 */
import { authHeaders } from './auth.js'

export const HELLO_TIMEOUT_MS = 10_000
export const MAX_FRAME_BYTES = 64 * 1024

export function createSignaler({
  wsUrl,
  client,
  kernel,
  session,
  WebSocketImpl = globalThis.WebSocket,
  helloTimeoutMs = HELLO_TIMEOUT_MS,
} = {}) {
  const handlers = new Set()
  let ws = null
  let authed = false
  let closed = false

  function emit(event) {
    for (const fn of handlers) fn(event)
  }

  function rawSend(frame) {
    if (!ws || ws.readyState !== 1) throw new Error('SIGNAL_NOT_OPEN')
    const text = JSON.stringify(frame)
    if (new TextEncoder().encode(text).length > MAX_FRAME_BYTES) {
      throw new Error('SIGNAL_TOO_LARGE')
    }
    ws.send(text)
  }

  async function hello() {
    // 复用认证挑战：purpose=WS_HELLO(0x06)，签名覆盖 CODE(4)
    const { headers } = await authHeaders({
      client,
      kernel,
      privateKey: session.privateKey,
      code: session.code,
      purpose: 'WS_HELLO',
    })
    rawSend({
      type: 'HELLO',
      code: session.code,
      challenge_id: headers['X-YS-Challenge-Id'],
      signature: headers['X-YS-Signature'],
    })
  }

  function open() {
    if (!wsUrl || typeof WebSocketImpl !== 'function') return null
    ws = new WebSocketImpl(wsUrl)
    const timer = setTimeout(() => {
      if (!authed) close()
    }, helloTimeoutMs)

    ws.onmessage = (ev) => {
      let frame
      try {
        frame = JSON.parse(ev.data)
      } catch {
        return
      }
      if (frame.type === 'HELLO_OK' || frame.type === 'AUTH_OK') {
        authed = true
        clearTimeout(timer)
      }
      if (frame.type === 'PING') {
        try {
          rawSend({ type: 'PONG' })
        } catch {
          /* 忽略 */
        }
      }
      emit(frame)
    }
    ws.onclose = () => {
      closed = true
      clearTimeout(timer)
      emit({ type: 'CLOSED' })
    }
    ws.onerror = () => emit({ type: 'ERROR' })

    return new Promise((resolve) => {
      ws.onopen = async () => {
        try {
          await hello()
        } catch {
          close()
          resolve(null)
          return
        }
        resolve(ws)
      }
      setTimeout(() => {
        if (ws && ws.readyState !== 1) {
          close()
          resolve(null)
        }
      }, helloTimeoutMs)
    })
  }

  function close() {
    closed = true
    try {
      ws?.close()
    } catch {
      /* 忽略 */
    }
    ws = null
    authed = false
  }

  return {
    wsUrl,
    open,
    close,
    send: rawSend,
    on(fn) {
      handlers.add(fn)
      return () => handlers.delete(fn)
    },
    get authed() {
      return authed
    },
    get closed() {
      return closed
    },
  }
}
