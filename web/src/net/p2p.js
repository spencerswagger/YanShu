/**
 * 后台静默试打洞（P2P 直传）。
 *
 * 设计原则（任务书）：
 * 1. **默认路径不等待**：本模块只在后台跑，超时/失败一律返回 `null`，不抛错、不影响中转进度；
 * 2. **不做 TURN**：`iceServers` 只来自 `/v1/config` 的 `stun_urls`（仅 `stun:`），出现 `turn:` 直接忽略；
 * 3. **打通也要用户点**才切：本模块只负责"能不能通"，切不切由 UI 决定（见 `chunkRouter`）；
 * 4. 超时上限 `DEFAULT_TIMEOUT_MS = 8000`（打洞 + ICE 交换），到点静默放弃。
 */
export const DEFAULT_TIMEOUT_MS = 8000

/** 只保留 STUN：契约 v1 不做 TURN，`turn:` 一律丢掉（防配置误带） */
export function stunOnly(urls) {
  if (!Array.isArray(urls)) return []
  return urls.filter((u) => typeof u === 'string' && u.startsWith('stun:'))
}

export function buildRtcConfig(stunUrls) {
  return { iceServers: stunOnly(stunUrls).map((urls) => ({ urls })) }
}

/** ws_url 为空 → 直接不尝试（契约 §9.6：静默走中转，通知改轮询 inbox） */
export function shouldAttemptDirect({ wsUrl, hasPeer, hasStun }) {
  if (!wsUrl) return false
  if (!hasPeer) return false
  if (!hasStun) return false
  return true
}

/**
 * 试一次打洞；成功返回 `{ channel, close }`，失败/超时返回 `null`（**不抛错**）。
 * @param {object} p
 * @param {object} p.signaler       `signal.js` 的实例（已 open）
 * @param {string} p.transferId
 * @param {string} p.peerCode       对端 4 位码
 * @param {string[]} p.stunUrls     `/v1/config` 的 `stun_urls`
 * @param {number} [p.timeoutMs]
 * @param {Function} [p.RTCPeerConnectionImpl]
 */
export async function attemptDirect({
  signaler,
  wsUrl,
  transferId,
  peerCode,
  stunUrls,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  RTCPeerConnectionImpl = globalThis.RTCPeerConnection,
} = {}) {
  if (!signaler || typeof RTCPeerConnectionImpl !== 'function') return null
  if (
    !shouldAttemptDirect({
      wsUrl: wsUrl ?? signaler?.wsUrl ?? '',
      hasPeer: Boolean(peerCode),
      hasStun: stunOnly(stunUrls).length > 0,
    })
  ) {
    return null
  }

  let pc = null
  let timer = null
  const cleanup = () => {
    if (timer) clearTimeout(timer)
    try {
      pc?.close()
    } catch {
      /* 忽略 */
    }
  }

  try {
    pc = new RTCPeerConnectionImpl(buildRtcConfig(stunUrls))
    const channel = pc.createDataChannel('ys-chunks', { ordered: true })
    const ready = new Promise((resolve) => {
      channel.onopen = () => resolve(true)
    })
    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return
      try {
        signaler.send({
          type: 'RTC_ICE',
          transfer_id: transferId,
          to_code: peerCode,
          payload: ev.candidate.toJSON ? ev.candidate.toJSON() : ev.candidate,
        })
      } catch {
        /* 信令断了就放弃，不影响中转 */
      }
    }
    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    signaler.send({
      type: 'RTC_OFFER',
      transfer_id: transferId,
      to_code: peerCode,
      payload: pc.localDescription,
    })

    const opened = await Promise.race([
      ready,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs)
      }),
    ])
    if (!opened) {
      cleanup()
      return null // 静默放弃：默认路径本来就是中转
    }

    return {
      channel,
      close: () => {
        cleanup()
        try {
          channel.close()
        } catch {
          /* 忽略 */
        }
      },
    }
  } catch {
    cleanup()
    return null
  }
}
