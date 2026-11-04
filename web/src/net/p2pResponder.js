/**
 * 接收侧信令（answerer）：收到 `RTC_OFFER` 就回 `RTC_ANSWER`，把 DataChannel 收到的块灌进缓冲。
 *
 * 为什么必须有它：发送端发 offer 后如果对面不回 answer，`RTCPeerConnection` 永远停在
 * `connecting` → 8 秒超时 → 静默回落。没有接收侧，直传功能等于死的。
 *
 * 状态机：`idle → answering → connected → (failed | closed) → relay`
 * 任何失败都**静默回落**（关掉 pc、清掉监听、状态置 relay），不弹错、不影响中转下载。
 *
 * 归属校验（客户端不盲信服务端）：只处理
 *   - `frame.transfer_id === 本笔 transferId`
 *   - `frame.to_code === 自己的码`（若帧里带）
 *   - `frame.from_code`（若有）必须是这笔传输的对端
 * 其余帧直接忽略。
 */
import { buildRtcConfig } from './p2p.js'
import { attachDirectReceiver } from './p2pChunks.js'

export const RESPONDER_TIMEOUT_MS = 10_000

/**
 * @param {object} p
 * @param {object} p.signaler         已 open 的信令客户端（`signal.js`）
 * @param {string} p.transferId       本笔传输 id
 * @param {string} p.selfCode         自己的 4 位码
 * @param {string} p.peerCode         对端（发送方）4 位码
 * @param {string[]} p.stunUrls       只放 STUN
 * @param {object} p.buffer           `createDirectBuffer()` 的缓冲
 * @param {number} [p.timeoutMs]
 * @param {Function} [p.RTCPeerConnectionImpl]
 * @param {Function} [p.onStatus]     'answering' | 'connected' | 'relay'
 */
export function createResponder({
  signaler,
  transferId,
  selfCode,
  peerCode,
  stunUrls,
  buffer,
  timeoutMs = RESPONDER_TIMEOUT_MS,
  RTCPeerConnectionImpl = globalThis.RTCPeerConnection,
  onStatus,
} = {}) {
  let pc = null
  let detach = null
  let timer = null
  let state = 'idle'

  const setState = (next) => {
    state = next
    onStatus?.(next)
  }

  function belongs(frame) {
    if (!frame || !transferId) return false
    if (frame.transfer_id !== transferId) return false
    if (frame.to_code && frame.to_code !== selfCode) return false
    if (frame.from_code && peerCode && frame.from_code !== peerCode) return false
    return true
  }

  function cleanup() {
    if (timer) clearTimeout(timer)
    timer = null
    detach?.()
    detach = null
    try {
      pc?.close()
    } catch {
      /* 忽略 */
    }
    pc = null
  }

  function fail() {
    cleanup()
    setState('relay') // 静默回落：中转本来就在跑
  }

  async function handleOffer(frame) {
    if (typeof RTCPeerConnectionImpl !== 'function') return
    cleanup()
    try {
      pc = new RTCPeerConnectionImpl(buildRtcConfig(stunUrls))
      setState('answering')
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
          /* 信令断了：静默回落 */
          fail()
        }
      }
      pc.ondatachannel = (ev) => {
        const channel = ev.channel
        detach = attachDirectReceiver(channel, buffer)
        channel.onclose = () => fail()
        setState('connected')
      }
      await pc.setRemoteDescription(frame.payload)
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)
      signaler.send({
        type: 'RTC_ANSWER',
        transfer_id: transferId,
        to_code: peerCode,
        payload: pc.localDescription,
      })
      timer = setTimeout(() => {
        if (state !== 'connected') fail()
      }, timeoutMs)
    } catch {
      fail()
    }
  }

  async function handleIce(frame) {
    if (!pc || !frame?.payload) return
    try {
      await pc.addIceCandidate(frame.payload)
    } catch {
      /* 单个候选失败不算致命，等后续候选或超时 */
    }
  }

  const off = signaler?.on?.((frame) => {
    if (!belongs(frame)) return
    if (frame.type === 'RTC_OFFER') handleOffer(frame)
    else if (frame.type === 'RTC_ICE') handleIce(frame)
    else if (frame.type === 'RTC_BYE') {
      cleanup()
      setState('relay')
    }
  })

  return {
    get state() {
      return state
    },
    close() {
      off?.()
      cleanup()
      setState('relay')
    },
  }
}
