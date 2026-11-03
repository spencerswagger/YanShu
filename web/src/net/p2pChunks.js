/**
 * 直连块帧格式 + 接收侧缓冲。
 *
 * 帧 = `u32be(index) ‖ 密文块字节`（块本身已是 `CHUNK_CT‖TAG`，这里不解析、不加密）。
 * 为什么把 index 放在帧头：DataChannel 是有序字节流语义，但一条消息可能被分片，
 * 接收侧必须能自己判断"这块属于哪一块"，不能依赖到达顺序。
 */

export const FRAME_HEADER_BYTES = 4

export function encodeChunkFrame(index, bytes) {
  const out = new Uint8Array(FRAME_HEADER_BYTES + bytes.length)
  new DataView(out.buffer).setUint32(0, index, false)
  out.set(bytes, FRAME_HEADER_BYTES)
  return out
}

export function decodeChunkFrame(buf) {
  const view = new Uint8Array(buf)
  if (view.length <= FRAME_HEADER_BYTES) throw new Error('P2P_FRAME_TOO_SHORT')
  const index = new DataView(view.buffer, view.byteOffset, view.byteLength).getUint32(0, false)
  return { index, bytes: view.subarray(FRAME_HEADER_BYTES) }
}

/** 接收侧缓冲：直连收到的块先存着，下载循环优先取它，取不到再回中转 GET */
export function createDirectBuffer() {
  const map = new Map()
  return {
    put(index, bytes) {
      map.set(index, bytes)
    },
    take(index) {
      if (!map.has(index)) return null
      const bytes = map.get(index)
      map.delete(index)
      return bytes
    },
    get size() {
      return map.size
    },
    clear() {
      map.clear()
    },
  }
}

/** 把 DataChannel 收到的消息灌进缓冲；坏帧静默丢弃（直连只是加速，不能因坏帧中断接收） */
export function attachDirectReceiver(channel, buffer) {
  channel.onmessage = (ev) => {
    try {
      const { index, bytes } = decodeChunkFrame(ev.data)
      buffer.put(index, bytes)
    } catch {
      /* 坏帧忽略 */
    }
  }
  return () => {
    channel.onmessage = null
  }
}

/**
 * 取一块密文：直连缓冲优先，没有就回中转 GET（行为与原来完全一致）。
 * 抽成函数是为了能单测"直连优先/回落"这条分支，不必起真通道。
 */
export async function takeChunkBytes({ directBuffer, index, getChunk }) {
  const direct = directBuffer?.take?.(index) || null
  if (direct) return { bytes: direct, source: 'direct' }
  return { bytes: await getChunk(index), source: 'relay' }
}
