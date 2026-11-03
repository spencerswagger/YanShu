/**
 * 分块路由：默认全部走中转；只有**用户明确点切**之后，剩余块才走直连（DataChannel）。
 *
 * 三条硬规则（对应任务书）：
 * 1. 默认路径不变：`enableDirect` 之前一律 `putChunk` 走中转，打洞结果不参与任何等待；
 * 2. 直连失败/断开 → 立刻回中转继续同一块（不丢块、不重复 ack）；
 * 3. 已传块不重传：路由只管"还没发的块"，是否补发由调用方按 missing 列表决定。
 */
export function createChunkRouter({ putChunk, onRoute } = {}) {
  let direct = null
  const stats = { relay: 0, direct: 0, fallback: 0 }

  return {
    get mode() {
      return direct ? 'direct' : 'relay'
    },
    get stats() {
      return { ...stats }
    },
    /** 用户点切直连后调用：`channel.send(index, bytes)` 抛错即视为断线 */
    enableDirect(channel) {
      if (!channel || typeof channel.send !== 'function') return false
      direct = channel
      return true
    },
    disableDirect() {
      if (!direct) return
      direct = null
      stats.fallback += 1
    },
    /** 发送一块：直连优先（仅当已启用），失败静默回落中转 */
    async send(index, bytes) {
      if (direct) {
        try {
          await direct.send(index, bytes)
          stats.direct += 1
          onRoute?.('direct', index)
          return 'direct'
        } catch {
          // 直连断了：静默回落，不弹错、不影响中转进度
          direct = null
          stats.fallback += 1
          onRoute?.('fallback', index)
        }
      }
      await putChunk({ index, bytes })
      stats.relay += 1
      onRoute?.('relay', index)
      return 'relay'
    },
  }
}
