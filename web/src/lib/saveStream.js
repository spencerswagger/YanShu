/**
 * 接收侧的"边解边写"落盘。
 *
 * 选型理由：**优先 File System Access API**（Chrome/Edge 的 `showSaveFilePicker`）——
 * 它给的是可写流，块解出来就写进文件，进程里只留一块明文（1 MiB），内存与文件大小无关。
 * 没有该 API（Safari/Firefox 目前都不支持）时退回"分块 Blob 累积"：功能可用，但明文会
 * 在内存里攒到文件大小（≥64 MiB 会明显吃内存），所以整包上限仍是 `config.maxPackSize`。
 *
 * 注意：本模块不碰任何密钥；它只拿到内核吐出的明文块。
 */

/** 分块 Blob 累积（兼容路径）：没有 FS Access 时用，内存随文件线性增长 */
export function createMemorySink() {
  const parts = []
  return {
    name: 'download.bin',
    async write(bytes) {
      parts.push(bytes)
    },
    async close() {
      return { blob: new Blob(parts), name: this.name }
    },
    async abort() {
      parts.length = 0
    },
  }
}

/** 流式写盘（Chrome/Edge）：块到即写，内存恒定 */
export function createFileSink() {
  return {
    name: 'download.bin',
    handle: null,
    writable: null,
    async open(suggestedName) {
      const picker = globalThis.showSaveFilePicker
      if (typeof picker !== 'function') return false
      this.handle = await picker({ suggestedName })
      this.writable = await this.handle.createWritable()
      return true
    },
    async write(bytes) {
      await this.writable.write(bytes)
    },
    async close() {
      await this.writable.close()
      return { file: this.handle, name: this.name }
    },
    async abort() {
      try {
        await this.writable?.abort()
      } catch {
        /* 忽略 */
      }
    },
  }
}

/**
 * 默认 sink 工厂：能用 FS Access 就流式写盘，否则退回内存累积。
 * 调用方（App）也可以注入自己的工厂，便于测试或 Node 侧写文件。
 */
export async function defaultSinkFactory(meta) {
  const name = meta?.name || 'download.bin'
  const fileSink = createFileSink()
  try {
    if (await fileSink.open(name)) {
      fileSink.name = name
      return fileSink
    }
  } catch {
    /* 用户取消选择文件 → 退回内存累积 */
  }
  const mem = createMemorySink()
  mem.name = name
  return mem
}
