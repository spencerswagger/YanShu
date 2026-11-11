/**
 * 接收侧的"边解边写"落盘。
 *
 * 三条 sink，按「不留整包在内存」优先选路：
 *  ① `createFileSink`   —— File System Access（Chrome/Edge）：用户选路径，块到即写，内存恒定。
 *     **必须在用户手势内调用** `showSaveFilePicker`，所以由调用方用 `canPick` 明确开关；
 *  ② `createOpfsSink`   —— Origin Private File System：**不需要手势**（无头浏览器/自动化也能用），
 *     块到即写；收完再 `getFile()` 交给浏览器下载。`File` 由浏览器按磁盘承载，不占 JS 堆。
 *  ③ `createMemorySink` —— 只在**小文件**（≤ `maxMemoryBytes`）用；超了直接报错，绝不静默攒。
 *
 * v0.2.4 的坑：`defaultSinkFactory` 用裸 `catch {}` 吞掉了 `showSaveFilePicker` 的失败
 * （无手势 → SecurityError；无头浏览器根本没有可点的对话框），静默退回整包内存累积——
 * 1 GiB 明文全程驻留 JS 堆，`close()` 时 `new Blob(parts)` 还要再复制一份。这条路必须堵死。
 *
 * 本模块不碰任何密钥；它只拿到内核吐出的明文块。
 */

export class SaveError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'SaveError'
    this.code = code
  }
}

/** 小文件内存累积的上限（超过就换 OPFS / 用户选路径，或明确报错） */
export const MAX_MEMORY_SAVE_BYTES = 64 * 1024 * 1024

/** 写盘失败的统一收口：配额单独给一个码，别让用户看到 `QuotaExceededError` 这种生词 */
function asSaveError(err, fallbackCode, what) {
  const quota =
    err?.name === 'QuotaExceededError' ||
    err?.name === 'NS_ERROR_DOM_QUOTA_REACHED' ||
    /quota/i.test(String(err?.message || ''))
  if (quota) {
    return new SaveError('SAVE_QUOTA_EXCEEDED', `本机存储不足，${what}失败（清理浏览器存储后重试）`)
  }
  return new SaveError(fallbackCode, `${what}失败：${err?.message || err}`)
}

function cleanName(name) {
  const base = String(name || '').split(/[\\/]/).pop()
  // eslint-disable-next-line no-control-regex
  const s = base.replace(/[\u0000-\u001f]/g, '').trim().slice(0, 180)
  return s || 'download.bin'
}

/** 分块 Blob 累积（小文件专用）：有硬上限，超了抛可读错误，不静默吃内存 */
export function createMemorySink({ maxBytes = MAX_MEMORY_SAVE_BYTES } = {}) {
  const parts = []
  let total = 0
  return {
    kind: 'memory',
    name: 'download.bin',
    async write(bytes) {
      total += bytes.length
      if (maxBytes && total > maxBytes) {
        parts.length = 0
        throw new SaveError(
          'SAVE_MEMORY_LIMIT',
          `文件超过 ${Math.round(maxBytes / 1048576)} MiB，当前浏览器无法流式落盘（避免整包进内存卡死）`,
        )
      }
      parts.push(bytes)
    },
    async close() {
      try {
        return { name: this.name, blob: new Blob(parts) }
      } catch (err) {
        throw asSaveError(err, 'SAVE_WRITE_FAILED', '组装文件')
      }
    },
    async cleanup() {
      parts.length = 0
    },
    async abort() {
      parts.length = 0
    },
  }
}

/** 用户选路径写盘（Chrome/Edge）。必须在用户手势内 `open()`，否则浏览器会拒。 */
export function createFileSink() {
  return {
    kind: 'file',
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
      try {
        await this.writable.write(bytes)
      } catch (err) {
        throw asSaveError(err, 'SAVE_WRITE_FAILED', '写入目标文件')
      }
    },
    async close() {
      try {
        await this.writable.close()
      } catch (err) {
        throw asSaveError(err, 'SAVE_WRITE_FAILED', '收尾目标文件')
      }
      // 已经写到用户选的位置，不需要再点一次 <a download>
      return { name: this.name, delivered: true }
    },
    async cleanup() {
      /* 用户选的路径由用户自己管，不动 */
    },
    async abort() {
      try {
        await this.writable?.abort()
      } catch {
        /* 用户已取消/流已关，忽略 */
      }
    },
  }
}

/** 浏览器内部暂存（OPFS）：无需手势、常量内存；收完 getFile() 换一个磁盘承载的 Blob 去下载。 */
export function createOpfsSink(name, { root = null, entryName = null } = {}) {
  let dir = root
  let handle = null
  let writable = null
  /**
   * **条目名必须唯一**：cleanup 是按条目名删的，若直接用交付名，
   * 用户 60s 内重下同一个文件时，上一次的定时器会把这一次正在写的文件删掉（表现为"重试也失败"）。
   * 交付给浏览器的名字仍是 `name`；临时条目叫 `<name>.<唯一串>.part`。
   */
  const entry = entryName || `${name}.${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 8)}.part`
  return {
    kind: 'opfs',
    name,
    entryName: entry,
    async open() {
      dir = dir || (await globalThis.navigator.storage.getDirectory())
      // 自己的同名残留（同一 entry 复用）先删，避免把两次内容接在一起
      try {
        await dir.removeEntry(entry)
      } catch {
        /* 没有就算了 */
      }
      try {
        handle = await dir.getFileHandle(entry, { create: true })
        writable = await handle.createWritable()
      } catch (err) {
        throw asSaveError(err, 'SAVE_WRITE_FAILED', '创建浏览器内部暂存')
      }
      return true
    },
    async write(bytes) {
      try {
        await writable.write(bytes)
      } catch (err) {
        throw asSaveError(err, 'SAVE_WRITE_FAILED', '写入浏览器内部暂存')
      }
    },
    async close() {
      try {
        await writable.close()
      } catch (err) {
        throw asSaveError(err, 'SAVE_WRITE_FAILED', '收尾浏览器内部暂存')
      }
      const file = await handle.getFile()
      return { name, file }
    },
    /** 交给浏览器下载之后再删（**别在 save 之前删**，那是唯一副本）；只删**自己的**条目 */
    async cleanup() {
      try {
        await dir?.removeEntry(entry)
      } catch {
        /* 忽略 */
      }
    },
    async abort() {
      try {
        await writable?.abort()
      } catch {
        /* 忽略 */
      }
      try {
        await dir?.removeEntry(entry)
      } catch {
        /* 没有就算了 */
      }
    },
  }
}

/** 有没有可用的 OPFS（拿不到就返回 null） */
export async function opfsRoot() {
  try {
    const storage = globalThis.navigator?.storage
    if (typeof storage?.getDirectory !== 'function') return null
    return await storage.getDirectory()
  } catch {
    return null
  }
}

/** 当前是否有「瞬时用户激活」——`showSaveFilePicker` 的硬要求 */
export function hasUserGesture() {
  return globalThis.navigator?.userActivation?.isActive === true
}

/**
 * 默认选路：小文件 → 内存；大文件 → 用户选路径（仅当有手势）→ OPFS → 明确报错。
 * 任何一步失败都**不静默**：要么换一条能保证落盘的路，要么把原因抛给 UI。
 */
export async function defaultSinkFactory(meta = {}, options = {}) {
  const name = cleanName(meta?.name)
  const size = Number(meta?.size) || 0
  const maxMemoryBytes = options.maxMemoryBytes ?? MAX_MEMORY_SAVE_BYTES

  if (size <= maxMemoryBytes) {
    const mem = createMemorySink({ maxBytes: maxMemoryBytes })
    mem.name = name
    return mem
  }

  const canPick = options.canPick ?? hasUserGesture()
  if (canPick && typeof globalThis.showSaveFilePicker === 'function') {
    const fileSink = createFileSink()
    try {
      if (await fileSink.open(name)) {
        fileSink.name = name
        return fileSink
      }
    } catch (err) {
      // 用户取消/浏览器拒绝都落到 OPFS：能落盘比让用户重来强，但必须留痕
      options.onNotice?.({
        code: 'SAVE_PICKER_UNAVAILABLE',
        message: `未使用「选择保存位置」（${err?.name || err?.message || err}），改走浏览器内部暂存后自动下载`,
      })
    }
  }

  const root = options.root ?? (await opfsRoot())
  if (root) {
    const sink = createOpfsSink(name, { root })
    await sink.open()
    return sink
  }

  throw new SaveError(
    'SAVE_UNSUPPORTED_LARGE',
    `文件 ${size} 字节：当前浏览器既不能「选择保存位置」也没有内部暂存（OPFS），为避免整包进内存卡死，本次不下载。请用 Chrome/Edge 打开，或让对方拆分后再发。`,
  )
}
