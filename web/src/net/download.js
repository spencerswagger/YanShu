/**
 * 接收编排：待收列表 → 取 prelude（开租约）→ 逐块下载 → 端侧解密 → 落盘 → ack。
 *
 * 契约要点：
 * - prelude 一取就进 `LEASED`（API.md §7.3），块下载必须带 `X-YS-Download-Id`（§7.4）；
 * - 列表里**没有**文件名/MIME（§7.1），文件名只能解清单后拿到；
 * - 三种终结态在内容端点都是 `410`，错误码互不混用（§5.2 / §5.3）；
 * - `ack` 成功即代表服务端物理删除密文（§7.5）。
 */
import { CryptoError } from '../crypto/errors.js'
import { ApiError } from './client.js'
import { runPool } from '../lib/pool.js'
import { info } from '../lib/log.js'
import { config } from '../config.js'

const TERMINAL_STATES = new Set(['REVOKED', 'EXPIRED', 'CONSUMED'])

const TERMINAL_CODE = {
  REVOKED: 'TRANSFER_REVOKED',
  EXPIRED: 'TRANSFER_EXPIRED',
  CONSUMED: 'TRANSFER_CONSUMED',
}

export function terminalError(state, terminalReason) {
  const key = TERMINAL_CODE[terminalReason] ? terminalReason : state
  const code = TERMINAL_CODE[key] || 'TRANSFER_STATE_CONFLICT'
  return new ApiError({ code, status: 410, message: `transfer ${state}` })
}

/**
 * @param {object} p
 * @param {object} p.api
 * @param {object} p.kernel
 * @param {object} p.session
 * @param {string} p.transferId
 * @param {(p:object)=>void} [p.onProgress]
 * @param {AbortSignal} [p.signal]
 * @param {(blob:Blob, name:string)=>void} [p.save] 落盘动作（浏览器里是 a[download]）
 * @param {boolean} [p.ack] 是否在成功后 ack（默认 true）
 */
export async function receiveTransfer({ api, kernel, session, transferId, onProgress, signal, save, ack = true }) {
  const report = (patch) => onProgress?.(patch)

  const meta = (await api.getTransfer(transferId)) || {}
  if (TERMINAL_STATES.has(meta.state)) throw terminalError(meta.state, meta.terminal_reason)

  report({ phase: 'prelude', done: 0, total: meta.plaintext_size || 0, message: '取回包头' })
  const prelude = await api.getPrelude(transferId)
  if (!prelude.downloadId) {
    throw new ApiError({ code: 'DOWNLOAD_NOT_STARTED', status: 409, message: 'no download id' })
  }

  const { handle, meta: manifest } = kernel.unpackOpen({
    prelude: prelude.bytes,
    identity: session.identity,
  })

  try {
    // §13 #18：包里的发送方码必须与列表/元数据一致（挡住"服务器换个人冒充"的低成本做法）
    if (meta.sender_code && manifest.sender_code && meta.sender_code !== manifest.sender_code) {
      throw new CryptoError('CRYPTO_SENDER_MISMATCH', `${meta.sender_code} ≠ ${manifest.sender_code}`)
    }
    if (meta.plaintext_size !== undefined && Number(manifest.size) !== Number(meta.plaintext_size)) {
      throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '清单大小与元数据不一致')
    }

    const chunkCount = Number(manifest.chunk_count)
    const total = Number(manifest.size)
    const parts = new Array(chunkCount)
    let done = 0
    let doneChunks = 0

    await runPool(
      [...Array(chunkCount).keys()],
      async (index) => {
        if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
        const slice = await api.getChunk({ transferId, downloadId: prelude.downloadId, index })
        const plain = kernel.unpackChunk(handle, index, slice)
        parts[index] = plain
        done += plain.length
        doneChunks += 1
        report({
          phase: 'downloading',
          done,
          total,
          message: `解密块 ${doneChunks}/${chunkCount}`,
        })
      },
      { concurrency: config.uploadConcurrency, signal },
    )

    kernel.unpackFinish(handle)

    const blob = new Blob(parts, { type: manifest.mime || 'application/octet-stream' })
    if (save) {
      report({ phase: 'saving', done: total, total, message: '落盘' })
      save(blob, safeFileName(manifest.name))
    }

    if (ack) {
      report({ phase: 'acking', done: total, total, message: '确认取件（服务端随即删除密文）' })
      await api.ack({ transferId, downloadId: prelude.downloadId })
    }

    info('接收完成', { bytes: total, chunks: chunkCount })
    report({ phase: 'done', done: total, total, message: '已取回' })
    return {
      transferId,
      name: manifest.name,
      mime: manifest.mime,
      size: total,
      chunkCount,
      blob,
      senderCode: manifest.sender_code,
    }
  } finally {
    try {
      kernel.unpackClose(handle)
    } catch {
      /* ignore */
    }
  }
}

/** 文件名只保留 basename（契约 §3.3），并挡掉控制字符与路径分隔符。 */
export function safeFileName(name) {
  const base = String(name || 'file').split(/[\\/]/).pop()
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f]/g, '').slice(0, 255)
  return cleaned || 'file'
}
