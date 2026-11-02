/**
 * 接收编排：取 prelude → 逐块下载 → 按块序号拼回整包 → 端侧解密 → 落盘 → ack。
 *
 * - prelude 一取就进 `LEASED`（API.md §7.3），块下载必须带 `X-YS-Download-Id`（§7.4）；
 * - 列表里没有文件名/MIME（§7.1），解包后才拿到；
 * - 三种终结态在内容端点都是 `410`（§5.2 / §5.3）；
 * - `ack` 成功即代表服务端物理删除密文（§7.5）。
 */
import { CryptoError } from '../crypto/errors.js'
import { ApiError } from './client.js'
import { runPool } from '../lib/pool.js'
import { info } from '../lib/log.js'
import { config } from '../config.js'

const TERMINAL_CODES = {
  REVOKED: 'TRANSFER_REVOKED',
  EXPIRED: 'TRANSFER_EXPIRED',
  CONSUMED: 'TRANSFER_CONSUMED',
}

export function terminalError(state, terminalReason) {
  const key = TERMINAL_CODES[terminalReason] ? terminalReason : state
  const code = TERMINAL_CODES[key] || 'TRANSFER_STATE_CONFLICT'
  return new ApiError({ code, status: 410, message: `transfer ${state}` })
}

/**
 * @param {object} p
 * @param {(code:string)=>Promise<Uint8Array>} p.senderPublic 由发送方码取 65 字节公钥（服务端可信）
 */
export async function receiveTransfer({ api, kernel, session, transferId, senderPublic, onProgress, signal, save, ack = true }) {
  const report = (patch) => onProgress?.(patch)

  const meta = (await api.getTransfer(transferId)) || {}
  if (meta.state === 'REVOKED' || meta.state === 'EXPIRED' || meta.state === 'CONSUMED') {
    throw terminalError(meta.state, meta.terminal_reason)
  }

  report({ phase: 'prelude', done: 0, total: meta.plaintext_size || 0, message: '取回包头' })
  const prelude = await api.getPrelude(transferId)
  if (!prelude.downloadId) throw new ApiError({ code: 'DOWNLOAD_NOT_STARTED', status: 409, message: 'no download id' })

  // 新内核来源由包内 SENDER_PUB 自证（6 参 `_v1`），老内核才需要另取发送方公钥
  const selfUnpack = kernel.capabilities?.selfUnpack || kernel.capabilities?.codeUnpack
  const pub = selfUnpack ? null : await senderPublic(meta.sender_code)
  const unpack = kernel.openUnpackSession({
    prelude: prelude.bytes,
    recipientPrivate: session.privateKey,
    senderPublic: pub,
    senderCode: meta.sender_code,
    plaintextSize: Number(meta.plaintext_size),
    chunkSize: Number(meta.chunk_size),
  })
  // 契约布局下 prelude 单独解不出清单（内核校验整包长度），此时先信 API 元数据，收齐后再核
  const manifest = unpack.meta
  if (manifest && meta.plaintext_size !== undefined && Number(manifest.size) !== Number(meta.plaintext_size)) {
    throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '清单大小与元数据不一致')
  }

  const chunkCount = Number(meta.chunk_count)
  let done = 0
  let plain
  try {
    await runPool(
      [...Array(chunkCount).keys()],
      async (index) => {
        if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
        const bytes = await api.getChunk({ transferId, downloadId: prelude.downloadId, index })
        unpack.feed(index, bytes)
        done += bytes.length
        report({ phase: 'downloading', done, total: meta.total_ciphertext_bytes || done, message: `下载块 ${index + 1}/${chunkCount}` })
      },
      { concurrency: config.uploadConcurrency, signal },
    )

    report({ phase: 'decrypting', done: 0, total: Number(manifest?.size ?? meta.plaintext_size), message: '端侧验签并解密' })
    const finished = unpack.finish()
    plain = finished.plain
    if (Number(finished.meta.size) !== plain.length) {
      throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '解密结果与清单大小不一致')
    }
  } finally {
    unpack.close()
  }

  const finalMeta = unpack.meta || {}
  // §13 #18：包内 SENDER_PUB 派生的码必须与列表里的发送方码一致（内核自证之后的第二道核对）
  if (finalMeta.sender_code && meta.sender_code && finalMeta.sender_code !== meta.sender_code) {
    throw new CryptoError('CRYPTO_SENDER_MISMATCH', `${meta.sender_code} ≠ ${finalMeta.sender_code}`)
  }
  const blob = new Blob([plain], { type: finalMeta.mime || 'application/octet-stream' })
  if (save) {
    report({ phase: 'saving', done: plain.length, total: plain.length, message: '落盘' })
    save(blob, safeFileName(finalMeta.name))
  }
  if (ack) {
    report({ phase: 'acking', done: plain.length, total: plain.length, message: '确认取件（服务端随即删除密文）' })
    await api.ack({ transferId, downloadId: prelude.downloadId })
  }
  info('接收完成', { bytes: plain.length, chunks: chunkCount })
  report({ phase: 'done', done: plain.length, total: plain.length, message: '已取回' })
  return {
    transferId,
    name: finalMeta.name,
    mime: finalMeta.mime,
    size: plain.length,
    chunkCount,
    blob,
    senderCode: meta.sender_code,
  }
}

/** 文件名只保留 basename（契约 §3.3），挡掉控制字符与路径分隔符。 */
export function safeFileName(name) {
  const base = String(name || 'file').split(/[\\/]/).pop()
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f]/g, '').slice(0, 255)
  return cleaned || 'file'
}
