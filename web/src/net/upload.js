/**
 * 发送编排：本地文件 → 端侧加密（WASM）→ prelude + 分块上传 → complete。
 *
 * 与契约的对应关系：
 * - 包结构/清单/签名全部由内核产出，这里只拿 "prelude 整段" 与 "第 i 块切片"（CRYPTO-PACK §4.3 / §12）；
 * - 上传顺序：`POST /transfers` → `PUT prelude` → `PUT chunks/{i}` → `POST complete`（API.md §6）；
 * - 刷新后续传：`GET /transfers/{id}/status` 的 `bitmap` / `missing` 决定只补哪些块（§6.5 / §8.3）。
 *
 * 隐私：日志里只有块序号/字节数/状态，不含文件名、明文、密钥。
 */
import { config } from '../config.js'
import { CryptoError } from '../crypto/errors.js'
import { encode as b64uEncode, decode as b64uDecode } from '../lib/base64url.js'
import { decodeBitmap, missingIndexes } from '../lib/bitmap.js'
import { runPool } from '../lib/pool.js'
import { info } from '../lib/log.js'

export function chunkCountOf(size, chunkSize) {
  return Math.max(1, Math.ceil(size / chunkSize))
}

export async function readFileChunk(file, index, chunkSize) {
  const start = index * chunkSize
  const end = Math.min(start + chunkSize, file.size)
  return new Uint8Array(await file.slice(start, end).arrayBuffer())
}

function idempotencyKey() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return b64uEncode(bytes)
}

function report(onProgress, patch) {
  onProgress?.(patch)
}

/**
 * @param {object} p
 * @param {object} p.api            createApi 的返回值
 * @param {object} p.kernel         端侧内核
 * @param {object} p.session        含 identity / code
 * @param {File|Blob} p.file        待发文件（只需要 name/size/type/slice）
 * @param {{code:string, nickname:string, publicKey:Uint8Array}} p.recipient
 * @param {(p:object)=>void} [p.onProgress]
 * @param {AbortSignal} [p.signal]
 * @param {object} [p.pendingStore]  保存续传记录（IndexedDB 视图）
 */
export async function sendFile({ api, kernel, session, file, recipient, onProgress, signal, pendingStore, ttlSeconds, maxDownloads }) {
  const chunkSize = config.chunkSize
  const chunkCount = chunkCountOf(file.size, chunkSize)
  const name = file.name || 'file'
  const mime = file.type || 'application/octet-stream'

  report(onProgress, { phase: 'hashing', done: 0, total: file.size, message: '读取并计算块摘要' })

  const handle = kernel.packOpen({
    identity: session.identity,
    recipientPublic: recipient.publicKey,
    name,
    mime,
    plaintextSize: file.size,
    chunkSize,
    createdAt: Date.now(),
  })

  try {
    // 第一遍：逐块摘要（清单要进 prelude，所以必须先读完；内存只驻留一个块）
    for (let i = 0; i < chunkCount; i++) {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      const plain = await readFileChunk(file, i, chunkSize)
      kernel.packDigest(handle, i, plain)
      report(onProgress, {
        phase: 'hashing',
        done: Math.min((i + 1) * chunkSize, file.size),
        total: file.size,
        message: `摘要 ${i + 1}/${chunkCount}`,
      })
    }

    const prelude = kernel.packSeal(handle)
    const infoPack = kernel.packInfo(handle)
    if (infoPack.chunkCount !== chunkCount || infoPack.plaintextSize !== file.size) {
      throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '内核回报的块数/大小与文件不一致')
    }
    const preludeSm3 = kernel.sm3(prelude)

    report(onProgress, { phase: 'creating', done: 0, total: file.size, message: '创建传输' })

    const created = await api.createTransfer({
      recipient_code: recipient.code,
      plaintext_size: file.size,
      chunk_size: infoPack.chunkSize,
      chunk_count: infoPack.chunkCount,
      prelude_len: prelude.length,
      prelude_sm3: b64uEncode(preludeSm3),
      ttl_seconds: ttlSeconds ?? config.defaultTtlSeconds,
      max_downloads: maxDownloads ?? config.defaultMaxDownloads,
      idempotency_key: idempotencyKey(),
    })

    const transferId = created.transfer_id
    const uploadToken = created.upload_token

    // 立刻落一份续传记录：之后任何一步失败/刷新，都能用同一个包会话续上
    const snapshot = b64uEncode(kernel.packExport(handle))
    await pendingStore?.put(transferId, {
      kind: 'send',
      transferId,
      uploadToken,
      recipientCode: recipient.code,
      recipientNickname: recipient.nickname,
      fileName: name,
      fileSize: file.size,
      chunkSize: infoPack.chunkSize,
      chunkCount: infoPack.chunkCount,
      preludeSm3: b64uEncode(preludeSm3),
      preludeLen: prelude.length,
      packSnapshot: snapshot,
      createdAt: Date.now(),
      state: 'UPLOADING',
    })

    report(onProgress, { phase: 'uploading', done: 0, total: file.size, message: '上传 prelude' })
    await api.putPrelude({ transferId, uploadToken, prelude })

    const missing = await fetchMissing(api, transferId, uploadToken, infoPack.chunkCount)
    await uploadChunks({ api, kernel, handle, file, chunkSize, transferId, uploadToken, indexes: missing, chunkCount, onProgress, signal })

    report(onProgress, { phase: 'completing', done: file.size, total: file.size, message: '标记完成' })
    const done = await api.complete({ transferId, uploadToken })
    await pendingStore?.put(transferId, {
      kind: 'send',
      transferId,
      uploadToken,
      recipientCode: recipient.code,
      recipientNickname: recipient.nickname,
      fileName: name,
      fileSize: file.size,
      chunkSize: infoPack.chunkSize,
      chunkCount: infoPack.chunkCount,
      preludeLen: prelude.length,
      preludeSm3: b64uEncode(preludeSm3),
      createdAt: Date.now(),
      state: done?.json?.state || 'READY',
      doneAt: Date.now(),
    })
    info('发送完成', { bytes: file.size, chunks: infoPack.chunkCount })
    report(onProgress, { phase: 'done', done: file.size, total: file.size, message: '已发送' })
    return {
      transferId,
      uploadToken,
      recipientCode: recipient.code,
      fileName: name,
      fileSize: file.size,
      chunkCount,
      state: done?.json?.state,
    }
  } finally {
    try {
      kernel.packClose(handle)
    } catch {
      /* 关闭失败不影响结果 */
    }
  }
}

/**
 * 续传：从本地快照恢复同一个包会话，只补 `missing` 的块。
 * 需要用户重新选同一个文件（浏览器拿不到上次的文件句柄）。
 */
export async function resumeSend({ api, kernel, session, record, file, onProgress, signal, pendingStore }) {
  if (!record?.packSnapshot) throw new CryptoError('CRYPTO_BAD_ARGUMENT', '缺少续传快照')
  if (file.size !== record.fileSize) throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '所选文件与待续传文件大小不一致')

  const handle = kernel.packImport(b64uDecode(record.packSnapshot))
  try {
    const prelude = kernel.packSeal(handle)
    const infoPack = kernel.packInfo(handle)
    if (infoPack.chunkCount !== record.chunkCount) {
      throw new CryptoError('CRYPTO_LENGTH_INCONSISTENT', '快照块数与原记录不一致')
    }

    const json = (await api.uploadStatus({ transferId: record.transferId, uploadToken: record.uploadToken })) || {}
    if (json.state && json.state !== 'UPLOADING') {
      // 已经在 READY/其它态：不再重复传块
      await pendingStore?.put(record.transferId, { ...record, state: json.state })
      return { transferId: record.transferId, state: json.state, resumed: false }
    }

    const missing = json.bitmap
      ? missingIndexes(decodeBitmap(json.bitmap, infoPack.chunkCount))
      : await fetchMissing(api, record.transferId, record.uploadToken, infoPack.chunkCount)

    if (!json.prelude_received) {
      await api.putPrelude({ transferId: record.transferId, uploadToken: record.uploadToken, prelude })
    }

    await uploadChunks({
      api,
      kernel,
      handle,
      file,
      chunkSize: record.chunkSize,
      transferId: record.transferId,
      uploadToken: record.uploadToken,
      indexes: missing,
      chunkCount: infoPack.chunkCount,
      onProgress,
      signal,
    })

    const done = await api.complete({ transferId: record.transferId, uploadToken: record.uploadToken })
    await pendingStore?.put(record.transferId, { ...record, state: done?.json?.state || 'READY', doneAt: Date.now() })
    return { transferId: record.transferId, state: done?.json?.state, resumed: true, missing: missing.length }
  } finally {
    try {
      kernel.packClose(handle)
    } catch {
      /* ignore */
    }
  }
}

async function fetchMissing(api, transferId, uploadToken, chunkCount) {
  const json = (await api.uploadStatus({ transferId, uploadToken })) || {}
  if (json.bitmap) return missingIndexes(decodeBitmap(json.bitmap, chunkCount))
  if (Array.isArray(json.missing)) {
    const out = []
    for (const range of json.missing) {
      for (let i = range.start; i < range.start + range.count; i++) out.push(i)
    }
    return out
  }
  return [...Array(chunkCount).keys()]
}

async function uploadChunks({ api, kernel, handle, file, chunkSize, transferId, uploadToken, indexes, chunkCount, onProgress, signal }) {
  if (indexes.length === 0) return
  const sentBytes = indexes.reduce((n, i) => {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, file.size)
    return n + (end - start)
  }, 0)
  let doneBytes = 0

  await runPool(
    indexes,
    async (index) => {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      const plain = await readFileChunk(file, index, chunkSize)
      const slice = kernel.packChunk(handle, index, plain)
      await api.putChunk({ transferId, uploadToken, index, bytes: slice })
      doneBytes += plain.length
      report(onProgress, {
        phase: 'uploading',
        done: doneBytes,
        total: sentBytes,
        message: `上传块 ${index + 1}/${chunkCount}`,
      })
    },
    { concurrency: config.uploadConcurrency, signal },
  )
}

export { decodeBitmap, missingIndexes }
