/**
 * 发送编排：本地文件 → 端侧内核打包（整包）→ 切成 prelude + 块切片 → 上传 → complete。
 *
 * 与契约的对应关系：
 * - 包结构/清单/签名全由内核产出，Web 只按 §4.2 的算术把整包切成 `prelude` 与
 *   `CHUNK_CT‖TAG` 切片（`crypto/layout.js`），不解析任何包内字段；
 * - 上传顺序照 API.md §6：`POST /transfers` → `PUT prelude` → `PUT chunks/{i}` → `POST complete`；
 * - 续传照 §6.5 / §8.3：`GET /status` 的 `bitmap/missing` 决定只补哪些块。
 *
 * 已知边界（内核当前是整包接口 `ys_pack`）：整份文件要进内存，所以有 `maxPackSize` 上限；
 * 超过上限提示等流式接口（Ark 已把"流式分块 API"列入 v1 不做的排期）。
 */
import { config } from '../config.js'
import { CryptoError } from '../crypto/errors.js'
import { encode as b64uEncode } from '../lib/base64url.js'
import { decodeBitmap, missingIndexes } from '../lib/bitmap.js'
import { runPool } from '../lib/pool.js'
import { info } from '../lib/log.js'

function idempotencyKey() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return b64uEncode(bytes)
}

const report = (onProgress, patch) => onProgress?.(patch)

/**
 * @param {object} p
 * @param {object} p.api
 * @param {object} p.kernel
 * @param {object} p.session        含 privateKey / publicKey / code
 * @param {File|Blob} p.file        要发的文件
 * @param {{code:string, nickname:string, publicKey:Uint8Array}} p.recipient
 */
export async function sendFile(params) {
  // 服务端重启会让 upload_token 立即失效（token secret 变化）：401 时自动重建一次传输
  try {
    return await sendOnce({ ...params, attempt: 1 })
  } catch (err) {
    if (!err?.authFailed || params.signal?.aborted) throw err
    info('上传凭证失效（服务端可能重启），自动重建传输', { status: err.status })
    params.onProgress?.({ phase: 'creating', done: 0, total: 0, message: '凭证失效，正在重建传输…' })
    return sendOnce({ ...params, attempt: 2 })
  }
}

async function sendOnce({ api, kernel, session, file, recipient, onProgress, signal, pendingStore, ttlSeconds, maxDownloads, attempt }) {
  void attempt
  const name = file.name || 'file'
  const mime = file.type || 'application/octet-stream'

  if (file.size > config.maxPackSize) {
    const err = new Error(`文件 ${file.size} 字节超过当前内核上限 ${config.maxPackSize} 字节（整包接口）`)
    err.code = 'FILE_TOO_LARGE'
    throw err
  }

  report(onProgress, { phase: 'packing', done: 0, total: file.size, message: '读取文件' })
  if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
  const data = new Uint8Array(await file.arrayBuffer())

  report(onProgress, { phase: 'packing', done: 0, total: file.size, message: '端侧打包（加密+签名）' })
  const pack = kernel.pack({
    data,
    name,
    mime,
    recipientPublic: recipient.publicKey,
    senderPrivate: session.privateKey,
    blockSize: kernel.blockSize || config.chunkSize,
  })

  const chunkSize = kernel.blockSize || config.chunkSize
  // 会话式包装在 JS 侧：prelude + 第 i 块切片 + 可导出/恢复（内核只提供整包接口）
  const packSession = kernel.openPackSession({ pack, plaintextSize: data.length, chunkSize })
  const { prelude, slices, preludeLen, chunkCount } = packSession
  const preludeSm3 = kernel.sm3(prelude)

  report(onProgress, { phase: 'creating', done: 0, total: data.length, message: '创建传输' })
  const created = await api.createTransfer({
    recipient_code: recipient.code,
    plaintext_size: data.length,
    chunk_size: chunkSize,
    chunk_count: chunkCount,
    prelude_len: preludeLen,
    prelude_sm3: b64uEncode(preludeSm3),
    ttl_seconds: ttlSeconds ?? config.defaultTtlSeconds,
    max_downloads: maxDownloads ?? config.defaultMaxDownloads,
    idempotency_key: idempotencyKey(),
  })

  const transferId = created.transfer_id
  const uploadToken = created.upload_token

  await pendingStore?.put(transferId, {
    kind: 'send',
    transferId,
    uploadToken,
    recipientCode: recipient.code,
    recipientNickname: recipient.nickname,
    fileName: name,
    fileSize: data.length,
    chunkSize,
    chunkCount,
    preludeLen,
    preludeSm3: b64uEncode(preludeSm3),
    // 会话快照（整包是密文）：≤ maxPersistPack 才留，刷新后靠它恢复
    session: pack.length <= config.maxPersistPack ? packSession.export() : null,
    packSize: pack.length,
    createdAt: Date.now(),
    state: 'UPLOADING',
  })

  report(onProgress, { phase: 'uploading', done: 0, total: data.length, message: '上传 prelude' })
  await api.putPrelude({ transferId, uploadToken, prelude })

  const missing = await fetchMissing(api, transferId, uploadToken, chunkCount)
  await uploadSlices({ api, transferId, uploadToken, slices, chunkCount, missing, onProgress, signal })

  report(onProgress, { phase: 'completing', done: data.length, total: data.length, message: '标记完成' })
  const done = await api.complete({ transferId, uploadToken })
  await pendingStore?.put(transferId, {
    kind: 'send',
    transferId,
    uploadToken,
    recipientCode: recipient.code,
    recipientNickname: recipient.nickname,
    fileName: name,
    fileSize: data.length,
    chunkSize,
    chunkCount,
    preludeLen,
    preludeSm3: b64uEncode(preludeSm3),
    createdAt: Date.now(),
    state: done?.json?.state || 'READY',
    doneAt: Date.now(),
  })
  packSession.close()
  info('发送完成', { bytes: data.length, chunks: chunkCount })
  report(onProgress, { phase: 'done', done: data.length, total: data.length, message: '已发送' })
  return {
    transferId,
    uploadToken,
    recipientCode: recipient.code,
    fileName: name,
    fileSize: data.length,
    chunkCount,
    preludeLen,
    state: done?.json?.state,
  }
}

/**
 * 续传：本机存着密文包时，直接从 `/status` 的缺失块补齐。
 * 没有包（文件太大或清理过）就只能重发——整包接口没法重建会话。
 */
export async function resumeSend({ api, kernel, session, record, onProgress, signal, pendingStore }) {
  if (!record?.session) {
    const err = new Error('本机没有保留会话快照，无法续传；请重新发送')
    err.code = 'RESUME_UNAVAILABLE'
    throw err
  }
  const packSession = kernel.resumePackSession(record.session)
  const { prelude, slices, chunkCount } = packSession
  const status = await api.uploadStatus({ transferId: record.transferId, uploadToken: record.uploadToken })
  if (status?.state && status.state !== 'UPLOADING') {
    await pendingStore?.put(record.transferId, { ...record, state: status.state })
    return { transferId: record.transferId, state: status.state, resumed: false }
  }
  if (!status?.prelude_received) {
    await api.putPrelude({ transferId: record.transferId, uploadToken: record.uploadToken, prelude })
  }
  const missing = status?.bitmap
    ? missingIndexes(decodeBitmap(status.bitmap, chunkCount))
    : await fetchMissing(api, record.transferId, record.uploadToken, chunkCount)

  await uploadSlices({
    api,
    transferId: record.transferId,
    uploadToken: record.uploadToken,
    slices,
    chunkCount,
    missing,
    onProgress,
    signal,
  })
  const done = await api.complete({ transferId: record.transferId, uploadToken: record.uploadToken })
  packSession.close()
  await pendingStore?.put(record.transferId, { ...record, state: done?.json?.state || 'READY', doneAt: Date.now() })
  return { transferId: record.transferId, state: done?.json?.state, resumed: true, missing: missing.length }
}

async function fetchMissing(api, transferId, uploadToken, chunkCount) {
  const json = (await api.uploadStatus({ transferId, uploadToken })) || {}
  if (json.bitmap) return missingIndexes(decodeBitmap(json.bitmap, chunkCount))
  if (Array.isArray(json.missing)) {
    const out = []
    for (const range of json.missing) for (let i = range.start; i < range.start + range.count; i++) out.push(i)
    return out
  }
  return [...Array(chunkCount).keys()]
}

async function uploadSlices({ api, transferId, uploadToken, slices, chunkCount, missing, onProgress, signal }) {
  if (!missing.length) return
  const totalBytes = missing.reduce((n, i) => n + slices[i].length, 0)
  let sent = 0
  await runPool(
    missing,
    async (index) => {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      if (!slices[index]) throw new CryptoError('CRYPTO_CHUNK_MISSING', `切片 ${index} 不存在`)
      await api.putChunk({ transferId, uploadToken, index, bytes: slices[index] })
      sent += slices[index].length
      report(onProgress, {
        phase: 'uploading',
        done: sent,
        total: totalBytes,
        message: `上传块 ${index + 1}/${chunkCount}`,
      })
    },
    { concurrency: config.uploadConcurrency, signal },
  )
}

export { decodeBitmap, missingIndexes }
