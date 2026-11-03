/**
 * 发送编排：本地文件 → 端侧内核打包（整包）→ 切成 prelude + 块切片 → 上传 → complete。
 *
 * 与契约的对应关系：
 * - 包结构/清单/签名全由内核产出，Web 只按 §4.2 的算术把整包切成 `prelude` 与
 *   `CHUNK_CT‖TAG` 切片（`crypto/layout.js`），不解析任何包内字段；
 * - 上传顺序照 API.md §6：`POST /transfers` → `PUT prelude` → `PUT chunks/{i}` → `POST complete`；
 * - 续传照 §6.5 / §8.3：`GET /status` 的 `bitmap/missing` 决定只补哪些块。
 *
 * 凭证自愈（真 `sm2` 环境会真的发生）：
 * - 服务端递增 `TOKEN_EPOCH` / 轮换 secret 后，旧 `upload_token` 会返回 `401`（`AUTH_TOKEN_STALE` 等）；
 * - 这里不把用户卡死：**重新创建一次传输并用同一个包会话重传**，界面提示"凭证失效，正在重建传输…"；
 * - 下载侧的租约失效在 `download.js` 里重开租约处理。
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
export async function sendFile({ api, kernel, session, file, recipient, onProgress, signal, pendingStore, ttlSeconds, maxDownloads }) {
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
  const packSession = kernel.openPackSession({ pack, plaintextSize: data.length, chunkSize })
  try {
    return await uploadSession({
      api,
      kernel,
      packSession,
      pack,
      name,
      mime,
      fileSize: data.length,
      recipient,
      onProgress,
      signal,
      pendingStore,
      ttlSeconds,
      maxDownloads,
    })
  } finally {
    packSession.close()
  }
}

/**
 * 续传：本机存着包会话快照时，用新 token / 旧快照把剩下的块补齐。
 * 若旧 token 已失效（401），自动重建一次传输再传（凭证自愈）。
 */
export async function resumeSend({ api, kernel, session, record, onProgress, signal, pendingStore }) {
  if (!record?.session) {
    const err = new Error('本机没有保留会话快照，无法续传；请重新发送')
    err.code = 'RESUME_UNAVAILABLE'
    throw err
  }
  const packSession = kernel.resumePackSession(record.session)
  try {
    return await uploadSession({
      api,
      kernel,
      packSession,
      pack: packSession.pack,
      name: record.fileName,
      mime: record.mime || 'application/octet-stream',
      fileSize: record.fileSize,
      recipient: { code: record.recipientCode, nickname: record.recipientNickname, publicKey: null },
      onProgress,
      signal,
      pendingStore,
      resume: { transferId: record.transferId, uploadToken: record.uploadToken },
    })
  } finally {
    packSession.close()
  }
}

/**
 * 传输编排主体（发送与续传共用）。凭证失效时最多重建一次。
 */
async function uploadSession({
  api,
  kernel,
  packSession,
  pack,
  name,
  mime,
  fileSize,
  recipient,
  onProgress,
  signal,
  pendingStore,
  ttlSeconds,
  maxDownloads,
  resume,
}) {
  const { prelude, slices, preludeLen, chunkCount } = packSession
  const preludeSm3 = kernel.sm3(prelude)

  let attempt = 0
  for (;;) {
    attempt += 1
    try {
      // ① 续传：先按旧 token 探进度；拿不到（401）就直接进入重建
      let transferId
      let uploadToken
      let missing = [...Array(chunkCount).keys()]
      let needPrelude = true

      if (resume && attempt === 1) {
        transferId = resume.transferId
        uploadToken = resume.uploadToken
        const status = (await api.uploadStatus({ transferId, uploadToken })) || {}
        if (status.state && status.state !== 'UPLOADING') {
          await pendingStore?.put(transferId, { ...(await pendingStore?.get(transferId)), state: status.state })
          return { transferId, state: status.state, resumed: false }
        }
        needPrelude = !status.prelude_received
        if (status.bitmap) missing = missingIndexes(decodeBitmap(status.bitmap, chunkCount))
        else if (Array.isArray(status.missing)) {
          missing = []
          for (const r of status.missing) for (let i = r.start; i < r.start + r.count; i++) missing.push(i)
        }
        report(onProgress, {
          phase: 'uploading',
          done: 0,
          total: fileSize,
          message: `续传：还缺 ${missing.length} 块`,
        })
      } else {
        report(onProgress, { phase: 'creating', done: 0, total: fileSize, message: '创建传输' })
        const created = await api.createTransfer({
          recipient_code: recipient.code,
          plaintext_size: fileSize,
          chunk_size: packSession.chunkSize,
          chunk_count: chunkCount,
          prelude_len: preludeLen,
          prelude_sm3: b64uEncode(preludeSm3),
          ttl_seconds: ttlSeconds ?? config.defaultTtlSeconds,
          max_downloads: maxDownloads ?? config.defaultMaxDownloads,
          idempotency_key: idempotencyKey(),
        })
        transferId = created.transfer_id
        uploadToken = created.upload_token
        await pendingStore?.put(transferId, {
          kind: 'send',
          transferId,
          uploadToken,
          recipientCode: recipient.code,
          recipientNickname: recipient.nickname,
          fileName: name,
          mime,
          fileSize,
          chunkSize: packSession.chunkSize,
          chunkCount,
          preludeLen,
          preludeSm3: b64uEncode(preludeSm3),
          session: pack.length <= config.maxPersistPack ? packSession.export() : null,
          packSize: pack.length,
          createdAt: Date.now(),
          state: 'UPLOADING',
        })
      }

      if (needPrelude) {
        report(onProgress, { phase: 'uploading', done: 0, total: fileSize, message: '上传 prelude' })
        await api.putPrelude({ transferId, uploadToken, prelude })
      }
      if (attempt === 1 && !resume) {
        missing = await fetchMissing(api, transferId, uploadToken, chunkCount)
      }
      await uploadSlices({ api, transferId, uploadToken, slices, chunkCount, missing, onProgress, signal })

      report(onProgress, { phase: 'completing', done: fileSize, total: fileSize, message: '标记完成' })
      const done = await api.complete({ transferId, uploadToken })
      await pendingStore?.put(transferId, {
        kind: 'send',
        transferId,
        uploadToken,
        recipientCode: recipient.code,
        recipientNickname: recipient.nickname,
        fileName: name,
        mime,
        fileSize,
        chunkSize: packSession.chunkSize,
        chunkCount,
        preludeLen,
        preludeSm3: b64uEncode(preludeSm3),
        createdAt: Date.now(),
        state: done?.json?.state || 'READY',
        doneAt: Date.now(),
      })
      info('发送完成', { bytes: fileSize, chunks: chunkCount })
      report(onProgress, { phase: 'done', done: fileSize, total: fileSize, message: '已发送' })
      return {
        transferId,
        uploadToken,
        recipientCode: recipient.code,
        fileName: name,
        fileSize,
        chunkCount,
        preludeLen,
        state: done?.json?.state,
      }
    } catch (err) {
      // 凭证失效（token 轮换 / EPOCH 递增 / 服务端重启）→ 重建一次，用同一个包会话重传
      if (attempt === 1 && err?.authFailed && !signal?.aborted) {
        info('上传凭证失效，自动重建传输', { status: err.status })
        report(onProgress, { phase: 'creating', done: 0, total: fileSize, message: '凭证失效，正在重建传输…' })
        resume = null
        continue
      }
      throw err
    }
  }
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
