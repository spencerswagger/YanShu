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
import { createChunkRouter } from './chunkRouter.js'
import { attemptDirect } from './p2p.js'
import { encodeChunkFrame } from './p2pChunks.js'
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
/**
 * 真流式发送（**默认路径**，常量内存）：
 *   ① 第一遍：`file.slice` 逐块读 → `ys_pack_hash_update`（只留每块 32B 摘要，不攒整包）；
 *   ② 出 prelude（幂等）→ 建传输 → 传 prelude；
 *   ③ 第二遍：逐块 `slice` → `ys_pack_stream_chunk` → 立即 PUT → 释放该块引用。
 * 内存只跟块大小有关（1 MiB），与文件大小无关。
 *
 * P2P 是可选快路：`p2p.signaler` 存在时后台静默试打洞，**默认仍全部走中转**；
 * 用户点确认后由 `chunkRouter` 接管**剩余块**（已传块不重传），直连断开则当块回落中转。
 */
async function sendFileStreaming({
  api,
  kernel,
  session,
  file,
  recipient,
  onProgress,
  signal,
  pendingStore,
  ttlSeconds,
  maxDownloads,
  p2p,
}) {
  const name = file.name || 'file'
  const mime = file.type || 'application/octet-stream'
  const chunkSize = kernel.blockSize || config.chunkSize
  const total = file.size
  const chunkCount = Math.max(1, Math.ceil(total / chunkSize))
  const readSlice = async (i) => {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, total)
    return new Uint8Array(await file.slice(start, end).arrayBuffer())
  }

  report(onProgress, { phase: 'packing', done: 0, total, message: '读取文件（流式）' })
  kernel.streamPackBegin({
    recipientPublic: recipient.publicKey,
    senderPrivate: session.privateKey,
    name,
    mime,
    chunkSize,
    totalSize: total,
    createdAt: Date.now(),
  })

  // 第一遍：只算摘要，不保留任何块
  for (let i = 0; i < chunkCount; i++) {
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
    kernel.streamHashUpdate(await readSlice(i))
    report(onProgress, { phase: 'packing', done: Math.min(total, (i + 1) * chunkSize), total, message: `摘要 ${i + 1}/${chunkCount}` })
  }

  const prelude = kernel.streamPrelude()
  const preludeSm3 = kernel.sm3(prelude)
  report(onProgress, { phase: 'creating', done: 0, total, message: '创建传输' })
  const created = await api.createTransfer({
    recipient_code: recipient.code,
    plaintext_size: total,
    chunk_size: chunkSize,
    chunk_count: chunkCount,
    prelude_len: prelude.length,
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
    fileSize: total,
    chunkSize,
    chunkCount,
    preludeLen: prelude.length,
    preludeSm3: b64uEncode(preludeSm3),
    session: null, // 流式不落会话快照（本来也不攒整包）
    createdAt: Date.now(),
    expiresAt: Date.now() + (ttlSeconds ?? config.defaultTtlSeconds) * 1000,
    state: 'UPLOADING',
    streaming: true,
  })

  await api.putPrelude({ transferId, uploadToken, prelude })

  // 分块路由：默认 putChunk 走中转；用户点切之后剩余块才走 DataChannel
  const router = createChunkRouter({
    putChunk: ({ index, bytes }) => api.putChunk({ transferId, uploadToken, index, bytes }),
  })
  if (p2p?.signaler) startDirectAttempt({ p2p, router, transferId, recipient })

  const missing = await fetchMissing(api, transferId, uploadToken, chunkCount)
  let sent = 0
  const totalBytes = missing.reduce(
    (n, i) => n + Math.min(chunkSize, total - i * chunkSize),
    0,
  )
  const headerLen = kernel.segmenter.recordHeaderLen
  await runPool(
    missing,
    async (index) => {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      const pt = await readSlice(index)
      const record = kernel.streamChunk(index, pt)
      // 传输切片 = `CHUNK_CT‖TAG`（pt+16）：块记录头 16B **不上传**，接收侧按 §6.3 重建
      const slice = record.subarray(headerLen)
      await router.send(index, slice)
      sent += pt.length
      report(onProgress, { phase: 'uploading', done: sent, total: totalBytes, message: `上传块 ${index + 1}/${chunkCount}` })
    },
    { concurrency: config.uploadConcurrency, signal },
  )

  kernel.streamPackEnd()
  report(onProgress, { phase: 'completing', done: total, total, message: '标记完成' })
  const done = await api.complete({ transferId, uploadToken })
  report(onProgress, { phase: 'done', done: total, total, message: '已发送' })
  info('发送完成（流式）', { bytes: total, chunks: chunkCount })
  return {
    transferId,
    uploadToken,
    recipientCode: recipient.code,
    fileName: name,
    fileSize: total,
    chunkCount,
    preludeLen: prelude.length,
    state: done?.json?.state,
  }
}

export async function sendFile({ api, kernel, session, file, recipient, onProgress, signal, pendingStore, ttlSeconds, maxDownloads, p2p }) {
  const name = file.name || 'file'
  const mime = file.type || 'application/octet-stream'

  const canStream = Boolean(kernel?.supportsStreaming)
  if (canStream && file.size > config.streamThresholdBytes) {
    return sendFileStreaming({
      api,
      kernel,
      session,
      file,
      recipient,
      onProgress,
      signal,
      pendingStore,
      ttlSeconds,
      maxDownloads,
      p2p,
    })
  }
  if (file.size > config.maxPackSize) {
    const err = new Error(
      canStream
        ? `文件 ${file.size} 字节超过上限 ${config.maxPackSize} 字节`
        : `文件 ${file.size} 字节超过当前内核上限 ${config.maxPackSize} 字节（整包接口）`,
    )
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
      p2p,
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
  p2p,
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

      // 直连路由：默认全部走中转；用户点切之后剩余块才走 DataChannel
      const router = createChunkRouter({
        putChunk: ({ index, bytes }) => api.putChunk({ transferId, uploadToken, index, bytes }),
      })
      if (p2p?.signaler) startDirectAttempt({ p2p, router, transferId, recipient })

      if (needPrelude) {
        report(onProgress, { phase: 'uploading', done: 0, total: fileSize, message: '上传 prelude' })
        await api.putPrelude({ transferId, uploadToken, prelude })
      }
      if (attempt === 1 && !resume) {
        missing = await fetchMissing(api, transferId, uploadToken, chunkCount)
      }
      await uploadSlices({ api, transferId, uploadToken, slices, chunkCount, missing, onProgress, signal, router })

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

/**
 * 后台静默试打洞：**不阻塞中转**，失败一律静默（不弹错）。
 * 打通后把"是否切换"交给用户：`p2p.onCandidate({ enable })`，用户不点就继续走中转。
 */
function startDirectAttempt({ p2p, router, transferId, recipient }) {
  const { signaler, stunUrls = [], onStatus, onCandidate } = p2p
  Promise.resolve()
    .then(() =>
      attemptDirect({
        signaler,
        wsUrl: signaler?.wsUrl,
        transferId,
        peerCode: recipient?.code,
        stunUrls,
        timeoutMs: p2p.timeoutMs,
      }),
    )
    .then((conn) => {
      if (!conn) {
        onStatus?.('unavailable') // 静默：默认路径本来就是中转
        return
      }
      const channel = conn.channel
      channel.onclose = () => {
        // 直连断了：立刻回中转继续（不丢块、不重复 ack）
        router.disableDirect()
        onStatus?.('fallback')
      }
      onCandidate?.({
        enable: () => {
          router.enableDirect({ send: (index, bytes) => channel.send(encodeChunkFrame(index, bytes)) })
          onStatus?.('direct')
        },
        close: conn.close,
      })
    })
    .catch(() => onStatus?.('unavailable'))
}

async function uploadSlices({ api, transferId, uploadToken, slices, chunkCount, missing, onProgress, signal, router }) {
  if (!missing.length) return
  const totalBytes = missing.reduce((n, i) => n + slices[i].length, 0)
  let sent = 0
  await runPool(
    missing,
    async (index) => {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      if (!slices[index]) throw new CryptoError('CRYPTO_CHUNK_MISSING', `切片 ${index} 不存在`)
      if (router) await router.send(index, slices[index])
      else await api.putChunk({ transferId, uploadToken, index, bytes: slices[index] })
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
