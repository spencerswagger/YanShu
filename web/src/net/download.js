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
import { takeChunkBytes } from './p2pChunks.js'
import { info } from '../lib/log.js'
import { config } from '../config.js'
import { bytes } from '../lib/bytes.js'
import { createChunkPacer } from './chunkPacer.js'

/** 让出一帧：`unpack.finish()` 是同步的，不让出的话「解密中」这段永远画不出来 */
function nextPaint() {
  if (typeof requestAnimationFrame !== 'function') return new Promise((r) => setTimeout(r, 0))
  return new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)))
}

function sleepAbortable(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException('aborted', 'AbortError'))
    const t = setTimeout(() => {
      signal?.removeEventListener?.('abort', onAbort)
      resolve()
    }, ms)
    function onAbort() {
      clearTimeout(t)
      reject(new DOMException('aborted', 'AbortError'))
    }
    signal?.addEventListener?.('abort', onAbort, { once: true })
  })
}

/** 单块只做一次取数（直连优先，失败回中转）；429/5xx 由调用方按 pacer 处理，不在这里吞 */
async function fetchChunkOnce({ directBuffer, index, relayGet }) {
  if (!directBuffer) return { bytes: await relayGet(index), source: 'relay' }
  return takeChunkBytes({ directBuffer, index, getChunk: relayGet })
}

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
export async function receiveTransfer(params) {
  const canStream = Boolean(params.kernel?.supportsStreaming && (params.sinkFactory || params.sink))
  if (canStream) {
    try {
      return await receiveStreaming({ ...params, attempt: 1 })
    } catch (err) {
      const leaseLost = err?.status === 401 || err?.code === 'DOWNLOAD_NOT_STARTED'
      if (!leaseLost || params.signal?.aborted) throw err
      info('下载租约失效，重新开租约取一次（流式）')
      return receiveStreaming({ ...params, attempt: 2 })
    }
  }
  try {
    return await receiveOnce({ ...params, attempt: 1 })
  } catch (err) {
    const leaseLost = err?.status === 401 || err?.code === 'DOWNLOAD_NOT_STARTED'
    if (!leaseLost || params.signal?.aborted) throw err
    info('下载租约失效，重新开租约取一次')
    params.onProgress?.({ phase: 'prelude', done: 0, total: 0, message: '租约失效，重新取包头…' })
    return receiveOnce({ ...params, attempt: 2 })
  }
}

const reportStream = (onProgress) => (patch) => onProgress?.(patch)

/**
 * 真流式接收（**默认路径**，常量内存）：
 *   ① prelude → `ys_unpack_stream_begin`（验签 + 清单校验，拿到 meta）；
 *   ② 逐块取切片 → 按 §6.3 重建 16B 记录头 → `ys_unpack_stream_chunk` → **立即交给 sink 写出**；
 *   ③ `ys_unpack_stream_end()` 全部到齐才算成功（缺块/摘要不符 → 报错，不会交出残缺文件）。
 *
 * 直连（P2P）与中转**共用同一个 sink**：`directBuffer` 里有这块就用它，没有就 `GET`；
 * 直连块喂不进内核（长度/序号不对）时当块改走中转补齐 —— 直连只是快路，不影响完整性。
 */
async function receiveStreaming({
  api,
  kernel,
  session,
  transferId,
  onProgress,
  signal,
  sinkFactory,
  save,
  pacer: injectedPacer,
  ack = true,
  directBuffer,
}) {
  const prelude = await api.getPrelude(transferId)
  const report = reportStream(onProgress)
  if (!prelude.downloadId) {
    throw new CryptoError('DOWNLOAD_NOT_STARTED', '取包头未拿到 download_id（无法下载块）')
  }
  report({ phase: 'prelude', done: 0, total: 0, message: '取回包头并验签…', verified: false })
  const meta = kernel.streamUnpackBegin(prelude.bytes, session.privateKey)
  const chunkCount = Number(meta.chunk_count)
  const totalSize = Number(meta.size)
  report({
    phase: 'prelude',
    done: 0,
    total: totalSize,
    message: `来自 ${meta.sender_code || ''}：${meta.name || '未命名'} · ${totalSize} 字节 · ${chunkCount} 块`,
    meta: { name: meta.name || '未命名', size: totalSize, senderCode: meta.sender_code, chunkCount },
    verified: false,
  })

  const sink = await (sinkFactory ? sinkFactory(meta) : createMemorySink())
  const relayGet = (i) => api.getChunk({ transferId, downloadId: prelude.downloadId, index: i, retry: false })
  const unpackSlice = (index, slice) =>
    kernel.streamUnpackChunk(
      bytes(kernel.segmenter.buildRecordHeader(index, slice.length - 16, chunkCount), slice),
    )

  // 客户端自己排队：契约 §11.1 把内容端点限到「按传输 600 次/分、按 IP 120 次/分」（最紧 2 次/秒）。
  const pacer = injectedPacer || createChunkPacer({ ratePerSec: config.chunkRatePerSec })

  /**
   * 取一块（含重试策略）：
   * - 429 → 交给 pacer（按 `Retry-After` 等，不套 5s 地板），同一块原地重试；连吃 9 次才报错；
   * - 500/502/503/504 → 1s/2s/4s 原地重试最多 3 次（**不能让学生单次 5xx 打死整条 1 GiB 下载**：
   *   `retry:false` 关掉了 client 层 withRetry，这层必须自己补上，否则比 main 还差）；
   * - 其它错误 → 直接抛（不静默、不吞）。
   */
  const fetchPaced = async (index, { relayOnly = false } = {}) => {
    let throttleStreak = 0
    let transient = 0
    for (;;) {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      await pacer.acquire()
      try {
        const picked = relayOnly
          ? { bytes: await relayGet(index), source: 'relay' }
          : await fetchChunkOnce({ directBuffer, index, relayGet })
        pacer.onSuccess()
        return picked
      } catch (err) {
        if (err?.status === 429) {
          throttleStreak += 1
          const waitMs = pacer.onThrottled(err.retryAfter)
          report({
            phase: 'downloading',
            done: fetched,
            decrypted: done,
            total: totalSize,
            message: `服务端限速：${Math.ceil(waitMs / 1000)} 秒后继续第 ${index + 1}/${chunkCount} 块（${pacer.summary()}）`,
            throttled: pacer.throttledCount,
          })
          if (throttleStreak > 8) {
            throw new ApiError({
              code: 'RATE_LIMITED',
              status: 429,
              retryAfter: err.retryAfter,
              message: `连续 ${throttleStreak} 次被限速，已暂停（可稍后重试，不会交残缺文件）`,
            })
          }
          await sleepAbortable(waitMs, signal)
          continue
        }
        if ([500, 502, 503, 504].includes(err?.status)) {
          transient += 1
          if (transient > 3) throw err
          const waitMs = 1000 * 2 ** (transient - 1) // 1s / 2s / 4s
          report({
            phase: 'downloading',
            done: fetched,
            decrypted: done,
            total: totalSize,
            message: `服务端 ${err.status}：${Math.round(waitMs / 1000)} 秒后重试第 ${index + 1}/${chunkCount} 块（第 ${transient}/3 次）`,
          })
          await sleepAbortable(waitMs, signal)
          continue
        }
        throw err
      }
    }
  }

  let done = 0 // 已解密并写出的明文字节
  let fetched = 0 // 已取到的密文字节（含尚未解密的块）
  try {
    for (let index = 0; index < chunkCount; index++) {
      const picked = await fetchPaced(index)
      // 先记「已取到」再解密：两个百分比因此会差一块左右，能看出解密落后于网络
      fetched += picked.bytes.length
      report({
        phase: 'downloading',
        done: fetched,
        decrypted: done,
        total: totalSize,
        message: `下载块 ${index + 1}/${chunkCount}`,
      })
      let plain
      try {
        plain = unpackSlice(index, picked.bytes)
      } catch (err) {
        if (picked.source !== 'direct') throw err
        // 直连块不可信 → 当块回落中转补齐（同样走 429/5xx 重试，不交残缺文件）
        plain = unpackSlice(index, (await fetchPaced(index, { relayOnly: true })).bytes)
      }
      await sink.write(plain)
      done += plain.length
      report({
        phase: 'downloading',
        done: fetched,
        decrypted: done,
        total: totalSize,
        message: `解密块 ${index + 1}/${chunkCount}`,
      })
    }
    kernel.streamUnpackEnd()

    report({
      phase: 'saving',
      done: totalSize,
      decrypted: done,
      total: totalSize,
      message: `块已全部处理（${chunkCount} 块 · ${done} 字节），校验并落盘…`,
      verified: true,
    })
    const out = await sink.close()
    // 落盘成功（内存 Blob / OPFS 文件 / 用户选的目标文件）之后，才把文件交给浏览器下载。
    // 「用户选路径」那条在 close() 时已经写到目标位置，不需要再点 <a download>。
    if (save && (out?.blob || out?.file)) {
      report({ phase: 'saving', done: totalSize, total: totalSize, message: '交给浏览器保存…', verified: true })
      await save(out.blob || out.file, out.name || safeFileName(meta.name, meta.ext))
    }
    // OPFS 副本在交给浏览器之后（saveBlob 的 revoke 之后）才清，避免把唯一副本删掉
    await sink.cleanup?.()
  } catch (err) {
    await sink.abort?.()
    throw err
  }

  if (ack) {
    // ack 必须带租约 id（契约 §8.5）：不带会被判 409 DOWNLOAD_NOT_STARTED
    await api.ack({ transferId, downloadId: prelude.downloadId })
  }
  info('接收完成（流式）', { bytes: done, chunks: chunkCount })
  return { name: sink.name, size: done, transferId, dataVerified: true }
}

async function receiveOnce({
  api,
  kernel,
  session,
  transferId,
  senderPublic,
  onProgress,
  signal,
  save,
  ack = true,
  attempt,
  directBuffer,
}) {
  void attempt
  const report = (patch) => onProgress?.(patch)

  const meta = (await api.getTransfer(transferId)) || {}
  if (meta.state === 'REVOKED' || meta.state === 'EXPIRED' || meta.state === 'CONSUMED') {
    throw terminalError(meta.state, meta.terminal_reason)
  }

  // 回退路径（没有流式内核 / 没给 sink）只能整包解、整包拼 Blob：先按 maxPackSize 挡住，
  // 别先把 1 GiB 拉下来再在收尾处被内存撑死（v0.2.4 就是「无报错、无文件」的死龟）。
  const plaintextSize = Number(meta.plaintext_size) || 0
  if (plaintextSize > config.maxPackSize) {
    const err = new Error(
      `当前内核不支持流式解包，${plaintextSize} 字节超过整包上限 ${config.maxPackSize} 字节，无法安全下载（否则会整包进内存）`,
    )
    err.code = 'FILE_TOO_LARGE'
    throw err
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
  if (manifest) {
    // prelude 阶段就能告诉用户"谁发的 / 多大 / 几块"，但**块还没校验**，必须如实标注
    report({
      phase: 'prelude',
      done: 0,
      total: Number(manifest.size),
      message: `来自 ${manifest.sender_code || meta.sender_code}：${manifest.name || '未命名'} · ${manifest.size} 字节 · ${manifest.chunk_count} 块`,
      meta: { name: manifest.name || '未命名', size: Number(manifest.size), senderCode: manifest.sender_code, chunkCount: manifest.chunk_count },
      verified: false,
      scope: unpack.metaScope,
    })
  }
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
        // 直连收到的块优先（`directBuffer` 由直连通道灌入）；没有就走中转，行为与原来一致
        const relayGet = (i) => api.getChunk({ transferId, downloadId: prelude.downloadId, index: i })
        const picked = await takeChunkBytes({ directBuffer, index, getChunk: relayGet })
        let bytes = picked.bytes
        if (picked.source === 'direct') {
          // 直连块不可信：喂不进内核（长度/序号不对）就当这块没收到，改走中转补齐，
          // 绝不因为"直连半途失败"交出残缺文件。
          try {
            unpack.feed(index, bytes)
          } catch {
            bytes = await relayGet(index)
            unpack.feed(index, bytes)
          }
        } else {
          unpack.feed(index, bytes)
        }
        done += bytes.length
        report({ phase: 'downloading', done, total: meta.total_ciphertext_bytes || done, message: `下载块 ${index + 1}/${chunkCount}` })
      },
      { concurrency: config.uploadConcurrency, signal },
    )

    report({
      phase: 'decrypting',
      done: 0,
      total: Number(manifest?.size ?? meta.plaintext_size),
      message: '端侧验签并解密（块 AEAD + 摘要）',
      verified: false,
    })
    await nextPaint()
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
    report({ phase: 'saving', done: plain.length, total: plain.length, message: '落盘', verified: true })
    // 交付失败要抛（不 ack），别出现「界面说已保存、其实没交出去」
    await save(blob, safeFileName(finalMeta.name, finalMeta.ext))
  }
  if (ack) {
    report({ phase: 'acking', done: plain.length, total: plain.length, message: '确认取件（服务端随即删除密文）' })
    await api.ack({ transferId, downloadId: prelude.downloadId })
  }
  info('接收完成', { bytes: plain.length, chunks: chunkCount })
  report({ phase: 'done', done: plain.length, total: plain.length, message: '已取回（块已校验）', verified: true })
  return {
    transferId,
    name: safeFileName(finalMeta.name, finalMeta.ext),
    mime: finalMeta.mime,
    size: plain.length,
    chunkCount,
    blob,
    senderCode: finalMeta.sender_code || meta.sender_code,
    dataVerified: true,
  }
}

/**
 * 落盘文件名（契约 §3.3 + 空名裁决）：
 * - 只保留 basename，挡掉控制字符与路径分隔符；
 * - **`NAME_LEN = 0` 合法**：显示"未命名"，并保留扩展名降级展示（如 `未命名.txt`）。
 */
export function safeFileName(name, ext) {
  const base = String(name || '').split(/[\\/]/).pop()
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f]/g, '').slice(0, 255)
  if (cleaned) return cleaned
  const suffix = String(ext || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16)
  return suffix ? `未命名.${suffix}` : '未命名'
}
