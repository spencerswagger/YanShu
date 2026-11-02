#!/usr/bin/env node
/**
 * 开发用中转（**只用于本地联调**，不是雁书服务端实现）。
 *
 * 存在理由：Core 的 HTTP 服务还没跑起来，而 "prelude + 块切片" 的上传/续传/终结态
 * 这些前端行为必须先能验证。所以这里按 `docs/API.md` 的路径、字段名、错误码做一个
 * 内存版最小实现——**只存不透明字节**，不解析 prelude/块内容（与契约 §2.3 一致），
 * 只额外算 `SM3` 做完整性核对（本机 `node:crypto` 自带 sm3）。
 *
 * 已知边界（刻意不实现，别当成服务端行为）：
 * - **不验签**：只检查 `X-YS-Code / X-YS-Challenge-Id / X-YS-Signature` 三头是否在，
 *   不校验 SM2 签名（验签是 Core 的职责）。所以这里挡不住伪造请求。
 * - 不做 WS 信令、不做 TURN/STUN、不做审计、不做持久化（进程退出即清空）。
 * - 不作为验收证据：跨端加密/解密是否真成立，只能由真实 WASM + Core 证明。
 *
 * 用法：node relay/dev-relay.mjs            # 默认 127.0.0.1:8787
 *      PORT=9000 node relay/dev-relay.mjs
 */
import http from 'node:http'
import crypto from 'node:crypto'

const PACK_VERSION = 'YSPK/1.0'
const MAX_BODY = 8 * 1024 * 1024

const DEFAULT_LIMITS = {
  codeLookupPerMin: 30,
  challengePerMin: 20,
  transferCreatePerHour: 10,
  chunkPutPerMin: 600,
  metaPerMin: 120,
}

// ---------------------------------------------------------------- 工具

const now = () => Date.now()
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
const hex = (buf) => Buffer.from(buf).toString('hex')
const rid = () => hex(crypto.randomBytes(8))
const tid = () => hex(crypto.randomBytes(16))
const b64u = (buf) => Buffer.from(buf).toString('base64url')
const sm3 = (buf) => crypto.createHash('sm3').update(buf).digest()

function sendJson(res, status, body, headers = {}) {
  const text = body === null ? '' : JSON.stringify(body)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-YS-Request-Id': res.reqId || rid(),
    ...headers,
  })
  res.end(text)
}

function sendError(res, status, code, message, extra = {}, headers = {}) {
  sendJson(res, status, { error: { code, message, request_id: res.reqId || rid(), ...extra } }, headers)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (c) => {
      size += c.length
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('too large'), { code: 'PAYLOAD_TOO_LARGE' }))
        req.destroy()
        return
      }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

async function readJson(req) {
  const raw = await readBody(req)
  if (raw.length === 0) return {}
  try {
    return JSON.parse(raw.toString('utf8'))
  } catch {
    throw Object.assign(new Error('bad json'), { code: 'BAD_REQUEST' })
  }
}

function assertFields(body, allowed) {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      throw Object.assign(new Error(`field not allowed: ${key}`), { code: 'FIELD_NOT_ALLOWED' })
    }
  }
}

function ceilDiv(a, b) {
  return Math.max(1, Math.ceil(a / b))
}

// ---------------------------------------------------------------- 状态

export function createRelay({ limits = {}, verifyDigests = true } = {}) {
  const cfg = {
    ...DEFAULT_LIMITS,
    ...limits,
    // 摘要校验：真 WASM 产出真 SM3，必须开着；接开发桩（假 SM3）联调时关掉。
    verifyDigests,
  }
  const codes = new Map()
  const challenges = new Map()
  const transfers = new Map()
  const idempotency = new Map()
  const rate = new Map()
  const failures = new Map()
  const locks = new Map()

  function takeRate(key, limit, windowMs) {
    const t = now()
    const entry = rate.get(key)
    if (!entry || t - entry.start >= windowMs) {
      rate.set(key, { start: t, count: 1 })
      return { ok: true, remaining: limit - 1, retryAfter: 0 }
    }
    entry.count += 1
    if (entry.count > limit) {
      return { ok: false, remaining: 0, retryAfter: Math.max(1, Math.ceil((entry.start + windowMs - t) / 1000)) }
    }
    return { ok: true, remaining: limit - entry.count, retryAfter: 0 }
  }

  function enforceRate(req, res, group, limit, windowMs = 60_000) {
    const ip = req.socket.remoteAddress || 'local'
    const r = takeRate(`${ip}|${group}`, limit, windowMs)
    if (!r.ok) {
      sendError(
        res,
        429,
        'RATE_LIMITED',
        'too many requests',
        { scope: group.startsWith('code') ? 'ip' : 'ip', retry_after: r.retryAfter },
        { 'Retry-After': String(r.retryAfter), 'X-YS-RateLimit-Limit': String(limit), 'X-YS-RateLimit-Remaining': '0' },
      )
      return false
    }
    return true
  }

  /** 校验三件套头 + 消费一次性挑战（**不验签**，见文件头说明）。 */
  function requireAuth(req, res, purpose) {
    const code = req.headers['x-ys-code']
    const challengeId = req.headers['x-ys-challenge-id']
    const signature = req.headers['x-ys-signature']
    if (!code || !challengeId || !signature) {
      sendError(res, 401, 'AUTH_MISSING', 'missing auth headers')
      return null
    }
    const ch = challenges.get(challengeId)
    if (!ch) {
      sendError(res, 401, 'AUTH_CHALLENGE_INVALID', 'unknown challenge')
      return null
    }
    if (ch.used) {
      sendError(res, 401, 'AUTH_CHALLENGE_INVALID', 'challenge already used')
      return null
    }
    ch.used = true
    if (ch.expiresAt < now()) {
      sendError(res, 401, 'AUTH_CHALLENGE_INVALID', 'challenge expired')
      return null
    }
    if (ch.purpose !== purpose) {
      sendError(res, 401, 'AUTH_CHALLENGE_INVALID', 'purpose mismatch')
      return null
    }
    return { code, challengeId, signature, nonce: ch.nonce }
  }

  function normalizeCode(input) {
    if (typeof input !== 'string') return null
    const s = input.toUpperCase().replace(/[\s-]+/g, '').replace(/O/g, '0').replace(/[IL]/g, '1')
    if (s.length !== 4) return null
    for (const ch of s) if (!'0123456789ABCDEFGHJKMNPQRSTVWXYZ'.includes(ch)) return null
    return s
  }

  function expireIfNeeded(t) {
    if (!t.terminal && t.expiresAt <= now()) {
      t.state = 'EXPIRED'
      t.terminalReason = 'EXPIRED'
      t.terminalAt = now()
      dropCiphertext(t)
    }
    if (t.state === 'LEASED' && t.leaseExpiresAt && t.leaseExpiresAt <= now() && !t.terminal) {
      t.state = 'READY'
      t.downloadId = null
      t.leaseExpiresAt = null
    }
    return t
  }

  function dropCiphertext(t) {
    t.prelude = null
    t.chunks.clear()
  }

  function isTerminal(t) {
    return t.state === 'REVOKED' || t.state === 'EXPIRED' || t.state === 'CONSUMED'
  }

  function termCode(t) {
    if (t.state === 'REVOKED') return 'TRANSFER_REVOKED'
    if (t.state === 'EXPIRED') return 'TRANSFER_EXPIRED'
    return 'TRANSFER_CONSUMED'
  }

  function transferMetaJson(t) {
    const base = {
      transfer_id: t.id,
      sender_code: t.senderCode,
      sender_nickname: codes.get(t.senderCode)?.nickname || null,
      recipient_code: t.recipientCode,
      plaintext_size: t.plaintextSize,
      chunk_size: t.chunkSize,
      chunk_count: t.chunkCount,
      prelude_len: t.preludeLen,
      created_at: iso(t.createdAt),
      expires_at: iso(t.expiresAt),
      state: t.state,
      max_downloads: t.maxDownloads,
      download_count: t.downloadCount,
    }
    if (isTerminal(t)) {
      return { ...base, terminal_reason: t.terminalReason, terminal_at: iso(t.terminalAt || now()) }
    }
    return {
      ...base,
      prelude_sm3: t.preludeSm3,
      total_ciphertext_bytes: t.preludeLen + t.receivedBytes(),
      lease_expires_at: t.leaseExpiresAt ? iso(t.leaseExpiresAt) : undefined,
    }
  }

  function bitmapOf(t) {
    const bytes = Buffer.alloc(Math.ceil(t.chunkCount / 8))
    for (const [index, chunk] of t.chunks) {
      bytes[index >> 3] |= 1 << (7 - (index % 8))
      void chunk
    }
    return b64u(bytes)
  }

  function missingRanges(t) {
    const out = []
    let i = 0
    while (i < t.chunkCount) {
      if (t.chunks.has(i)) {
        i += 1
        continue
      }
      const start = i
      while (i < t.chunkCount && !t.chunks.has(i)) i += 1
      out.push({ start, count: i - start })
    }
    return out
  }

  function expectedChunkLen(t, index) {
    const plain = index === t.chunkCount - 1 ? t.plaintextSize - t.chunkSize * (t.chunkCount - 1) : t.chunkSize
    return plain + 16
  }

  // ---------------------------------------------------------------- 服务

  const server = http.createServer(async (req, res) => {
    res.reqId = rid()
    const url = new URL(req.url, 'http://localhost')
    const path = url.pathname
    const method = req.method

    // dev-only CORS（生产同源，不需要）
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Headers', '*')
    res.setHeader('Access-Control-Expose-Headers', 'X-YS-Download-Id, X-YS-Lease-Expires-At, X-YS-State, X-YS-Request-Id, Content-Length, Retry-After, X-YS-RateLimit-Limit, X-YS-RateLimit-Remaining')
    res.setHeader('X-YS-Dev-Relay', '1')
    if (method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    try {
      // 只记方法/路径（不记 body、不记查询串值），方便联调对时序
      if (process.env.YS_DEV_RELAY_LOG === '1') console.log(`[relay] ${method} ${path}`)
      if (method === 'GET' && path === '/healthz') {
        sendJson(res, 200, { ok: true, transfers: transfers.size, codes: codes.size })
        return
      }

      if (method === 'GET' && path === '/debug/state') {
        // 联调用的只读快照（不返回任何密文/明文，只给编号与状态）
        sendJson(res, 200, {
          codes: [...codes.keys()],
          transfers: [...transfers.values()].map((t) => ({
            id: t.id,
            sender: t.senderCode,
            recipient: t.recipientCode,
            state: t.state,
            chunks: t.chunks.size,
            chunk_count: t.chunkCount,
            prelude: Boolean(t.prelude),
          })),
        })
        return
      }

      if (method === 'GET' && path === '/v1/config') {
        sendJson(res, 200, {
          api_version: 'v1',
          crypto_pack_version: PACK_VERSION,
          chunk_size: 1048576,
          max_plaintext_size: 4294967296,
          max_ttl_seconds: 86400,
          stun_urls: [],
          ws_url: null,
          limits: {
            code_lookup_per_min: cfg.codeLookupPerMin,
            challenge_per_min: cfg.challengePerMin,
            transfer_create_per_hour: cfg.transferCreatePerHour,
            chunk_put_per_min: cfg.chunkPutPerMin,
          },
        })
        return
      }

      // -------------------------------------------------- 挑战
      if (method === 'POST' && path === '/v1/challenges') {
        if (!enforceRate(req, res, 'challenge', cfg.challengePerMin)) return
        const body = await readJson(req)
        assertFields(body, ['purpose'])
        const purposes = ['REGISTER', 'NICKNAME_UPDATE', 'TRANSFER_CREATE', 'TRANSFER_REVOKE', 'INBOX_LIST', 'WS_HELLO', 'TRANSFER_ACK']
        if (!purposes.includes(body.purpose)) {
          sendError(res, 400, 'BAD_REQUEST', 'unknown purpose')
          return
        }
        const id = tid()
        const nonce = crypto.randomBytes(32)
        const expiresAt = now() + 120_000
        challenges.set(id, { id, purpose: body.purpose, nonce, expiresAt, used: false })
        // 10 分钟后清理
        setTimeout(() => challenges.delete(id), 600_000).unref?.()
        sendJson(res, 200, { challenge_id: id, nonce: b64u(nonce), purpose: body.purpose, expires_at: iso(expiresAt) })
        return
      }

      // -------------------------------------------------- 码
      if (method === 'POST' && path === '/v1/codes') {
        const auth = requireAuth(req, res, 'REGISTER')
        if (!auth) return
        const body = await readJson(req)
        assertFields(body, ['code', 'public_key', 'nickname'])
        const code = normalizeCode(body.code)
        if (!code) {
          sendError(res, 400, 'CODE_FORMAT_INVALID', 'bad code')
          return
        }
        if (auth.code !== code) {
          sendError(res, 401, 'AUTH_CODE_MISMATCH', 'challenge code mismatch')
          return
        }
        const nickname = String(body.nickname || '')
        if (!nickname || Buffer.byteLength(nickname) > 32 || /[\u0000-\u001f<>]/.test(nickname)) {
          sendError(res, 400, 'NICKNAME_INVALID', 'bad nickname')
          return
        }
        const existing = codes.get(code)
        if (existing && existing.publicKey !== body.public_key) {
          sendError(res, 409, 'CODE_TAKEN', 'code taken')
          return
        }
        for (const [otherCode, entry] of codes) {
          if (entry.publicKey === body.public_key && otherCode !== code) {
            sendError(res, 409, 'PUBKEY_TAKEN', 'pubkey taken')
            return
          }
        }
        const registeredAt = existing?.registeredAt || now()
        codes.set(code, { code, publicKey: body.public_key, nickname, registeredAt, updatedAt: now() })
        sendJson(res, 201, { code, public_key: body.public_key, nickname, registered_at: iso(registeredAt) })
        return
      }

      const codeMatch = path.match(/^\/v1\/codes\/([^/]+)$/)
      if (codeMatch) {
        const code = normalizeCode(decodeURIComponent(codeMatch[1]))
        if (method === 'GET') {
          if (!enforceRate(req, res, 'code_lookup', cfg.codeLookupPerMin)) return
          const ip = req.socket.remoteAddress || 'local'
          const lockKey = `${ip}|${code}`
          const lockedUntil = locks.get(lockKey)
          if (lockedUntil && lockedUntil > now()) {
            const retry = Math.ceil((lockedUntil - now()) / 1000)
            sendError(res, 423, 'CODE_LOCKED', 'locked', { retry_after: retry }, { 'Retry-After': String(retry) })
            return
          }
          const entry = code ? codes.get(code) : null
          if (!entry) {
            const key = `${ip}|${code}`
            const count = (failures.get(key) || 0) + 1
            failures.set(key, count)
            if (count >= 5) {
              locks.set(lockKey, now() + 60_000)
              failures.delete(key)
              sendError(res, 423, 'CODE_LOCKED', 'locked', { retry_after: 60 }, { 'Retry-After': '60' })
              return
            }
            sendError(res, 404, 'CODE_NOT_FOUND', 'not found')
            return
          }
          sendJson(res, 200, {
            code: entry.code,
            public_key: entry.publicKey,
            nickname: entry.nickname,
            registered_at: iso(entry.registeredAt),
          })
          return
        }
        if (method === 'PATCH') {
          const auth = requireAuth(req, res, 'NICKNAME_UPDATE')
          if (!auth) return
          const body = await readJson(req)
          assertFields(body, ['nickname'])
          const entry = codes.get(code)
          if (!entry) {
            sendError(res, 404, 'CODE_NOT_FOUND', 'not found')
            return
          }
          if (auth.code !== code) {
            sendError(res, 401, 'AUTH_CODE_MISMATCH', 'code mismatch')
            return
          }
          const nickname = String(body.nickname || '')
          if (!nickname || Buffer.byteLength(nickname) > 32 || /[\u0000-\u001f<>]/.test(nickname)) {
            sendError(res, 400, 'NICKNAME_INVALID', 'bad nickname')
            return
          }
          entry.nickname = nickname
          entry.updatedAt = now()
          sendJson(res, 200, { code, nickname, updated_at: iso(entry.updatedAt) })
          return
        }
      }

      // -------------------------------------------------- 创建传输
      if (method === 'POST' && path === '/v1/transfers') {
        if (!enforceRate(req, res, 'transfer_create', cfg.transferCreatePerHour, 3_600_000)) return
        const auth = requireAuth(req, res, 'TRANSFER_CREATE')
        if (!auth) return
        const body = await readJson(req)
        assertFields(body, [
          'recipient_code',
          'plaintext_size',
          'chunk_size',
          'chunk_count',
          'prelude_len',
          'prelude_sm3',
          'ttl_seconds',
          'max_downloads',
        ])
        const recipient = normalizeCode(body.recipient_code)
        if (!recipient || !codes.has(recipient)) {
          sendError(res, 404, 'CODE_NOT_FOUND', 'recipient not found')
          return
        }
        const plaintextSize = Number(body.plaintext_size)
        const chunkSize = Number(body.chunk_size)
        const chunkCount = Number(body.chunk_count)
        const preludeLen = Number(body.prelude_len)
        if (!Number.isFinite(plaintextSize) || plaintextSize < 0 || plaintextSize > 4294967296) {
          sendError(res, 400, 'BAD_REQUEST', 'bad plaintext_size')
          return
        }
        if (!Number.isFinite(chunkSize) || chunkSize < 16 || chunkSize > 1048576) {
          sendError(res, 400, 'CHUNK_SIZE_INVALID', 'bad chunk_size')
          return
        }
        if (chunkCount !== ceilDiv(plaintextSize, chunkSize)) {
          sendError(res, 400, 'CHUNK_COUNT_MISMATCH', 'chunk_count mismatch')
          return
        }
        if (!Number.isFinite(preludeLen) || preludeLen < 1 || preludeLen > 4194304) {
          sendError(res, 400, 'BAD_REQUEST', 'bad prelude_len')
          return
        }
        if (typeof body.prelude_sm3 !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.prelude_sm3)) {
          sendError(res, 400, 'BAD_REQUEST', 'bad prelude_sm3')
          return
        }
        const ttl = Math.min(86400, Math.max(3600, Number(body.ttl_seconds) || 86400))
        const maxDownloads = Math.min(3, Math.max(1, Number(body.max_downloads) || 1))

        const idemKey = req.headers['idempotency-key']
        if (idemKey) {
          const hit = idempotency.get(idemKey)
          if (hit && now() - hit.at < 600_000) {
            const t = transfers.get(hit.transferId)
            if (!t) {
              idempotency.delete(idemKey)
            } else {
              if (hit.bodyHash !== hex(sm3(Buffer.from(JSON.stringify(body))))) {
                sendError(res, 409, 'TRANSFER_STATE_CONFLICT', 'idempotency body mismatch')
                return
              }
              sendJson(res, 200, {
                transfer_id: t.id,
                state: t.state,
                upload_token: t.uploadToken,
                chunk_size: t.chunkSize,
                chunk_count: t.chunkCount,
                prelude_len: t.preludeLen,
                created_at: iso(t.createdAt),
                expires_at: iso(t.expiresAt),
              })
              return
            }
          }
        }

        const id = tid()
        const t = {
          id,
          senderCode: auth.code,
          recipientCode: recipient,
          plaintextSize,
          chunkSize,
          chunkCount,
          preludeLen,
          preludeSm3: body.prelude_sm3,
          uploadToken: b64u(crypto.randomBytes(32)),
          createdAt: now(),
          expiresAt: now() + ttl * 1000,
          state: 'UPLOADING',
          prelude: null,
          chunks: new Map(),
          downloadCount: 0,
          maxDownloads,
          downloadId: null,
          leaseExpiresAt: null,
          terminal: false,
          receivedBytes() {
            let n = 0
            for (const chunk of this.chunks.values()) n += chunk.length
            return n
          },
        }
        transfers.set(id, t)
        if (idemKey) idempotency.set(idemKey, { transferId: id, at: now(), bodyHash: hex(sm3(Buffer.from(JSON.stringify(body)))) })
        sendJson(res, 201, {
          transfer_id: id,
          state: 'UPLOADING',
          upload_token: t.uploadToken,
          chunk_size: t.chunkSize,
          chunk_count: t.chunkCount,
          prelude_len: t.preludeLen,
          created_at: iso(t.createdAt),
          expires_at: iso(t.expiresAt),
        })
        return
      }

      // -------------------------------------------------- 发送方上传侧
      const tMatch = path.match(/^\/v1\/transfers\/([0-9a-f]{32})(\/(.*))?$/)
      if (tMatch) {
        const t = transfers.get(tMatch[1])
        const rest = tMatch[3] || ''
        if (!t) {
          sendError(res, 404, 'TRANSFER_NOT_FOUND', 'not found')
          return
        }
        expireIfNeeded(t)
        const token = req.headers['x-ys-upload-token']

        if (method === 'PUT' && rest === 'prelude') {
          if (token !== t.uploadToken) {
            sendError(res, 401, 'AUTH_MISSING', 'bad upload token')
            return
          }
          if (t.state !== 'UPLOADING') {
            sendError(res, 409, 'TRANSFER_STATE_CONFLICT', 'not uploading')
            return
          }
          if (!String(req.headers['content-type'] || '').startsWith('application/octet-stream')) {
            sendError(res, 415, 'CONTENT_TYPE_UNSUPPORTED', 'need application/octet-stream')
            return
          }
          const body = await readBody(req)
          if (body.length !== t.preludeLen) {
            sendError(res, 400, 'LENGTH_MISMATCH', 'prelude length mismatch')
            return
          }
          const digest = b64u(sm3(body))
          if (cfg.verifyDigests && digest !== t.preludeSm3) {
            sendError(res, 400, 'PRELUDE_DIGEST_MISMATCH', 'prelude sm3 mismatch')
            return
          }
          if (t.prelude) {
            sendJson(res, 204, null)
            return
          }
          t.prelude = body
          sendJson(res, 201, { prelude_len: body.length, prelude_sm3: digest })
          return
        }

        const chunkMatch = rest.match(/^chunks\/(\d+)$/)
        if (chunkMatch) {
          const index = Number(chunkMatch[1])
          if (!Number.isInteger(index) || index < 0 || index >= t.chunkCount) {
            sendError(res, 400, 'CHUNK_INDEX_OUT_OF_RANGE', 'index out of range')
            return
          }
          if (method === 'PUT') {
            if (!enforceRate(req, res, 'chunk_put', cfg.chunkPutPerMin)) return
            if (token !== t.uploadToken) {
              sendError(res, 401, 'AUTH_MISSING', 'bad upload token')
              return
            }
            if (t.state !== 'UPLOADING') {
              sendError(res, 409, 'TRANSFER_STATE_CONFLICT', 'not uploading')
              return
            }
            if (!String(req.headers['content-type'] || '').startsWith('application/octet-stream')) {
              sendError(res, 415, 'CONTENT_TYPE_UNSUPPORTED', 'need application/octet-stream')
              return
            }
            const body = await readBody(req)
            if (body.length !== expectedChunkLen(t, index)) {
              sendError(res, 400, 'LENGTH_MISMATCH', `expect ${expectedChunkLen(t, index)} got ${body.length}`)
              return
            }
            const digest = b64u(sm3(body))
            const existing = t.chunks.get(index)
            if (existing) {
              if (existing.length === body.length && existing.digest === digest) {
                sendJson(res, 204, null)
              } else {
                sendError(res, 409, 'CHUNK_CONFLICT', 'chunk conflict')
              }
              return
            }
            t.chunks.set(index, { data: body, length: body.length, digest })
            sendJson(res, 201, {
              index,
              length: body.length,
              received_chunks: t.chunks.size,
              chunk_count: t.chunkCount,
            })
            return
          }
          if (method === 'HEAD') {
            if (isTerminal(t)) {
              sendError(res, 410, termCode(t), 'terminal')
              return
            }
            const existing = t.chunks.get(index)
            if (!existing) {
              sendError(res, 404, 'CHUNK_NOT_FOUND', 'not found')
              return
            }
            res.writeHead(200, { 'Content-Length': String(existing.length) })
            res.end()
            return
          }
          if (method === 'GET') {
            if (isTerminal(t)) {
              sendError(res, 410, termCode(t), 'terminal')
              return
            }
            if (t.state === 'UPLOADING') {
              sendError(res, 409, 'TRANSFER_NOT_READY', 'uploading')
              return
            }
            const downloadId = req.headers['x-ys-download-id']
            if (!downloadId || downloadId !== t.downloadId) {
              sendError(res, 409, 'DOWNLOAD_NOT_STARTED', 'no valid download id')
              return
            }
            const existing = t.chunks.get(index)
            if (!existing) {
              sendError(res, 404, 'CHUNK_NOT_FOUND', 'not found')
              return
            }
            res.writeHead(200, {
              'Content-Type': 'application/octet-stream',
              'Content-Length': String(existing.length),
              'Accept-Ranges': 'bytes',
              'X-YS-Request-Id': res.reqId,
            })
            res.end(existing.data)
            return
          }
        }

        if (method === 'GET' && rest === 'status') {
          if (token !== t.uploadToken) {
            sendError(res, 401, 'AUTH_MISSING', 'bad upload token')
            return
          }
          sendJson(res, 200, {
            transfer_id: t.id,
            state: t.state,
            chunk_count: t.chunkCount,
            chunk_size: t.chunkSize,
            prelude_received: Boolean(t.prelude),
            received_chunks: t.chunks.size,
            bitmap: bitmapOf(t),
            missing: missingRanges(t),
            uploaded_bytes: t.preludeLen + t.receivedBytes(),
            updated_at: iso(now()),
          })
          return
        }

        if (method === 'POST' && rest === 'complete') {
          if (token !== t.uploadToken) {
            sendError(res, 401, 'AUTH_MISSING', 'bad upload token')
            return
          }
          if (isTerminal(t)) {
            sendError(res, 409, 'TRANSFER_STATE_CONFLICT', 'terminal')
            return
          }
          if (!t.prelude) {
            sendError(res, 409, 'PRELUDE_MISSING', 'prelude missing')
            return
          }
          const missing = missingRanges(t)
          if (missing.length > 0) {
            sendError(res, 409, 'CHUNKS_MISSING', 'chunks missing', { missing })
            return
          }
          t.state = 'READY'
          sendJson(res, 200, { state: 'READY', expires_at: iso(t.expiresAt) })
          return
        }

        if (method === 'POST' && rest === 'revoke') {
          const auth = requireAuth(req, res, 'TRANSFER_REVOKE')
          if (!auth) return
          if (auth.code !== t.senderCode) {
            sendError(res, 401, 'AUTH_CODE_MISMATCH', 'not sender')
            return
          }
          if (isTerminal(t) && t.state !== 'REVOKED') {
            sendError(res, 409, 'TRANSFER_STATE_CONFLICT', 'terminal')
            return
          }
          t.state = 'REVOKED'
          t.terminal = true
          t.terminalReason = 'REVOKED'
          t.terminalAt = now()
          dropCiphertext(t)
          sendJson(res, 200, { state: 'REVOKED', terminal_reason: 'REVOKED', terminal_at: iso(t.terminalAt) })
          return
        }

        if (method === 'POST' && rest === 'ack') {
          const auth = requireAuth(req, res, 'TRANSFER_ACK')
          if (!auth) return
          if (auth.code !== t.recipientCode) {
            sendError(res, 401, 'AUTH_CODE_MISMATCH', 'not recipient')
            return
          }
          const downloadId = req.headers['x-ys-download-id']
          if (!downloadId || downloadId !== t.downloadId) {
            sendError(res, 409, 'DOWNLOAD_NOT_STARTED', 'no valid download id')
            return
          }
          if (isTerminal(t) && t.state !== 'CONSUMED') {
            sendError(res, 409, 'TRANSFER_STATE_CONFLICT', 'terminal')
            return
          }
          t.downloadCount += 1
          if (t.downloadCount < t.maxDownloads) {
            t.state = 'READY'
            t.downloadId = null
            t.leaseExpiresAt = null
            sendJson(res, 200, { state: 'READY', remaining_downloads: t.maxDownloads - t.downloadCount })
            return
          }
          t.state = 'CONSUMED'
          t.terminal = true
          t.terminalReason = 'CONSUMED'
          t.terminalAt = now()
          dropCiphertext(t)
          sendJson(res, 200, { state: 'CONSUMED', terminal_reason: 'CONSUMED', terminal_at: iso(t.terminalAt) })
          return
        }

        if (method === 'GET' && rest === 'prelude') {
          if (!enforceRate(req, res, 'meta', cfg.metaPerMin)) return
          if (isTerminal(t)) {
            sendError(res, 410, termCode(t), 'terminal')
            return
          }
          if (t.state === 'UPLOADING') {
            sendError(res, 409, 'TRANSFER_NOT_READY', 'uploading')
            return
          }
          if (!t.prelude) {
            sendError(res, 410, termCode(t), 'ciphertext gone')
            return
          }
          if (t.state !== 'LEASED' || !t.downloadId) {
            t.state = 'LEASED'
            t.downloadId = tid()
            t.leaseExpiresAt = now() + 30 * 60_000
          } else {
            t.leaseExpiresAt = now() + 30 * 60_000
          }
          res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(t.prelude.length),
            'Accept-Ranges': 'bytes',
            'X-YS-Download-Id': t.downloadId,
            'X-YS-Lease-Expires-At': iso(t.leaseExpiresAt),
            'X-YS-State': 'LEASED',
            'X-YS-Request-Id': res.reqId,
          })
          res.end(t.prelude)
          return
        }

        if (method === 'GET' && rest === '') {
          if (!enforceRate(req, res, 'meta', cfg.metaPerMin)) return
          sendJson(res, 200, transferMetaJson(t))
          return
        }
      }

      // -------------------------------------------------- 收件箱
      if (method === 'GET' && path === '/v1/inbox') {
        const auth = requireAuth(req, res, 'INBOX_LIST')
        if (!auth) return
        const state = url.searchParams.get('state') || 'ready'
        if (!['ready', 'all'].includes(state)) {
          sendError(res, 400, 'BAD_REQUEST', 'bad state')
          return
        }
        const limit = Math.min(50, Math.max(1, Number(url.searchParams.get('limit')) || 20))
        const cursor = Number(url.searchParams.get('cursor')) || 0
        const items = [...transfers.values()]
          .filter((t) => t.recipientCode === auth.code)
          .filter((t) => (state === 'all' ? true : !isTerminal(t)))
          .filter((t) => (state === 'all' ? true : t.state === 'READY' || t.state === 'LEASED'))
          .sort((a, b) => b.createdAt - a.createdAt)
        const slice = items.slice(cursor, cursor + limit)
        sendJson(res, 200, {
          items: slice.map((t) => ({
            transfer_id: t.id,
            sender_code: t.senderCode,
            sender_nickname: codes.get(t.senderCode)?.nickname || null,
            recipient_code: t.recipientCode,
            plaintext_size: t.plaintextSize,
            chunk_size: t.chunkSize,
            chunk_count: t.chunkCount,
            prelude_len: t.preludeLen,
            created_at: iso(t.createdAt),
            expires_at: iso(t.expiresAt),
            state: t.state,
          })),
          next_cursor: cursor + limit < items.length ? String(cursor + limit) : null,
        })
        return
      }

      sendError(res, 404, 'NOT_FOUND', 'no such endpoint')
    } catch (err) {
      if (err.code === 'PAYLOAD_TOO_LARGE') {
        sendError(res, 413, 'PAYLOAD_TOO_LARGE', 'too large')
        return
      }
      if (err.code === 'BAD_REQUEST' || err.code === 'FIELD_NOT_ALLOWED') {
        sendError(res, 400, err.code, err.message)
        return
      }
      console.error('[relay]', err)
      sendError(res, 500, 'INTERNAL', 'internal error')
    }
  })

  return { server, state: { codes, challenges, transfers }, cfg }
}

// 直接运行时启动
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT) || 8787
  const host = process.env.HOST || '127.0.0.1'
  // 接开发桩（假 SM3）联调时必须关掉摘要校验：YS_DEV_RELAY_VERIFY_DIGESTS=off
  const verifyDigests = process.env.YS_DEV_RELAY_VERIFY_DIGESTS !== 'off'
  const { server } = createRelay({ verifyDigests })
  server.listen(port, host, () => {
    console.log(`[dev-relay] http://${host}:${port}  （仅本地联调：不验签、不持久化、不解析包内容）`)
  })
}
