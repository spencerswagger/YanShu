/**
 * 契约端点封装（路径 / 字段名 / 头 / 错误码全部照 docs/API.md 写死，不自行发明）。
 *
 * 分工：本文件只做"一次请求"；重试与编排在 upload.js / download.js。
 * 需要签名的端点在 `auth.js` 里拿一次性挑战（§1.2）。
 */
import { authHeaders, fields, PURPOSES } from './auth.js'
import { encode as b64uEncode, decode as b64uDecode } from '../lib/base64url.js'

export function createApi({ client, kernel, session }) {
  /** 每次调用都取当前身份（撞码重生成后 session 会换） */
  const who = () => ({ privateKey: session.privateKey, publicKey: session.publicKey, code: session.code })

  async function signed(purpose, buildFields, extraHeaders = {}) {
    const me = who()
    const { headers } = await authHeaders({
      client,
      kernel,
      privateKey: me.privateKey,
      code: me.code,
      purpose,
      fieldBytes: buildFields(me),
    })
    return { ...headers, ...extraHeaders }
  }

  return {
    session,
    client,

    // ------------------------------------------------------------ 启动配置
    getConfig: async () => (await client.get('/config', { retry: true })).json,

    // ------------------------------------------------------------ 码
    register: async ({ nickname }) => {
      const me = who()
      const publicKey = me.publicKey
      const headers = await signed(
        'REGISTER',
        (s) => fields.REGISTER({ code: s.code, publicKey }),
        { 'Content-Type': 'application/json' },
      )
      const res = await client.post('/codes', {
        json: { code: me.code, public_key: toBase64Url(publicKey), nickname },
        headers,
      })
      return res.json
    },

    getCode: async (code) => (await client.get(`/codes/${encodeURIComponent(code)}`, { retry: true })).json,

    patchNickname: async ({ code, nickname }) => {
      const headers = await signed('NICKNAME_UPDATE', (s) =>
        fields.NICKNAME_UPDATE({ code: s.code, nickname }),
      )
      const res = await client.patch(`/codes/${encodeURIComponent(code)}`, { json: { nickname }, headers })
      return res.json
    },

    // ------------------------------------------------------------ 发送方
    createTransfer: async (body) => {
      const headers = await signed('TRANSFER_CREATE', (s) =>
        fields.TRANSFER_CREATE({
          senderCode: s.code,
          recipientCode: body.recipient_code,
          plaintextSize: body.plaintext_size,
          chunkSize: body.chunk_size,
          chunkCount: body.chunk_count,
          preludeLen: body.prelude_len,
          preludeSm3: toBytes(body.prelude_sm3),
        }),
      )
      const extra = {}
      if (body.idempotency_key) {
        extra['Idempotency-Key'] = body.idempotency_key
        extra['Content-Type'] = 'application/json'
      }
      const res = await client.post('/transfers', {
        json: {
          recipient_code: body.recipient_code,
          plaintext_size: body.plaintext_size,
          chunk_size: body.chunk_size,
          chunk_count: body.chunk_count,
          prelude_len: body.prelude_len,
          prelude_sm3: body.prelude_sm3,
          ttl_seconds: body.ttl_seconds,
          max_downloads: body.max_downloads,
        },
        headers: { ...headers, ...extra },
      })
      return res.json
    },

    putPrelude: ({ transferId, uploadToken, prelude }) =>
      client.put(`/transfers/${transferId}/prelude`, {
        bytes: prelude,
        headers: { 'X-YS-Upload-Token': uploadToken },
      }),

    putChunk: ({ transferId, uploadToken, index, bytes }) =>
      client.put(`/transfers/${transferId}/chunks/${index}`, {
        bytes,
        headers: { 'X-YS-Upload-Token': uploadToken },
      }),

    uploadStatus: async ({ transferId, uploadToken }) =>
      (
        await client.get(`/transfers/${transferId}/status`, {
          headers: { 'X-YS-Upload-Token': uploadToken },
          retry: true,
        })
      ).json,

    complete: ({ transferId, uploadToken }) =>
      client.post(`/transfers/${transferId}/complete`, {
        headers: { 'X-YS-Upload-Token': uploadToken },
      }),

    revoke: async ({ transferId }) => {
      const headers = await signed('TRANSFER_REVOKE', (s) =>
        fields.TRANSFER_REVOKE({ senderCode: s.code, transferId }),
      )
      const res = await client.post(`/transfers/${transferId}/revoke`, { headers })
      return res.json
    },

    // ------------------------------------------------------------ 接收方
    inbox: async ({ state = 'ready', limit = 20, cursor } = {}) => {
      const headers = await signed('INBOX_LIST', (s) => fields.INBOX_LIST({ code: s.code }))
      const qs = new URLSearchParams({ state, limit: String(limit) })
      if (cursor) qs.set('cursor', cursor)
      const res = await client.get(`/inbox?${qs.toString()}`, { headers, retry: true })
      return res.json
    },

    getTransfer: async (transferId) => (await client.get(`/transfers/${transferId}`, { retry: true })).json,

    getPrelude: async (transferId) => {
      const res = await client.get(`/transfers/${transferId}/prelude`, { raw: true, retry: true })
      return {
        bytes: res.bytes,
        downloadId: res.headers.get('X-YS-Download-Id'),
        leaseExpiresAt: res.headers.get('X-YS-Lease-Expires-At'),
        state: res.headers.get('X-YS-State'),
        length: Number(res.headers.get('Content-Length')) || res.bytes.length,
      }
    },

    getChunk: async ({ transferId, downloadId, index }) => {
      const res = await client.get(`/transfers/${transferId}/chunks/${index}`, {
        raw: true,
        headers: { 'X-YS-Download-Id': downloadId },
        retry: true,
      })
      return res.bytes
    },

    ack: async ({ transferId, downloadId }) => {
      const headers = await signed('TRANSFER_ACK', (s) =>
        fields.TRANSFER_ACK({ receiverCode: s.code, transferId }),
      )
      headers['X-YS-Download-Id'] = downloadId
      const res = await client.post(`/transfers/${transferId}/ack`, { headers })
      return res.json
    },

    headChunk: ({ transferId, index }) =>
      client.head(`/transfers/${transferId}/chunks/${index}`, { retry: true }),
  }
}

// ---------------------------------------------------------------- 小工具

function toBase64Url(bytes) {
  return b64uEncode(bytes)
}

function toBytes(textOrBytes) {
  return typeof textOrBytes === 'string' ? b64uDecode(textOrBytes) : textOrBytes
}
