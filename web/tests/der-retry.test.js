import test from 'node:test'
import assert from 'node:assert/strict'
import { encodeSignature, normalizeSignature, decodeSignature } from '../src/lib/der.js'
import { withRetry, isRetryable } from '../src/lib/retry.js'
import { ApiError } from '../src/net/client.js'

test('DER 签名编码：SEQ + 两个 INTEGER，长度 70..72，高位补 00', () => {
  const raw = new Uint8Array(64)
  raw[0] = 0x80 // r 高位为 1 → 必须补 0x00
  raw[31] = 0x01
  raw[32] = 0x7f // s 高位为 0
  raw[63] = 0x02
  const der = encodeSignature(raw)
  assert.equal(der[0], 0x30)
  assert.equal(der[1], der.length - 2)
  assert.equal(der[2], 0x02)
  assert.equal(der[3], 32 + 1, 'r 补了 0x00')
  assert.equal(der[4], 0x00)
  assert.ok(der.length >= 70 && der.length <= 72)

  assert.equal(normalizeSignature(der).length, der.length, '已是 DER 就原样返回')
  assert.throws(() => normalizeSignature(new Uint8Array(63)))
})

test('DER 解码：编码后再解回 64 字节 r‖s', () => {
  const raw = new Uint8Array(64).map((_, i) => (i * 13 + 7) & 0xff)
  raw[0] = 0x00
  raw[32] = 0x91
  const der = encodeSignature(raw)
  const back = decodeSignature(der)
  assert.equal(back.length, 64)
  assert.deepEqual([...back], [...raw])
  // 高位补的 0x00 被去掉后应还原
  assert.equal(back[0], 0x00)
  assert.equal(back[32], 0x91)
  assert.throws(() => decodeSignature(new Uint8Array([0x30, 0x00])))
})

test('退避：429 以 Retry-After 为准（取较大值）', async () => {
  const waits = []
  let calls = 0
  const err = new ApiError({ code: 'RATE_LIMITED', status: 429, retryAfter: 12, message: 'slow down' })
  const result = await withRetry(
    async () => {
      calls += 1
      if (calls === 1) throw err
      return 'ok'
    },
    { sleep: async (ms) => waits.push(ms), backoffMs: [5000, 20000, 60000] },
  )
  assert.equal(result, 'ok')
  assert.deepEqual(waits, [12000], '5000 与 12000 取大')
})

test('退避：503 走 5s → 20s → 60s，最多 3 次', async () => {
  const waits = []
  let calls = 0
  const err = new ApiError({ code: 'SERVICE_UNAVAILABLE', status: 503, message: 'busy' })
  await assert.rejects(
    withRetry(
      async () => {
        calls += 1
        throw err
      },
      { sleep: async (ms) => waits.push(ms), backoffMs: [5000, 20000, 60000] },
    ),
    err,
  )
  assert.equal(calls, 4, '首次 + 3 次重试')
  assert.deepEqual(waits, [5000, 20000, 60000])
})

test('业务错误不重试', async () => {
  let calls = 0
  const err = new ApiError({ code: 'CODE_NOT_FOUND', status: 404, message: 'nope' })
  assert.equal(isRetryable(err), false)
  await assert.rejects(
    withRetry(async () => {
      calls += 1
      throw err
    }),
    err,
  )
  assert.equal(calls, 1)
})

test('507 配额错误不自动重试（API.md §10.2：不是速率错误）', async () => {
  assert.equal(isRetryable(new ApiError({ code: 'INSUFFICIENT_STORAGE', status: 507 })), false)
  let calls = 0
  const err = new ApiError({ code: 'INSUFFICIENT_STORAGE', status: 507, message: 'quota' })
  await assert.rejects(
    withRetry(async () => {
      calls += 1
      throw err
    }),
    err,
  )
  assert.equal(calls, 1, '507 只尝试一次')
})
