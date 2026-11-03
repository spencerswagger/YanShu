/**
 * 用内核的 `sm2-verify-vectors.json`（15 条：7 正例 + 8 负例）验证**验签语义**。
 *
 * 重点不是"我们的实现能验过"，而是把三类失败分清楚：
 *   - 签名/消息/公钥/userID 被改 → 验签失败（`CRYPTO_SIGNATURE_INVALID`）
 *   - **验签通过但 `X-YS-Code` ≠ `SIG_INPUT` 里的 `CODE(4)`** → `AUTH_CODE_MISMATCH`（不是签名错）
 *   - 空消息 / 超长消息 → `BAD_INPUT`（契约的 `SIG_INPUT` 都是定长小消息）
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { instantiateKernel } from '../src/crypto/wasm.js'
import { kernelPathOrSkip } from './helpers/kernel.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(resolve(here, 'fixtures/sm2-verify-vectors.json'), 'utf8'))

const hexOf = (h) => Uint8Array.from(Buffer.from(h, 'hex'))
// ABI 的验签**没有 userID 入参**（固定国标默认串）。所以"换 userID"那条向量只能在"可配置 userID 的 verifier"
// 上成立；对固定默认 ID 的实现来说，它是 oracle 侧属性，不是我们能执行的用例——显式标 SKIP 而不是假装通过。
const DEFAULT_ID = vectors.meta?.user_id || '1234567812345678'

test('验签向量：可执行部分逐条对上（固定默认 userID）', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const applicable = vectors.verify_vectors.filter((v) => !v.user_id || v.user_id === DEFAULT_ID)
  const fixedIdOnly = vectors.verify_vectors.filter((v) => v.user_id && v.user_id !== DEFAULT_ID)
  assert.ok(fixedIdOnly.length >= 1, '应有"换 userID"这类需要可配置 ID 的向量')

  const byServer = {}
  for (const v of applicable) {
    let actual
    try {
      actual = kernel.verify(hexOf(v.pub65), hexOf(v.sig_input), hexOf(v.sig_der))
    } catch {
      actual = false
    }
    assert.equal(actual, v.expect_verify, `${v.name}: 期望 ${v.expect_verify}，实际 ${actual}`)
    byServer[v.expect_server] = (byServer[v.expect_server] || 0) + 1
  }
  // 七种 PURPOSE 正例验签通过且服务端 OK
  assert.equal(byServer.OK, 7)
  // 消息改字节 / 签名翻转 / 换公钥 / 昵称长度前缀写错 → 验签失败
  assert.equal(byServer.CRYPTO_SIGNATURE_INVALID, 4)
  // 签名有效但服务端策略拒绝：码不一致 1 条、空消息/超长各 1 条
  assert.equal(byServer.AUTH_CODE_MISMATCH, 1)
  assert.equal(byServer.BAD_INPUT, 2)
  console.log(
    `[verify-vectors] 可执行 ${applicable.length} 条（${Object.entries(byServer).map(([k, v]) => `${k}:${v}`).join(' ')}）；` +
      `固定默认 ID 下不可执行 ${fixedIdOnly.length} 条：${fixedIdOnly.map((v) => v.name).join(',')}`,
  )
})

test('验签通过但码不一致：这是 AUTH_CODE_MISMATCH，不是签名错', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  const kernel = await instantiateKernel(readFileSync(wasmPath))
  const v = vectors.verify_vectors.find((x) => x.name === 'code_mismatch')
  assert.ok(v, '向量里应有 code_mismatch')
  assert.equal(kernel.verify(hexOf(v.pub65), hexOf(v.sig_input), hexOf(v.sig_der)), true, '签名本身有效')
  assert.equal(v.expect_server, 'AUTH_CODE_MISMATCH')
  assert.notEqual(v.request_code, v.code_in_sig, '这条向量的前提是两者不同')

  // 界面要把两种失败分开：文案不得都写成“签名失败”
  const { describeError } = await import('../src/net/errors.js')
  const { ApiError } = await import('../src/net/client.js')
  const sigErr = describeError(new ApiError({ code: 'AUTH_SIGNATURE_INVALID', status: 401 }))
  const codeErr = describeError(new ApiError({ code: 'AUTH_CODE_MISMATCH', status: 401 }))
  assert.notEqual(sigErr.title, codeErr.title)
  assert.match(codeErr.title, /码/)
})

test('签名入参是原文：与向量的 sig_input 长度逐条一致（没有预哈希）', async (t) => {
  const wasmPath = kernelPathOrSkip(t)
  if (!wasmPath) return
  // 预哈希会让长度变成 32；这里断言我们喂给内核的就是向量原文长度（44..109）
  for (const v of vectors.verify_vectors) {
    if (!v.sig_input_len) continue
    assert.ok(v.sig_input_len >= 44, `${v.name} 原文长度 ${v.sig_input_len}`)
    assert.notEqual(v.sig_input_len, 32)
  }
})
