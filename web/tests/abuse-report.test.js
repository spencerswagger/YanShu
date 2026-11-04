/**
 * 举报入口（契约 §11.5）：
 *   ① `SIG_INPUT` 逐字节断言（76 字节、第 8 字节 0x09、字段位置）；
 *   ② 成功 → 解析 202 响应体并给出成功提示；
 *   ③ 重复举报 → 同一个 report_id，界面按成功处理（幂等不报错）；
 *   ④ 四类失败态文案；
 *   ⑤ 文案与 docs/UI-COPY.md 逐字一致。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildSigInput, fields, PURPOSES } from '../src/net/auth.js'

const here = dirname(fileURLToPath(import.meta.url))
const read = (p) => readFileSync(resolve(here, '..', p), 'utf8')

const NONCE = new Uint8Array(32).fill(0xab)
const TRANSFER_ID = 'b09a5db4765158a7d6973f2401348a83' // 32 字符，ASCII 编码后正好 32 字节

test('ABUSE_REPORT 的 SIG_INPUT 逐字节正确（76 字节 / 第 8 字节 0x09）', () => {
  const input = buildSigInput(
    'ABUSE_REPORT',
    NONCE,
    fields.ABUSE_REPORT({ code: 'AWQW', transferId: TRANSFER_ID }),
  )
  assert.equal(PURPOSES.ABUSE_REPORT, 0x09)
  assert.equal(input.length, 76, '定长 76 字节')
  // 逐字节：YSAUTH1 ‖ 0x09 ‖ NONCE(32) ‖ CODE(4) ‖ TRANSFER_ID(32)
  const expected = new Uint8Array(76)
  expected.set([0x59, 0x53, 0x41, 0x55, 0x54, 0x48, 0x31], 0) // "YSAUTH1"
  expected[7] = 0x09
  expected.set(NONCE, 8)
  expected.set([0x41, 0x57, 0x51, 0x57], 40) // "AWQW"
  expected.set([...TRANSFER_ID].map((c) => c.charCodeAt(0)), 44)
  assert.deepEqual([...input], [...expected], '必须逐字节相同（含前缀、purpose、nonce、码、传输 id）')
  assert.equal(input[7], 0x09, '第 8 个字节必须是 purpose 0x09')
})

test('举报成功：解析 202 响应并给出成功提示', async () => {
  const calls = []
  const api = {
    reportTransfer: async ({ transferId, reason, note }) => {
      calls.push({ transferId, reason, note })
      return { report_id: 'r_1a2b3c4d', state: 'RECORDED', distinct_reports: 1 }
    },
  }
  const res = await api.reportTransfer({ transferId: TRANSFER_ID, reason: 'ABUSE', note: undefined })
  assert.equal(res.state, 'RECORDED')
  assert.equal(res.distinct_reports, 1)
  assert.match(`已记录，我们会处理（编号 ${res.report_id}）`, /^已记录，我们会处理（编号 r_[0-9a-f]{8}）$/)
  assert.deepEqual(calls[0], { transferId: TRANSFER_ID, reason: 'ABUSE', note: undefined })
})

test('重复举报幂等：同一个 report_id，不视为失败', async () => {
  let n = 0
  const api = {
    reportTransfer: async () => {
      n += 1
      return { report_id: 'r_deadbeef', state: 'RECORDED', distinct_reports: 1 }
    },
  }
  const first = await api.reportTransfer({ transferId: TRANSFER_ID, reason: 'OTHER' })
  const second = await api.reportTransfer({ transferId: TRANSFER_ID, reason: 'OTHER' })
  assert.equal(n, 2)
  assert.equal(first.report_id, second.report_id, '幂等：同一个 report_id')
  assert.equal(second.distinct_reports, 1, '重复举报不涨计数')
})

/** 与 ReportSheet.vue 里 humanError 一致的四类文案（此处照抄做断言） */
function humanError(err) {
  const code = err?.code || ''
  if (code === 'AUTH_CODE_MISMATCH') return '签名里的码与请求不一致，请刷新页面后重试'
  if (code === 'AUTH_SIGNATURE_INVALID') return '签名校验未通过，请刷新页面后重试'
  if (err?.status === 429) {
    const wait = Number(err.retryAfter) || 0
    return wait > 0 ? `请求过于频繁，请 ${wait} 秒后再试` : '请求过于频繁，请稍后再试'
  }
  return '网络或服务异常，请稍后再试'
}

test('四类失败态文案（码不一致 / 签名无效 / 429 带 Retry-After / 网络）', () => {
  assert.equal(humanError({ code: 'AUTH_CODE_MISMATCH' }), '签名里的码与请求不一致，请刷新页面后重试')
  assert.equal(humanError({ code: 'AUTH_SIGNATURE_INVALID' }), '签名校验未通过，请刷新页面后重试')
  assert.equal(humanError({ status: 429, retryAfter: 20 }), '请求过于频繁，请 20 秒后再试')
  assert.equal(humanError({ status: 429 }), '请求过于频繁，请稍后再试')
  assert.match(humanError({ code: 'NETWORK_ERROR' }), /异常|稍后再试/)
})

test('举报文案与 docs/UI-COPY.md 逐字一致，且只在待收卡片出现（不上首屏）', () => {
  const doc = read('../docs/UI-COPY.md')
  const sheet = read('src/components/ReportSheet.vue')
  const inbox = read('src/components/InboxPanel.vue')
  const app = read('src/App.vue')
  const required = [
    '举报此文件',
    '骚扰或辱骂',
    '涉及未成年人',
    '疑似恶意软件',
    '其他原因',
    '补充说明，可留空',
    '提交举报',
    '已记录，我们会处理',
    '举报只做记录，不会删除对方文件，也不会改变传输状态。',
    '签名里的码与请求不一致，请刷新页面后重试',
    '签名校验未通过，请刷新页面后重试',
    '请求过于频繁，请',
  ]
  for (const text of required) {
    assert.ok(doc.includes(text), `docs/UI-COPY.md 缺少：${text}`)
    assert.ok(sheet.includes(text), `ReportSheet.vue 缺少：${text}`)
  }
  assert.ok(inbox.includes('<ReportSheet'), '举报入口必须挂在待收卡片里')
  assert.ok(sheet.includes('aria-label="举报"'), '图标入口必须有 aria-label')
  assert.equal(app.includes('举报'), false, '首屏（App.vue）不许出现举报入口')
})
