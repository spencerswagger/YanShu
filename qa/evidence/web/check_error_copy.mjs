#!/usr/bin/env node
/**
 * 独立验收：路由级错误码有中文文案后，「未知码仍走兜底（请求失败·原始码）」必须仍成立。
 *
 * 只断言**用户可见行为**（标题/是否兜底/是否终结/是否自动重试），不改文案措辞：
 *   A. ROUTE_NOT_FOUND / METHOD_NOT_ALLOWED：不再落兜底标题、标题与提示是中文（无 ASCII 字母）、
 *      非终结、不自动重试；
 *   B. 未识别的码 `WAT_999`：必须回 `请求失败（WAT_999）`，并把服务端 message 作为 hint；
 *   C. 老形态（只有 HTTP status、没有 code）：必须回 `请求失败（HTTP_404）`。
 *
 * 用法：node check_error_copy.mjs <web 目录> [--json-out x.json]
 * 退出码：0 全过；1 有 FAIL；2 用法/环境错误。
 */
import { createRequire } from 'node:module'
import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const webDir = process.argv[2]
if (!webDir) {
  console.error('[BLOCKED] 用法：node check_error_copy.mjs <web 目录> [--json-out x.json]')
  process.exit(2)
}
const jsonIdx = process.argv.indexOf('--json-out')
const jsonOut = jsonIdx > 0 ? process.argv[jsonIdx + 1] : ''

const load = async (rel) => import(pathToFileURL(resolve(webDir, rel)).href)
const { describeError } = await load('src/net/errors.js')
const { ApiError } = await load('src/net/client.js')

const rows = []
const noAsciiLetters = (s) => !/[A-Za-z]/.test(String(s ?? ''))
const add = (name, ok, ev) => {
  rows.push({ name, pass: !!ok, evidence: ev })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(46)} ${ev}`)
}

// A. 两条路由级码：有中文文案、不落兜底
for (const [code, status] of [['ROUTE_NOT_FOUND', 404], ['METHOD_NOT_ALLOWED', 405]]) {
  const d = describeError(new ApiError({ code, status, message: 'raw message from server' }))
  add(`${code} 有中文文案且不落兜底`,
    d.title !== `请求失败（${code}）` && noAsciiLetters(d.title) && noAsciiLetters(d.hint)
      && d.terminal === false && !d.retry,
    `title=${JSON.stringify(d.title)} terminal=${d.terminal} retry=${!!d.retry}`)
}

// B. 未知码必须仍走兜底，且带原始码
{
  const d = describeError(new ApiError({ code: 'WAT_999', status: 418, message: '服务端原话' }))
  add('未知码 WAT_999 仍走兜底并带原始码',
    d.title === '请求失败（WAT_999）' && String(d.hint).includes('服务端原话'),
    `title=${JSON.stringify(d.title)} hint=${JSON.stringify(d.hint)}`)
}

// C. 老形态：调用方自己拼 HTTP_<status> 当 code（client 的默认码是 NETWORK_ERROR，不是 HTTP_x）
{
  const d = describeError(new ApiError({ code: 'HTTP_404', status: 404, message: 'HTTP 404' }))
  add('老形态 HTTP_404 仍走兜底（不抛不吞）',
    d.title === '请求失败（HTTP_404）' && d.hint === 'HTTP 404',
    `title=${JSON.stringify(d.title)} hint=${JSON.stringify(d.hint)}`)
}

// D. 端点语义码不被新文案串味
{
  const d = describeError(new ApiError({ code: 'CODE_NOT_FOUND', status: 404, message: 'not registered' }))
  add('CODE_NOT_FOUND 仍归自己的文案',
    d.title !== '请求失败（CODE_NOT_FOUND）' && noAsciiLetters(d.title),
    `title=${JSON.stringify(d.title)}`)
}

const bad = rows.filter((r) => !r.pass)
console.log('-'.repeat(86))
console.log(`${rows.length - bad.length}/${rows.length} 通过　结论：${bad.length ? 'FAIL' : 'PASS'}`)
if (jsonOut) {
  writeFileSync(jsonOut, JSON.stringify({
    at: new Date().toISOString(), webDir, rows, verdict: bad.length ? 'FAIL' : 'PASS',
  }, null, 2))
}
process.exit(bad.length ? 1 : 0)
