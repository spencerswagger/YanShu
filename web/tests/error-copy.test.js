/**
 * 路由级错误码的**中文文案** + 兜底路径不许被改掉。
 *
 * 背景：#58 让「未匹配路由 / 未定义方法」也走契约信封（`ROUTE_NOT_FOUND` / `METHOD_NOT_ALLOWED`），
 * 前端映射表里没有这两条 → 用户会看到「请求失败（ROUTE_NOT_FOUND）」这种原始码。
 * 补两条中文文案（`docs/UI-COPY.md` R14「失败态 · 网络/其他 → 复用 describeError()」的委派），
 * 同时**锁住兜底**：未识别的码仍显示「请求失败（原始码）」，旧形态（裸 404 → `HTTP_404`）也仍走兜底。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { ApiError } from '../src/net/client.js'
import { describeError } from '../src/net/errors.js'

const noAsciiLetters = (s) => !/[A-Za-z]/.test(s)

test('ROUTE_NOT_FOUND / METHOD_NOT_ALLOWED 有中文文案，且不含原始英文码', () => {
  const route = describeError(new ApiError({ code: 'ROUTE_NOT_FOUND', status: 404, message: 'no route' }))
  const method = describeError(new ApiError({ code: 'METHOD_NOT_ALLOWED', status: 405, message: 'no method' }))

  for (const [name, d] of [['ROUTE_NOT_FOUND', route], ['METHOD_NOT_ALLOWED', method]]) {
    assert.notEqual(d.title, `请求失败（${name}）`, `${name} 不应再落到兜底标题`)
    assert.ok(noAsciiLetters(d.title), `${name} 的标题不应含英文原文：${d.title}`)
    assert.ok(noAsciiLetters(d.hint), `${name} 的提示不应含英文原文：${d.hint}`)
    // 与现有文案同量级：标题是短语、提示一句话（不写解释性长句）
    assert.ok(d.title.length <= 8, `${name} 标题过长：${d.title}`)
    assert.ok(d.hint.length <= 30, `${name} 提示过长：${d.hint}`)
    assert.match(d.hint, /刷新/, `${name} 必须给"下一步"（刷新页面）`)
    assert.equal(d.terminal, false, `${name} 不是终结态`)
    assert.ok(!d.retry, `${name} 不该自动重试`)
  }
})

test('兜底保留：未识别的码仍是「请求失败（原始码）」+ 服务端文案作提示', () => {
  const d = describeError(new ApiError({ code: 'SOME_FUTURE_CODE', status: 418, message: '服务端新加的码' }))
  assert.equal(d.title, '请求失败（SOME_FUTURE_CODE）', '兜底标题不许被改动')
  assert.equal(d.hint, '服务端新加的码', '兜底提示用服务端 message')
  assert.equal(d.terminal, false)
})

test('兜底保留：旧形态（裸 404，无 error.code → HTTP_404）照旧走兜底，不抛不吞', () => {
  const d = describeError(new ApiError({ code: 'HTTP_404', status: 404, message: 'HTTP 404' }))
  assert.equal(d.title, '请求失败（HTTP_404）')
  assert.equal(d.hint, 'HTTP 404')
})

test('端点语义码不因新增两条而串味：CODE_NOT_FOUND 仍是「码不对」', () => {
  const d = describeError(new ApiError({ code: 'CODE_NOT_FOUND', status: 404, message: 'not registered' }))
  assert.equal(d.title, '码不对', '路径成立、对象不存在的语义必须还归 CODE_NOT_FOUND')
})
