/**
 * `wasm:sync` 的**溯源写入**回归（"看起来全绿、最关键的断言没跑"这类假绿）。
 *
 * 背景：README 曾写「cargo build 后 npm run wasm:sync」就算把产物准备好了，但 sync 只拷产物、
 * 从不写 `ys_kernel.build.json`，于是 `wasm-real.test.js` 的「产物 ↔ commit 同源」那条**静默 SKIP**。
 * 现在的口径：
 *   - `--commit <40hex>`：写溯源，且 sha256/bytes/ysVersion/headerLen 全部从字节现算（commit 由调用方声明）；
 *   - 不给 `--commit`：不写溯源，但必须**明确告警**（SKIP 不是通过）；
 *   - `--commit` 不合法、或候选不是合法内核：非 0 退出，产物不落盘、溯源不写。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { kernelPathOrSkip } from './helpers/kernel.js'

const here = dirname(fileURLToPath(import.meta.url))
const WEB = resolve(here, '..')
const SYNC = join(WEB, 'scripts/sync-wasm.mjs')
const ENSURE = join(WEB, 'scripts/ensure-wasm.mjs')

const sha = (buf) => createHash('sha256').update(buf).digest('hex')

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), 'ys-sync-prov-'))
  const publicDir = join(dir, 'public')
  mkdirSync(publicDir, { recursive: true })
  return { dir, publicDir, wasmPath: join(publicDir, 'ys_kernel.wasm'), metaPath: join(publicDir, 'ys_kernel.build.json') }
}

function run(script, { publicDir, env = {}, args = [] } = {}) {
  const r = spawnSync(process.execPath, [script, ...args], {
    env: { ...process.env, YS_PUBLIC_DIR: publicDir, ...env },
    encoding: 'utf8',
  })
  return { rc: r.status ?? -1, stdout: String(r.stdout || ''), stderr: String(r.stderr || '') }
}

const NOT_A_KERNEL = Buffer.alloc(1024, 0x61) // 不是合法 wasm：实例化必抛
const COMMIT = 'a'.repeat(40)

test('--commit 不合法（不是 40 位十六进制）：非 0 退出，产物与溯源都不落盘', () => {
  const sb = sandbox()
  const cand = join(sb.dir, 'cand.wasm')
  writeFileSync(cand, NOT_A_KERNEL)
  for (const bad of ['HEAD', 'a'.repeat(39), 'z'.repeat(40)]) {
    const r = run(SYNC, {
      publicDir: sb.publicDir,
      env: { YS_WASM: cand },
      args: ['--expect-sha', sha(NOT_A_KERNEL), '--commit', bad],
    })
    assert.notEqual(r.rc, 0, `--commit「${bad}」必须非 0 退出`)
    assert.match(r.stderr, /--commit/, '报错里要说是 --commit 的问题')
    assert.equal(existsSync(sb.metaPath), false, `--commit「${bad}」不许写溯源`)
  }
  assert.equal(existsSync(sb.wasmPath), false, '非法 --commit 时不该拷产物')
})

test('--commit 合法但候选不是内核：非 0 退出，不落盘也不写溯源', () => {
  const sb = sandbox()
  const cand = join(sb.dir, 'cand.wasm')
  writeFileSync(cand, NOT_A_KERNEL)
  const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: ['--commit', COMMIT] })
  assert.notEqual(r.rc, 0, '不是合法 wasm 必须非 0 退出')
  assert.match(r.stderr, /候选产物/, '报错要说清是候选产物的问题')
  assert.equal(existsSync(sb.wasmPath), false, '不合格产物不许拷进 public/')
  assert.equal(existsSync(sb.metaPath), false, '不合格产物不许写溯源')
})

test('只给 --expect-sha（不给 --commit）：同步成功但**不伪造溯源**，并明确告警 SKIP', () => {
  const sb = sandbox()
  const cand = join(sb.dir, 'cand.wasm')
  writeFileSync(cand, NOT_A_KERNEL)
  const r = run(SYNC, {
    publicDir: sb.publicDir,
    env: { YS_WASM: cand },
    args: ['--expect-sha', sha(NOT_A_KERNEL)],
  })
  assert.equal(r.rc, 0, '摘要对齐就该同步成功')
  assert.equal(sha(readFileSync(sb.wasmPath)), sha(NOT_A_KERNEL), '产物应逐字节一致')
  assert.equal(existsSync(sb.metaPath), false, '没有 --commit 不许凭空造 commit 写溯源')
  const out = r.stdout + r.stderr
  assert.match(out, /SKIP/, '必须明确说"同源断言会 SKIP"')
  assert.match(out, /--commit/, '要告诉怎么补溯源')
})

test('--commit 合法 + 真内核：溯源里除 commit/builtAt 外全部与字节一致，且 ensure-wasm 认可', (t) => {
  const real = kernelPathOrSkip(t)
  if (!real) return
  const bytes = readFileSync(real)
  const sb = sandbox()
  const cand = join(sb.dir, 'cand.wasm')
  writeFileSync(cand, bytes)

  // 不给 --expect-sha，只显式指向这一份产物：摘要由脚本自己算（不扫缓存凑数）
  const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: ['--commit', COMMIT] })
  assert.equal(r.rc, 0, `同步失败：${r.stderr}`)

  const meta = JSON.parse(readFileSync(sb.metaPath, 'utf8'))
  assert.equal(meta.commit, COMMIT, 'commit 应是调用方声明的那一个')
  assert.equal(meta.ref, COMMIT.slice(0, 7))
  assert.match(meta.builtAt, /^\d{4}-\d{2}-\d{2}T/, 'builtAt 应是 ISO 时间')
  assert.equal(meta.sha256, sha(bytes), 'sha256 必须从字节现算')
  assert.equal(meta.bytes, bytes.length, 'bytes 必须从字节现算')
  assert.equal(meta.ysVersion, '0x10000', 'ys_version 由产物自己回答')
  assert.equal(meta.headerLen, 112, 'ys_header_len 由产物自己回答')
  assert.equal(meta.imports, 0, '内核必须 0 import')
  assert.ok(meta.exports >= 43, `函数导出数应 ≥43，实际 ${meta.exports}`)

  // 写完溯源后，prebuild/pretest 的前置核验必须认这份产物（sha256 + bytes 双向一致）
  const e = run(ENSURE, { publicDir: sb.publicDir })
  assert.equal(e.rc, 0, `ensure-wasm 应认可：${e.stderr}`)
})
