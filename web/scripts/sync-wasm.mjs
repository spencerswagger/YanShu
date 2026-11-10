#!/usr/bin/env node
/**
 * 把端侧内核的 wasm 产物同步到前端静态目录——**按溯源摘要强绑定**。
 *
 * 产物不入库（根 `.gitignore` 忽略 `*.wasm`），所以部署/本地联调要先跑这一步。
 * 查找顺序：`YS_WASM` → `CARGO_TARGET_DIR` → `/.cache/rust-web` → `/.cache/rust`。
 *
 * 与旧版的区别（旧版会把缓存里**另一个版本**拷过来当成功，等于静默换掉 sm2/sm3/sm4 实现）：
 * - 期望摘要来自 `public/ys_kernel.build.json`，或显式 `--expect-sha <sha256>`；
 * - 两者都没有 → **拒绝同步**（无法确定版本），非 0 退出；
 * - 只接受摘要完全一致的候选；拷贝走「临时文件 + rename」，拷完复验摘要。
 *
 * 溯源（`public/ys_kernel.build.json`）在这里**只在给了 `--commit` 时才写**：
 * 旧版本 README 让人「cargo build 后 npm run wasm:sync」就以为溯源也有了 —— 实际没写，
 * 于是「产物↔commit 同源」那条测试**静默 SKIP**（看起来全绿，最关键的断言没跑）。现在：
 * - `--commit <40hex>`：产物自身的字段（sha256/bytes/ysVersion/headerLen/导出数）**从字节现算**，
 *   commit 由调用方声明（与 Dockerfile 的 `YS_KERNEL_COMMIT` 同口径），通过核验才原子写入溯源；
 * - 不给 `--commit` 且本来就没有溯源：同步照样成功，但**明确告警**"溯源用例会 SKIP"，不伪造来源。
 *
 * 用法：
 *   npm run wasm:sync                                    # 按溯源里的 sha256 同步
 *   node scripts/sync-wasm.mjs --expect-sha <sha256>
 *   node scripts/sync-wasm.mjs --expect-sha <sha256> --commit <40 位内核 commit>   # 顺便写溯源
 *   YS_PUBLIC_DIR=/tmp/x YS_WASM=/path/to.wasm node scripts/sync-wasm.mjs --expect-sha <sha256>
 */
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  META_NAME,
  WASM_NAME,
  atomicCopyFile,
  atomicWriteJson,
  formatScanned,
  pickMatchingCandidate,
  probeKernel,
  sha256File,
} from './kernel-meta.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const webDir = resolve(here, '..')
const publicDir = process.env.YS_PUBLIC_DIR ? resolve(process.env.YS_PUBLIC_DIR) : join(webDir, 'public')
const target = join(publicDir, WASM_NAME)
const metaPath = join(publicDir, META_NAME)

const argv = process.argv.slice(2)
const argVal = (name) => {
  const eq = argv.find((a) => a.startsWith(`--${name}=`))
  if (eq) return eq.split('=').slice(1).join('=')
  const i = argv.indexOf(`--${name}`)
  return i >= 0 ? argv[i + 1] : ''
}

let expectSha = String(argVal('expect-sha') || '').toLowerCase()
// commit 必须由调用方明确声明（40 位十六进制）：脚本不许猜来源，猜出来的"同源"等于假的
const wantCommit = String(argVal('commit') || '').trim().toLowerCase()
if (wantCommit && !/^[0-9a-f]{40}$/.test(wantCommit)) {
  console.error(`[sync-wasm] --commit 必须是 40 位十六进制 commit（实际「${wantCommit}」）——拒绝同步/写溯源`)
  process.exit(2)
}
let meta = null
if (existsSync(metaPath)) {
  try {
    meta = JSON.parse(readFileSync(metaPath, 'utf8'))
  } catch (err) {
    console.error(`[sync-wasm] 溯源不是合法 JSON（${err.message}）——拒绝同步`)
    process.exit(2)
  }
  if (!expectSha && meta.sha256) expectSha = String(meta.sha256).toLowerCase()
}

// 没给 --expect-sha 但给了 --commit：只接受**你显式指向**的那一份产物（YS_WASM），不扫缓存凑数
if (!expectSha && wantCommit && process.env.YS_WASM) {
  const explicit = resolve(process.env.YS_WASM)
  if (!existsSync(explicit)) {
    console.error(`[sync-wasm] YS_WASM 指向的产物不存在：${explicit}——拒绝继续`)
    process.exit(2)
  }
  expectSha = sha256File(explicit)
  console.log(
    `[sync-wasm] 未给 --expect-sha：按显式 YS_WASM 取摘要 ${expectSha.slice(0, 12)}…（只认这一份，不扫缓存）`,
  )
}

if (!expectSha) {
  console.error(
    [
      '[sync-wasm] 没有可用的期望摘要（溯源缺 sha256，也没给 --expect-sha）——无法确定要同步哪一版，拒绝继续。',
      '  npm run wasm:rebuild                              # 重建并写溯源（推荐）',
      '  node scripts/sync-wasm.mjs --expect-sha <sha256>  # 你明确知道要用哪一版时',
    ].join('\n'),
  )
  process.exit(2)
}

const candidates = [
  process.env.YS_WASM,
  process.env.CARGO_TARGET_DIR && resolve(process.env.CARGO_TARGET_DIR, 'wasm32-unknown-unknown/release/yanshu_sm.wasm'),
  '/.cache/rust-web/wasm32-unknown-unknown/release/yanshu_sm.wasm',
  '/.cache/rust/wasm32-unknown-unknown/release/yanshu_sm.wasm',
].filter(Boolean)

const { hit, scanned } = pickMatchingCandidate(candidates, expectSha)
if (!hit) {
  console.error(
    [
      `[sync-wasm] 没有候选与期望摘要一致（期望 ${expectSha.slice(0, 12)}…）——不会用别的版本凑数。`,
      '候选：',
      formatScanned(scanned),
      '  npm run wasm:rebuild   # 从内核分支重建；或设 YS_WASM 指向正确产物',
    ].join('\n'),
  )
  process.exit(2)
}

// 要在溯源里声明 commit，就先核验产物本身（不是合法内核对不上版本/头长 → 不落盘、不写溯源）
let facts = null
if (wantCommit) {
  try {
    facts = probeKernel(readFileSync(hit.path))
  } catch (err) {
    console.error(`[sync-wasm] 候选产物无法实例化（${err.message}）——拒绝同步/写溯源：${hit.path}`)
    process.exit(3)
  }
  const problems = []
  if (facts.imports !== 0) problems.push(`应当 0 import，实际 ${facts.imports}`)
  if (facts.ysVersion !== '0x10000') problems.push(`ys_version 应为 0x10000（YSPK/1.0），实际 ${facts.ysVersion}`)
  if (facts.headerLen !== 112) problems.push(`ys_header_len 应为 112（契约布局），实际 ${facts.headerLen}`)
  if (!facts.hasMemory) problems.push('缺少 memory 导出')
  if (problems.length) {
    console.error(`[sync-wasm] 候选产物不合格——拒绝同步/写溯源：${hit.path}\n - ` + problems.join('\n - '))
    process.exit(3)
  }
}

atomicCopyFile(hit.path, target)
const got = sha256File(target)
if (got !== expectSha) {
  console.error(`[sync-wasm] 拷入后摘要不一致（${got.slice(0, 12)}… != ${expectSha.slice(0, 12)}…）——已停下，请检查磁盘/并发写入`)
  process.exit(2)
}
const bytes = readFileSync(target).length
console.log(`[sync-wasm] 已同步（摘要对齐 + 原子写）：${hit.path} → ${target}（${bytes} B, sha256=${got.slice(0, 12)}…）`)
if (meta && meta.bytes && Number(meta.bytes) !== bytes) {
  console.error(`[sync-wasm] 注意：溯源写的是 ${meta.bytes} B，实际 ${bytes} B（摘要一致但字节数不同，请复核溯源）`)
  process.exit(2)
}

if (facts) {
  // 只写"字节能证明的字段 + 调用方声明的 commit"；字段口径与 rebuild-wasm / Dockerfile 一致
  atomicWriteJson(metaPath, {
    commit: wantCommit,
    ref: wantCommit.slice(0, 7),
    builtAt: new Date().toISOString(),
    sha256: got,
    bytes,
    ...facts,
  })
  console.log(
    `[sync-wasm] 已写溯源：${metaPath}（commit=${wantCommit.slice(0, 7)} ysVersion=${facts.ysVersion} ` +
      `header=${facts.headerLen} exports=${facts.exports}）`,
  )
} else if (!meta) {
  console.warn(
    [
      '[sync-wasm] 注意：这次**没有写溯源**（没给 --commit，也没有已有溯源可沿用）。',
      '  → tests/wasm-real.test.js 的「产物 ↔ commit 同源」断言会 SKIP（不是通过）。',
      '  → 要 skipped=0：加 --commit <该产物对应的 40 位内核 commit>，或 npm run wasm:rebuild。',
    ].join('\n'),
  )
}
