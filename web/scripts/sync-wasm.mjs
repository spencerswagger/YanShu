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
 * 用法：
 *   npm run wasm:sync                         # 按溯源里的 sha256 同步
 *   node scripts/sync-wasm.mjs --expect-sha <sha256>
 *   YS_PUBLIC_DIR=/tmp/x YS_WASM=/path/to.wasm node scripts/sync-wasm.mjs --expect-sha <sha256>
 */
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { META_NAME, WASM_NAME, atomicCopyFile, formatScanned, pickMatchingCandidate, sha256File } from './kernel-meta.mjs'

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
