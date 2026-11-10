#!/usr/bin/env node
/**
 * `pretest` / `prebuild` 的统一前置：保证 `public/ys_kernel.wasm` 与溯源**强绑定**。
 *
 * 为什么这么严：WASM 是 sm2/sm3/sm4 内核。旧实现在「产物在、溯源缺」时会从构建缓存拷回
 * **另一个版本**还当成功（140,762B/daa949… → 111,841B/0c9e2f…），等于静默换掉加密实现。
 *
 * 规则：
 * 1. 产物 + 溯源都在且 sha256/bytes 一致 → 通过；
 * 2. 溯源缺 / 摘要不符 / 溯源坏 → **直接非 0 退出**，打印两边的大小与摘要，绝不自动替换；
 * 3. 产物缺但溯源在 → 只有在缓存里找到**摘要完全一致**的候选时才原子拷入，否则非 0 退出；
 * 4. 都没有 → 非 0 退出并给可执行命令。
 *
 * 环境变量：`YS_PUBLIC_DIR` 可覆盖 `public/`（测试用），`YS_WASM` 可指定候选产物路径。
 */
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { META_NAME, WASM_NAME, atomicCopyFile, formatScanned, pickMatchingCandidate, verifyArtifact } from './kernel-meta.mjs'

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const publicDir = process.env.YS_PUBLIC_DIR ? resolve(process.env.YS_PUBLIC_DIR) : join(webDir, 'public')
const wasmPath = join(publicDir, WASM_NAME)
const metaPath = join(publicDir, META_NAME)

const candidates = [
  process.env.YS_WASM,
  process.env.CARGO_TARGET_DIR && resolve(process.env.CARGO_TARGET_DIR, 'wasm32-unknown-unknown/release/yanshu_sm.wasm'),
  '/.cache/rust-web/wasm32-unknown-unknown/release/yanshu_sm.wasm',
  '/.cache/rust/wasm32-unknown-unknown/release/yanshu_sm.wasm',
].filter(Boolean)

const NEXT_STEPS = [
  '下一步（任选其一，别靠"从缓存随便拷一份"）：',
  '  npm run wasm:rebuild      # 从内核分支重建并写溯源（推荐）',
  '  npm run wasm:sync -- --expect-sha <sha256>   # 明确告诉脚本该用哪一版',
].join('\n')

function die(lines) {
  console.error(['[ensure-wasm] ' + lines[0], ...lines.slice(1)].join('\n'))
  process.exit(1)
}

const v = verifyArtifact({ wasmPath, metaPath })

if (v.ok) {
  console.log(`[ensure-wasm] 产物就位：commit=${String(v.meta.commit).slice(0, 7)} sha256=${v.sha.slice(0, 12)}… bytes=${v.bytes}`)
  process.exit(0)
}

// 产物缺、溯源在：只有摘要完全对齐的缓存才允许用（原子拷入后复验）
if (v.code === 'NO_WASM') {
  let expectSha = ''
  if (existsSync(metaPath)) {
    try {
      expectSha = JSON.parse(readFileSync(metaPath, 'utf8')).sha256 || ''
    } catch {
      expectSha = ''
    }
  }
  const { hit, scanned } = pickMatchingCandidate(candidates, expectSha)
  if (hit) {
    atomicCopyFile(hit.path, wasmPath)
    const after = verifyArtifact({ wasmPath, metaPath })
    if (after.ok) {
      console.log(`[ensure-wasm] 已按溯源同步（原子写）：${hit.path} → ${wasmPath} sha256=${after.sha.slice(0, 12)}… bytes=${after.bytes}`)
      process.exit(0)
    }
    die([`同步后仍不一致：${after.code}`, `  产物 ${after.wasm?.bytes} B ${after.wasm?.sha256?.slice(0, 12)}…`])
  }
  die([
    `缺产物，且缓存里没有与溯源 sha256 一致的候选（期望 ${String(expectSha).slice(0, 12)}…）`,
    '候选：',
    formatScanned(scanned),
    NEXT_STEPS,
  ])
}

if (v.code === 'NO_META') {
  die([
    '有产物但缺溯源（public/ys_kernel.build.json）——无法确定它是哪一版，拒绝继续。',
    `  现有产物 ${v.wasm.bytes} B sha256=${v.wasm.sha256.slice(0, 12)}…`,
    '  （历史上这一步会从缓存拷回另一版并当作成功，那等于静默换掉加密实现）',
    NEXT_STEPS,
  ])
}

if (v.code === 'SHA_MISMATCH' || v.code === 'BYTES_MISMATCH') {
  die([
    `产物与溯源不一致（${v.code}）——拒绝自动替换。`,
    `  产物 ${v.wasm.bytes} B sha256=${v.wasm.sha256.slice(0, 12)}…`,
    `  溯源 ${v.metaBytes ?? '?'} B sha256=${String(v.metaSha).slice(0, 12)}…`,
    NEXT_STEPS,
  ])
}

if (v.code === 'BAD_META') {
  die([`溯源文件不是合法 JSON：${v.detail}`, '  可能是半截写入；请重新生成（npm run wasm:rebuild）'])
}

if (v.code === 'META_NO_SHA') {
  die(['溯源里没有 sha256，无法绑定版本（拒绝继续）', NEXT_STEPS])
}

if (!existsSync(wasmPath) && !existsSync(metaPath)) {
  die(['缺少端侧内核产物（public/ys_kernel.wasm 与 public/ys_kernel.build.json 都不在）', NEXT_STEPS])
}

die([`未知状态：${v.code}`, NEXT_STEPS])
