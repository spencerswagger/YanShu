#!/usr/bin/env node
/**
 * `pretest` / `prebuild` 的统一前置：保证 `public/ys_kernel.wasm` 与溯源文件就位。
 *
 * 规则（对应复审 P2：不准"看起来绿其实没跑"）：
 * 1. 已有产物且 sha256 与溯源一致 → 直接通过（本地开发最常见）；
 * 2. 没有产物但有构建缓存 → 自动 `wasm:sync` 拷进来；
 * 3. 都没有：
 *    - `CI` 环境（或 `--ci`）→ **非 0 退出**，不允测试/构建静默跑下去；
 *    - 本地 → 也非 0 退出，但打印"怎么生成"的两行命令（避免把空站发出去）。
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const wasm = join(webDir, 'public/ys_kernel.wasm')
const meta = join(webDir, 'public/ys_kernel.build.json')
const ci = Boolean(process.env.CI) || process.argv.includes('--ci')

function ok() {
  const sha = createHash('sha256').update(readFileSync(wasm)).digest('hex')
  const built = JSON.parse(readFileSync(meta, 'utf8'))
  if (built.sha256 && built.sha256 !== sha) {
    return { ok: false, reason: `产物与溯源 sha256 不一致（产物 ${sha.slice(0, 12)}…，溯源 ${built.sha256.slice(0, 12)}…）` }
  }
  return { ok: true, sha, commit: built.commit }
}

function trySync() {
  try {
    execFileSync(process.execPath, [join(webDir, 'scripts/sync-wasm.mjs')], { stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

if (existsSync(wasm) && existsSync(meta)) {
  const check = ok()
  if (check.ok) {
    console.log(`[ensure-wasm] 产物就位：commit=${String(check.commit).slice(0, 7)} sha256=${check.sha.slice(0, 12)}…`)
    process.exit(0)
  }
  console.error(`[ensure-wasm] ${check.reason}`)
  process.exit(1)
}

if (trySync() && existsSync(wasm) && existsSync(meta)) {
  const check = ok()
  console.log(`[ensure-wasm] 已从缓存同步：commit=${String(check.commit).slice(0, 7)} sha256=${check.sha.slice(0, 12)}…`)
  process.exit(0)
}

const howTo = [
  '缺少端侧内核产物（public/ys_kernel.wasm 或 public/ys_kernel.build.json）',
  '  npm run wasm:rebuild     # 从 feat/endcrypto-wasm 最新 commit 构建并核验（推荐）',
  '  npm run wasm:sync        # 已有构建缓存时直接同步',
].join('\n')
console.error(`[ensure-wasm] ${howTo}`)
if (ci) console.error('[ensure-wasm] CI 环境：缺产物直接失败，测试/构建不会静默跳过')
process.exit(1)
