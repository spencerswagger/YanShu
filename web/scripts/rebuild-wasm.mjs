#!/usr/bin/env node
/**
 * 一条命令重建端侧内核并核验"产物与源码同源"。
 *
 *   cd web && npm run wasm:rebuild            # 默认取 origin/feat/endcrypto-wasm 的最新 commit
 *   YS_KERNEL_REF=<commit> npm run wasm:rebuild
 *
 * 做四件事（每一步失败都直接非 0 退出，不产出"看起来能用"的产物）：
 *   1. `git fetch origin` 后解析 `origin/feat/endcrypto-wasm` 的 head commit（不是本地工作区，避免脏树）；
 *   2. 用 `git archive` 把该 commit 的源码导出到临时目录（不改你的工作区、不建 worktree）；
 *   3. `cargo build --release --target wasm32-unknown-unknown -p yanshu-sm`（独立 target 目录，避免和别人串产物）；
 *   4. 实例化产物核验：0 import、`ys_version()`、`ys_header_len()`、导出数、`ys_unpack_v1` arity，
 *      并把 {commit, sha256, ysVersion, headerLen, exports, unpackV1Arity, builtAt} 写进
 *      `public/ys_kernel.build.json`（前端据此显示"内核构建于哪个 commit"，测试据此校验同源）。
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: webDir }).toString().trim()
const ref = process.env.YS_KERNEL_REF || 'origin/feat/endcrypto-wasm'
const outWasm = join(webDir, 'public/ys_kernel.wasm')
const outMeta = join(webDir, 'public/ys_kernel.build.json')

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'inherit'], ...opts }).toString().trim()
}

if (process.env.YS_KERNEL_REF !== 'skip-fetch') {
  console.log('[1/4] git fetch origin')
  try {
    run('git', ['fetch', 'origin'], { cwd: repoRoot })
  } catch (err) {
    // 沙盒/CI 里的 ssh 封装可能失败；这时不静默继续，明确告警：可能用到过期的 origin 引用
    console.warn('[warn] git fetch 失败，沿用本地已有的 origin/* 引用（请确认不是过期的）')
    console.warn('[warn] ' + String(err.stderr || err.message).split('\n').slice(0, 2).join(' '))
  }
}

let commit
try {
  commit = run('git', ['rev-parse', ref], { cwd: repoRoot })
} catch {
  console.error(`找不到引用 ${ref}：先 git fetch origin，或用 YS_KERNEL_REF=<commit> 指定`)
  process.exit(2)
}
const short = commit.slice(0, 7)
console.log(`[2/4] 取出 ${ref} @ ${short} 的源码（git archive，不动工作区）`)

const work = mkdtempSync(join(tmpdir(), 'ys-kernel-'))
execFileSync('sh', ['-c', `git -C "${repoRoot}" archive ${commit} | tar -x -C "${work}"`], { stdio: 'inherit' })

const targetDir = process.env.CARGO_TARGET_DIR || join(work, 'target')
console.log(`[3/4] cargo build（target=${targetDir}）`)
try {
  // 有些环境（含本沙盒）的 cargo 是包装脚本，负责设置 RUSTUP_HOME/CARGO_HOME；
  // 优先用它，其次才是 PATH 里的 cargo（可用 YS_CARGO 覆盖）。
  const cargoBin =
    process.env.YS_CARGO || (existsSync('/.keys/bin/cargo') ? '/.keys/bin/cargo' : 'cargo')
  console.log(`[3/4] 使用 cargo：${cargoBin}`)
  const out = execFileSync(
    cargoBin,
    ['build', '--release', '--target', 'wasm32-unknown-unknown', '-p', 'yanshu-sm'],
    { cwd: join(work, 'crypto'), env: { ...process.env, CARGO_TARGET_DIR: targetDir }, stdio: ['ignore', 'pipe', 'pipe'] },
  )
  process.stdout.write(out)
} catch (err) {
  console.error('cargo build 失败：')
  console.error(String(err.stdout || ''))
  console.error(String(err.stderr || err.message))
  console.error(`源码目录：${join(work, 'crypto')}`)
  process.exit(5)
}

const built = join(targetDir, 'wasm32-unknown-unknown/release/yanshu_sm.wasm')
if (!existsSync(built)) {
  console.error(`构建产物不存在：${built}`)
  process.exit(3)
}

const bytes = readFileSync(built)
const sha256 = createHash('sha256').update(bytes).digest('hex')
const module = new WebAssembly.Module(bytes)
const imports = WebAssembly.Module.imports(module).length
const instance = new WebAssembly.Instance(module, {})
const e = instance.exports
const fns = Object.keys(e).filter((k) => typeof e[k] === 'function')

const facts = {
  commit,
  ref,
  builtAt: new Date().toISOString(),
  sha256,
  bytes: bytes.length,
  imports,
  exports: fns.length,
  ysVersion: `0x${e.ys_version().toString(16)}`,
  headerLen: typeof e.ys_header_len === 'function' ? e.ys_header_len() : null,
  unpackV1Arity: typeof e.ys_unpack_v1 === 'function' ? e.ys_unpack_v1.length : null,
  hasSignDer: typeof e.ys_sm2_sign_der === 'function',
  hasPackV1: typeof e.ys_pack_v1 === 'function',
}

console.log('[4/4] 核验产物')
console.log(JSON.stringify(facts, null, 2))

const problems = []
if (imports !== 0) problems.push(`应当 0 import，实际 ${imports}`)
if (facts.ysVersion !== '0x10000') problems.push(`ys_version 应为 0x10000，实际 ${facts.ysVersion}`)
if (facts.headerLen !== 112) problems.push(`ys_header_len 应为 112（契约布局），实际 ${facts.headerLen}`)
if (facts.unpackV1Arity !== 6) problems.push(`ys_unpack_v1 应为 6 参自证原型，实际 ${facts.unpackV1Arity}`)
if (!facts.hasSignDer) problems.push('缺少 ys_sm2_sign_der（契约 DER 签名）')
if (!facts.hasPackV1) problems.push('缺少 ys_pack_v1（清单 ext/created_at）')
if (problems.length) {
  console.error('产物不合格：\n - ' + problems.join('\n - '))
  process.exit(4)
}

mkdirSync(dirname(outWasm), { recursive: true })
copyFileSync(built, outWasm)
writeFileSync(outMeta, JSON.stringify(facts, null, 2) + '\n')
console.log(`已写入 ${outWasm}`)
console.log(`已写入 ${outMeta}（前端与测试据此校验"产物 ↔ 源码 commit"同源）`)
