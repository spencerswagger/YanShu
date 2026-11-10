#!/usr/bin/env node
/**
 * 把端侧内核的 wasm 产物同步到前端静态目录——**按摘要强绑定**，并可选地写构建溯源。
 *
 * 产物不入库（根 `.gitignore` 忽略 `*.wasm`），所以部署/本地联调要先跑这一步。
 * 查找顺序：`YS_WASM` → `CARGO_TARGET_DIR` → `/.cache/rust-web` → `/.cache/rust` → 仓库里的冻结内核
 * `server/kernel/yanshu_sm.wasm`。
 *
 * 版本绑定的硬口径（旧版会把缓存里**另一个版本**拷过来当成功，等于静默换掉 sm2/sm3/sm4 实现）：
 * - 期望摘要的优先级：**显式 `--expect-sha` > `--commit` + 显式 `YS_WASM`（现算）> 已有溯源的 sha256**；
 * - 都没有 → **拒绝同步**（无法确定版本），非 0 退出；
 * - 只接受摘要完全一致的候选；拷贝走「临时文件 + rename」，拷完复验摘要。
 *
 * 溯源（`public/ys_kernel.build.json`）**只在给了 `--commit` 时才写**：旧版 README 让人
 * 「cargo build 后 npm run wasm:sync」就以为溯源也有了 —— 实际没写，于是「产物↔commit 同源」
 * 那条测试**静默 SKIP**（看起来全绿，最关键的断言没跑，而 `npm test`/`npm run build` 的
 * `pretest`/`prebuild` 反而会因缺溯源硬失败）。现在的口径：
 * - `--commit <40hex>`：产物自身的字段（sha256/bytes/ysVersion/headerLen/导入导出/arity）**从字节现算**，
 *   commit 由调用方声明（与 `web/Dockerfile` 的 `YS_KERNEL_COMMIT` 同口径）+ 校验该 commit 在本仓存在；
 *   覆盖已有溯源时打印「旧 commit/sha → 新」，不静默改写；
 * - 不给 `--commit` 且本来就没有溯源：同步照样成功，但**明确告警**"溯源用例会 SKIP、`npm test` 会硬失败"，
 *   绝不伪造来源。
 *
 * 候选一律先实例化核验：不是合法 wasm / 没有 `ys_version` → 非 0 退出，产物不落盘；
 * 要写溯源时再叠加四项契约门禁（0 import / `ys_version == 0x10000` / `ys_header_len == 112` /
 * `ys_unpack_v1` 6 参 + `ys_sm2_sign_der` + `ys_pack_v1`），与 `wasm:rebuild` 同强度。
 *
 * 用法：
 *   npm run wasm:sync                                    # 按溯源里的 sha256 同步
 *   node scripts/sync-wasm.mjs --expect-sha <sha256>
 *   node scripts/sync-wasm.mjs --expect-sha <sha256> --commit <40 位内核 commit>   # 顺便写溯源
 *   YS_WASM=/path/to.wasm node scripts/sync-wasm.mjs --commit <40 位内核 commit>   # 显式产物 + 写溯源
 *   YS_PUBLIC_DIR=/tmp/x YS_WASM=/path/to.wasm node scripts/sync-wasm.mjs --expect-sha <sha256>
 */
import { execFileSync } from 'node:child_process'
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
const hasFlag = (name) => argv.some((a) => a === `--${name}` || a.startsWith(`--${name}=`))
const argVal = (name) => {
  const eq = argv.find((a) => a.startsWith(`--${name}=`))
  if (eq) return eq.split('=').slice(1).join('=')
  const i = argv.indexOf(`--${name}`)
  if (i < 0) return ''
  const next = argv[i + 1]
  return next === undefined || next.startsWith('--') ? '' : next
}

// ── 1) 参数：commit 必须由调用方明确声明（40 位十六进制），脚本不许猜来源 ──────────────
const wantCommit = String(argVal('commit') || '').trim().toLowerCase()
if (hasFlag('commit') && !wantCommit) {
  console.error('[sync-wasm] --commit 需要值：<40 位十六进制内核 commit>（不给值等于"我想写溯源但不说来源"，拒绝）')
  process.exit(2)
}
if (wantCommit && !/^[0-9a-f]{40}$/.test(wantCommit)) {
  console.error(`[sync-wasm] --commit 必须是 40 位十六进制 commit（实际「${wantCommit}」）——拒绝同步/写溯源`)
  process.exit(2)
}

// ── 2) 已有溯源：只当"参考/待替换"，不当权威 ─────────────────────────────────────
let meta = null
if (existsSync(metaPath)) {
  try {
    meta = JSON.parse(readFileSync(metaPath, 'utf8'))
  } catch (err) {
    console.error(`[sync-wasm] 溯源不是合法 JSON（${err.message}）——拒绝同步（先修/删 ${metaPath}）`)
    process.exit(2)
  }
}

// ── 3) 期望摘要：显式 --expect-sha > --commit + 显式 YS_WASM 现算 > 旧溯源 ─────────
let expectSha = String(argVal('expect-sha') || '').trim().toLowerCase()
let expectFrom = expectSha ? '--expect-sha' : ''
if (hasFlag('expect-sha') && !expectSha) {
  console.error('[sync-wasm] --expect-sha 需要值：<64 位十六进制 sha256>（悬空等于"我以为我指定了版本"，拒绝猜）')
  process.exit(2)
}
if (expectSha && !/^[0-9a-f]{64}$/.test(expectSha)) {
  console.error(`[sync-wasm] --expect-sha 必须是 64 位十六进制 sha256（实际「${expectSha}」）——拒绝同步`)
  process.exit(2)
}
if (!expectSha && wantCommit && process.env.YS_WASM) {
  const explicit = resolve(process.env.YS_WASM)
  if (!existsSync(explicit)) {
    console.error(`[sync-wasm] YS_WASM 指向的产物不存在：${explicit}——拒绝继续`)
    process.exit(2)
  }
  expectSha = sha256File(explicit)
  expectFrom = 'YS_WASM（显式产物）'
  console.log(`[sync-wasm] 未给 --expect-sha：按显式 YS_WASM 取摘要 ${expectSha.slice(0, 12)}…（只认这一份，不扫缓存）`)
}
if (!expectSha && meta && meta.sha256) {
  expectSha = String(meta.sha256).toLowerCase()
  expectFrom = '已有溯源'
}
if (!expectSha) {
  console.error(
    [
      '[sync-wasm] 没有可用的期望摘要（溯源缺 sha256，也没给 --expect-sha / --commit+YS_WASM）——无法确定要同步哪一版，拒绝继续。',
      '  npm run wasm:rebuild                              # 重建并写溯源（推荐）',
      '  node scripts/sync-wasm.mjs --expect-sha <sha256>  # 你明确知道要用哪一版时',
      '  YS_WASM=<产物路径> node scripts/sync-wasm.mjs --commit <40 位 commit>   # 显式产物 + 写溯源',
    ].join('\n'),
  )
  process.exit(2)
}
// 换版提示要放在**门禁通过之后**打（先打印"将被替换"再 exit 3 = 承诺了没做）
const replacingMeta = Boolean(meta && meta.sha256 && String(meta.sha256).toLowerCase() !== expectSha)
const commitChanged = Boolean(wantCommit && meta && meta.commit && String(meta.commit) !== wantCommit)

// ── 4) 候选（含仓库里的冻结内核；仍然只认同摘要的那一份） ───────────────────────────
// 冻结内核按**目录布局**取（web/ 的上一级 server/kernel/），不依赖 git，tarball/CI 里也成立
const frozenKernel = resolve(webDir, '../server/kernel/yanshu_sm.wasm')

const candidates = [
  process.env.YS_WASM,
  process.env.CARGO_TARGET_DIR && resolve(process.env.CARGO_TARGET_DIR, 'wasm32-unknown-unknown/release/yanshu_sm.wasm'),
  '/.cache/rust-web/wasm32-unknown-unknown/release/yanshu_sm.wasm',
  '/.cache/rust/wasm32-unknown-unknown/release/yanshu_sm.wasm',
  frozenKernel,
].filter(Boolean)

const { hit, scanned } = pickMatchingCandidate(candidates, expectSha)
if (!hit) {
  console.error(
    [
      `[sync-wasm] 没有候选与期望摘要一致（期望 ${expectSha.slice(0, 12)}…，来源：${expectFrom}）——不会用别的版本凑数。`,
      '候选：',
      formatScanned(scanned),
      '  npm run wasm:rebuild   # 从内核分支重建；或设 YS_WASM 指向正确产物',
    ].join('\n'),
  )
  process.exit(2)
}

// ── 5) 要写溯源时，先确认"声明的 commit"在本仓真的存在（非 git 环境降级为告警） ──────
if (wantCommit) {
  let gitRoot = null
  try {
    gitRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: webDir, stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim()
  } catch {
    gitRoot = null
  }
  if (!gitRoot) {
    console.warn('[sync-wasm] 当前不在 git 仓库里，无法校验 --commit 是否真实存在（按声明写入，请自行确认）')
  } else {
    try {
      execFileSync('git', ['cat-file', '-e', `${wantCommit}^{commit}`], { cwd: gitRoot, stdio: 'ignore' })
    } catch {
      console.error(
        `[sync-wasm] --commit ${wantCommit.slice(0, 7)} 在本仓库不存在（git cat-file 失败）——拒绝写溯源：` +
          '那样会把"同源"写成一句假话。先 git fetch origin，或换成真实的内核 commit。',
      )
      process.exit(2)
    }
  }
}

// ── 6) 无条件实例化核验：不是雁书内核的字节不进 public/ ─────────────────────────────
let facts
try {
  facts = probeKernel(readFileSync(hit.path))
} catch (err) {
  console.error(`[sync-wasm] 候选产物不合格（${err.message}）——拒绝同步：${hit.path}`)
  process.exit(3)
}
const problems = []
// 0 import 已由 probeKernel 先拒（它会在实例化前抛错），这里只补"契约形状"四项
if (facts.ysVersion !== '0x10000') problems.push(`ys_version 应为 0x10000（YSPK/1.0），实际 ${facts.ysVersion}`)
if (facts.headerLen !== 112) problems.push(`ys_header_len 应为 112（契约布局），实际 ${facts.headerLen}`)
if (!facts.hasMemory) problems.push('缺少 memory 导出')
if (wantCommit) {
  // 与 wasm:rebuild 同强度：要写溯源就别放过 rebuild 会拒的产物
  if (facts.unpackV1Arity !== 6) problems.push(`ys_unpack_v1 应为 6 参自证原型，实际 ${facts.unpackV1Arity}`)
  if (!facts.hasSignDer) problems.push('缺少 ys_sm2_sign_der（契约 DER 签名）')
  if (!facts.hasPackV1) problems.push('缺少 ys_pack_v1（清单 ext/created_at）')
}
if (problems.length) {
  console.error(
    `[sync-wasm] 候选产物不合格（${wantCommit ? '写溯源的门禁' : '基本核验'}）——拒绝同步：${hit.path}\n - ` +
      problems.join('\n - '),
  )
  process.exit(3)
}

// 门禁过了才说"要换溯源"：不承诺做不到的事
if (replacingMeta) {
  console.log(
    `[sync-wasm] 溯源将被替换：旧 ${String(meta.sha256).slice(0, 12)}…（commit ${String(meta.commit).slice(0, 7)}）` +
      ` → 新 ${expectSha.slice(0, 12)}…（期望来源：${expectFrom}）`,
  )
} else if (commitChanged) {
  // 同一份字节、换一个 commit 声明：也要说出来（否则"同源"被悄悄改写）
  console.log(
    `[sync-wasm] 溯源里的 commit 声明变更：${String(meta.commit).slice(0, 7)} → ${wantCommit.slice(0, 7)}（产物字节不变）`,
  )
}

// ── 7) 拷贝 + 复验（旧溯源的字节数只在不替换它时才是一道硬门禁；一律在拷贝前判，免得留下"新产物 + 旧溯源"）──
const oldBytes = bytesOf(target)
const candBytes = bytesOf(hit.path)
if (!wantCommit && meta && meta.bytes && Number(meta.bytes) !== candBytes) {
  console.error(
    `[sync-wasm] 拒绝：溯源写的是 ${meta.bytes} B，候选是 ${candBytes} B（摘要一致但字节数不同）——` +
      '先把溯源修对或删掉，别让 public/ 处于"产物与溯源各说一套"的状态',
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

// ── 8) 溯源：只在声明了 commit 时才写；否则明确说清"这次没写" ───────────────────────
if (wantCommit) {
  atomicWriteJson(metaPath, {
    commit: wantCommit,
    ref: wantCommit.slice(0, 7),
    builtAt: new Date().toISOString(),
    sha256: got,
    bytes,
    ...facts,
  })
  console.log(
    `[sync-wasm] 已写溯源：${metaPath}（commit=${wantCommit.slice(0, 7)} sha256=${got.slice(0, 12)}… ` +
      `${bytes} B / ysVersion=${facts.ysVersion} header=${facts.headerLen} exports=${facts.exports}）`,
  )
  if (oldBytes > 0 && oldBytes !== bytes) console.log(`[sync-wasm] 产物字节数变化：${oldBytes} B → ${bytes} B`)
} else if (!meta) {
  console.warn(
    [
      '[sync-wasm] 注意：这次**没有写溯源**（没给 --commit，也没有已有溯源可沿用）。',
      '  → 直接跑 node --test：`tests/wasm-real.test.js` 的「产物 ↔ commit 同源」会 SKIP（不是通过）。',
      '  → 跑 npm test / npm run build：pretest / prebuild 的 ensure-wasm 会因缺溯源**硬失败**（rc≠0）。',
      '  → 要跳过这两条：加 --commit <该产物对应的 40 位内核 commit>，或 npm run wasm:rebuild。',
    ].join('\n'),
  )
}

function bytesOf(path) {
  try {
    return existsSync(path) ? readFileSync(path).length : 0
  } catch {
    return 0
  }
}
