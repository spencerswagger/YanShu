/**
 * `wasm:sync` 的**溯源写入**与门禁回归（"看起来全绿、最关键的断言没跑"这类假绿）。
 *
 * 背景：README 曾写「cargo build 后 npm run wasm:sync」就算把产物准备好了，但 sync 只拷产物、
 * 从不写 `ys_kernel.build.json`，于是 `wasm-real.test.js` 的「产物 ↔ commit 同源」那条**静默 SKIP**。
 *
 * 本文件守两条线：
 *   A. **换版路径必须能走通**（P0）：public/ 里已有旧溯源时，用 `--commit + YS_WASM` 同步新产物
 *      不能被旧 meta.sha256 挡住，也不许留下「新产物 + 旧溯源」的半坏状态。
 *   B. **门禁有牙**：删掉任何一条核验（版本 / 包头 / import / arity / signDer / packV1 / 无 ys_version），
 *      对应的用例必须变红——所以每条门禁各有一个专门的用例，而不是只测 happy path。
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
import { buildTinyKernel } from './helpers/tiny-kernel.js'

const here = dirname(fileURLToPath(import.meta.url))
const WEB = resolve(here, '..')
const SYNC = join(WEB, 'scripts/sync-wasm.mjs')
const ENSURE = join(WEB, 'scripts/ensure-wasm.mjs')

const sha = (buf) => createHash('sha256').update(buf).digest('hex')

/** 当前仓库真实存在的 commit（写溯源时要过 `git cat-file -e`） */
const REAL_COMMIT = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: WEB, encoding: 'utf8' }).stdout.trim()

function sandbox({ wasm, meta } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ys-sync-prov-'))
  const publicDir = join(dir, 'public')
  mkdirSync(publicDir, { recursive: true })
  const wasmPath = join(publicDir, 'ys_kernel.wasm')
  const metaPath = join(publicDir, 'ys_kernel.build.json')
  if (wasm) writeFileSync(wasmPath, wasm)
  if (meta) writeFileSync(metaPath, typeof meta === 'string' ? meta : JSON.stringify(meta, null, 2))
  return { dir, publicDir, wasmPath, metaPath, cand: (bytes) => {
    const p = join(dir, `cand-${sha(bytes).slice(0, 8)}.wasm`)
    writeFileSync(p, bytes)
    return p
  } }
}

function run(script, { publicDir, env = {}, args = [] } = {}) {
  const r = spawnSync(process.execPath, [script, ...args], {
    env: { ...process.env, YS_PUBLIC_DIR: publicDir, ...env },
    encoding: 'utf8',
  })
  return { rc: r.status ?? -1, stdout: String(r.stdout || ''), stderr: String(r.stderr || '') }
}

// ── A. 换版路径（P0）─────────────────────────────────────────────────────────────

test('已有旧溯源时用 --commit + YS_WASM 换版：能同步进来，且溯源一起换新（不留"新产物 + 旧溯源"）', () => {
  const oldKernel = buildTinyKernel({ version: 0x10000, headerLen: 112 })
  // "新一版"：形状完全合法但字节不同（加一个空的 custom section），模拟内核升级
  const newKernel = Buffer.concat([buildTinyKernel(), Buffer.from([0x00, 0x02, 0x01, 0x00])])
  assert.notEqual(sha(newKernel), sha(oldKernel), '基线自检：两份产物必须不同字节')
  const oldMeta = { commit: 'b'.repeat(40), sha256: sha(oldKernel), bytes: oldKernel.length, ysVersion: '0x10000' }
  const sb = sandbox({ wasm: oldKernel, meta: oldMeta })
  const cand = sb.cand(newKernel)

  // 注意：这里**故意**不给 --expect-sha —— 旧溯源里的 sha 不能挡路，否则"内核换版"这个唯一需要 --commit 的场景跑不通
  const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: ['--commit', REAL_COMMIT] })
  assert.equal(r.rc, 0, `换版应成功，实际 rc=${r.rc}\nstdout:${r.stdout}\nstderr:${r.stderr}`)
  assert.equal(sha(readFileSync(sb.wasmPath)), sha(newKernel), 'public/ 里必须是新产物')
  const meta = JSON.parse(readFileSync(sb.metaPath, 'utf8'))
  assert.equal(meta.sha256, sha(newKernel), '溯源必须指向新产物（否则 ensure-wasm 会 SHA_MISMATCH）')
  assert.equal(meta.commit, REAL_COMMIT)
  assert.match(r.stdout, /溯源将被替换/, '换版要打一行「旧 → 新」，不许静默改写')

  // 换完之后 prebuild/pretest 的前置核验必须认这一对
  const e = run(ENSURE, { publicDir: sb.publicDir })
  assert.equal(e.rc, 0, `ensure-wasm 应认可换版后的产物+溯源：${e.stderr}`)
})

test('--commit 没给值 / 格式不对 / 本仓不存在：都非 0 退出，产物与溯源都不动', () => {
  const kernel = buildTinyKernel()
  const sb = sandbox({ wasm: kernel })
  const cand = sb.cand(kernel)
  const before = { sha: sha(readFileSync(sb.wasmPath)), meta: existsSync(sb.metaPath) }

  const cases = [
    { args: ['--expect-sha', sha(kernel), '--commit'], label: '--commit 缺值' },
    { args: ['--expect-sha', sha(kernel), '--commit', 'HEAD'], label: '--commit=HEAD' },
    { args: ['--expect-sha', sha(kernel), '--commit', 'a'.repeat(39)], label: '39 位' },
    { args: ['--expect-sha', sha(kernel), '--commit', 'f'.repeat(40)], label: '本仓不存在的 commit' },
  ]
  for (const c of cases) {
    const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: c.args })
    assert.notEqual(r.rc, 0, `${c.label} 必须非 0 退出`)
    assert.match(r.stderr, /--commit/, `${c.label} 的报错要指向 --commit`)
    assert.equal(existsSync(sb.metaPath), before.meta, `${c.label} 不许写溯源`)
    assert.equal(sha(readFileSync(sb.wasmPath)), before.sha, `${c.label} 不许动已有产物`)
  }
})

// ── B. 门禁要有牙：每条核验一个用例 ──────────────────────────────────────────────

test('产物形状门禁（版本 / 包头 / import / arity / signDer / packV1 / 无 ys_version）：逐条拒绝且不落盘', () => {
  const cases = [
    { label: 'ys_version=0x20000（不是 YSPK/1.0）', kernel: buildTinyKernel({ version: 0x20000 }), want: /ys_version/ },
    { label: 'ys_header_len=40（旧布局）', kernel: buildTinyKernel({ headerLen: 40 }), want: /ys_header_len/ },
    { label: '有 import', kernel: buildTinyKernel({ importCount: 2 }), want: /import/ },
    { label: '没有 ys_version', kernel: buildTinyKernel({ version: null }), want: /ys_version/ },
    { label: 'ys_unpack_v1 不是 6 参', kernel: buildTinyKernel({ unpackV1: false }), want: /ys_unpack_v1/ },
    { label: '没有 ys_sm2_sign_der', kernel: buildTinyKernel({ signDer: false }), want: /ys_sm2_sign_der/ },
    { label: '没有 ys_pack_v1', kernel: buildTinyKernel({ packV1: false }), want: /ys_pack_v1/ },
  ]
  for (const c of cases) {
    const sb = sandbox({})
    const cand = sb.cand(c.kernel)
    const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: ['--commit', REAL_COMMIT] })
    assert.notEqual(r.rc, 0, `${c.label} 必须被拒`)
    assert.match(r.stderr, c.want, `${c.label} 的报错应点明原因`)
    assert.equal(existsSync(sb.wasmPath), false, `${c.label}：不合格产物不许拷进 public/`)
    assert.equal(existsSync(sb.metaPath), false, `${c.label}：不合格产物不许写溯源`)
  }
})

test('完全不是 wasm 的字节：同步被拒（不留 59 B 假产物）', () => {
  const sb = sandbox({})
  const cand = sb.cand(Buffer.alloc(59, 0x61))
  const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: ['--expect-sha', sha(Buffer.alloc(59, 0x61))] })
  assert.notEqual(r.rc, 0, '非 wasm 字节必须被拒（哪怕摘要对上了）')
  assert.equal(existsSync(sb.wasmPath), false, '不许把假产物放进 public/')
})

test('只给 --expect-sha（不给 --commit）：同步成功但**不伪造溯源**，并说清 SKIP 与 npm test 会硬失败', () => {
  const kernel = buildTinyKernel()
  const sb = sandbox({})
  const cand = sb.cand(kernel)
  const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: ['--expect-sha', sha(kernel)] })
  assert.equal(r.rc, 0, r.stderr)
  assert.equal(sha(readFileSync(sb.wasmPath)), sha(kernel), '产物应逐字节一致')
  assert.equal(existsSync(sb.metaPath), false, '没有 --commit 不许凭空造 commit 写溯源')
  const out = r.stdout + r.stderr
  assert.match(out, /SKIP/, '必须明确说"同源断言会 SKIP"')
  assert.match(out, /--commit/, '要告诉怎么补溯源')
  assert.match(out, /pretest|prebuild|npm test/, '要说清 npm test / build 会因缺溯源硬失败（否则让人以为只是 SKIP）')
})

test('已有溯源 + 不给 --commit：沿用旧溯源摘要同步，字节数对不上时**拷贝前**就拒（不制造半坏状态）', () => {
  const kernel = buildTinyKernel()
  const staleBytesMeta = { commit: 'c'.repeat(40), sha256: sha(kernel), bytes: kernel.length + 10 }
  const sb = sandbox({ wasm: buildTinyKernel({ version: 0x10000 }), meta: staleBytesMeta })
  const cand = sb.cand(kernel)
  const before = sha(readFileSync(sb.wasmPath))

  const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand } })
  assert.equal(r.rc, 2, '字节数与溯源不符应拒绝')
  assert.match(r.stderr, /字节数/, '要说明是字节数不一致')
  assert.equal(sha(readFileSync(sb.wasmPath)), before, '拒绝时必须保留原产物（不能先拷再报错）')
})

// ── C. 真内核：写到能通过 ensure-wasm 的溯源 ─────────────────────────────────────

test('--commit + 真内核：溯源字段全部来自字节，且 ensure-wasm 认可', (t) => {
  const real = kernelPathOrSkip(t)
  if (!real) return
  const bytes = readFileSync(real)
  const sb = sandbox({})
  const cand = sb.cand(bytes)
  const r = run(SYNC, { publicDir: sb.publicDir, env: { YS_WASM: cand }, args: ['--commit', REAL_COMMIT] })
  assert.equal(r.rc, 0, `同步失败：${r.stderr}`)

  const meta = JSON.parse(readFileSync(sb.metaPath, 'utf8'))
  assert.equal(meta.commit, REAL_COMMIT, 'commit 应是调用方声明的那一个')
  assert.equal(meta.ref, REAL_COMMIT.slice(0, 7))
  assert.match(meta.builtAt, /^\d{4}-\d{2}-\d{2}T/, 'builtAt 应是 ISO 时间')
  assert.equal(meta.sha256, sha(bytes), 'sha256 必须从字节现算')
  assert.equal(meta.bytes, bytes.length, 'bytes 必须从字节现算')
  assert.equal(meta.ysVersion, '0x10000', 'ys_version 由产物自己回答')
  assert.equal(meta.headerLen, 112, 'ys_header_len 由产物自己回答')
  assert.equal(meta.imports, 0, '内核必须 0 import')
  assert.equal(meta.unpackV1Arity, 6)
  assert.ok(meta.exports >= 43, `函数导出数应 ≥43，实际 ${meta.exports}`)

  const e = run(ENSURE, { publicDir: sb.publicDir })
  assert.equal(e.rc, 0, `ensure-wasm 应认可：${e.stderr}`)
})
