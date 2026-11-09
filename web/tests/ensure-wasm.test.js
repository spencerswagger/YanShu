/**
 * `ensure-wasm` / `sync-wasm` 的**版本绑定回归**（国密内核不能静默换版）。
 *
 * 两种必须报错的情形：
 *   ① 产物在、溯源缺（旧实现会从缓存拷回另一版并当成功，140,762B/daa949… → 111,841B/0c9e2f…）；
 *   ② 溯源写的摘要与产物不符。
 * 两种情形都要断言：脚本非 0 退出、**产物字节没被替换**（比较前后 sha256）、报错里能看到两边的摘要。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const WEB = resolve(here, '..')
const ENSURE = join(WEB, 'scripts/ensure-wasm.mjs')
const SYNC = join(WEB, 'scripts/sync-wasm.mjs')

const sha = (buf) => createHash('sha256').update(buf).digest('hex')

/** 造一个临时 public 目录；返回路径与写入工具 */
function sandbox({ wasm, meta } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ys-ensure-'))
  const publicDir = join(dir, 'public')
  mkdirSync(publicDir, { recursive: true })
  const wasmPath = join(publicDir, 'ys_kernel.wasm')
  const metaPath = join(publicDir, 'ys_kernel.build.json')
  if (wasm) writeFileSync(wasmPath, wasm)
  if (meta) writeFileSync(metaPath, typeof meta === 'string' ? meta : JSON.stringify(meta, null, 2))
  return { dir, publicDir, wasmPath, metaPath }
}

function run(script, { publicDir, env = {}, args = [] } = {}) {
  try {
    const stdout = execFileSync(process.execPath, [script, ...args], {
      env: { ...process.env, YS_PUBLIC_DIR: publicDir, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return { rc: 0, stdout: String(stdout), stderr: '' }
  } catch (err) {
    return { rc: err.status ?? -1, stdout: String(err.stdout || ''), stderr: String(err.stderr || '') }
  }
}

const WASM_A = Buffer.alloc(140_762, 0x61) // 假装「正确的那一版」
const WASM_B = Buffer.alloc(111_841, 0x62) // 假装缓存里「另一版」

test('① 产物在、溯源缺：非 0 退出，且不会被替换成缓存里的另一版', () => {
  const sb = sandbox({ wasm: WASM_A })
  const before = sha(readFileSync(sb.wasmPath))
  const decoy = join(sb.dir, 'cached-other.wasm')
  writeFileSync(decoy, WASM_B)

  const r = run(ENSURE, { publicDir: sb.publicDir, env: { YS_WASM: decoy } })

  assert.notEqual(r.rc, 0, '缺溯源必须非 0 退出')
  assert.match(r.stderr, /缺溯源/, '报错要说清是缺溯源')
  assert.match(r.stderr, /140762|daa949|sha256=/i, '报错要带现有产物的大小/摘要')
  assert.match(r.stderr, /wasm:rebuild/, '要给可执行的下一步')
  assert.equal(sha(readFileSync(sb.wasmPath)), before, '产物一个字节都不许变（不许换成另一版）')
  assert.equal(readFileSync(sb.wasmPath).length, 140_762)
  assert.equal(existsSync(join(sb.publicDir, 'ys_kernel.build.json')), false, '不许自己编一份溯源出来')
})

test('② 溯源与产物不符：非 0 退出，产物保持原样，报错带两边的摘要', () => {
  const sb = sandbox({ wasm: WASM_A, meta: { commit: 'bad', sha256: sha(WASM_B), bytes: WASM_B.length } })
  const before = sha(readFileSync(sb.wasmPath))
  const decoy = join(sb.dir, 'cached-other.wasm')
  writeFileSync(decoy, WASM_B)

  const r = run(ENSURE, { publicDir: sb.publicDir, env: { YS_WASM: decoy } })

  assert.notEqual(r.rc, 0)
  assert.match(r.stderr, /SHA_MISMATCH|不一致/, '要点明摘要不一致')
  assert.ok(r.stderr.includes(sha(WASM_A).slice(0, 12)), '报错要带产物的摘要')
  assert.ok(r.stderr.includes(sha(WASM_B).slice(0, 12)), '报错要带溯源的摘要')
  assert.equal(sha(readFileSync(sb.wasmPath)), before, '不一致时不许自动替换')
})

test('③ 产物与溯源一致：通过，且不改内容', () => {
  const sb = sandbox({ wasm: WASM_A, meta: { commit: 'ok', sha256: sha(WASM_A), bytes: WASM_A.length } })
  const r = run(ENSURE, { publicDir: sb.publicDir })
  assert.equal(r.rc, 0, r.stderr)
  assert.match(r.stdout, /产物就位/)
  assert.equal(sha(readFileSync(sb.wasmPath)), sha(WASM_A))
})

test('④ 产物缺、溯源在：只接受摘要一致的候选（原子写），不匹配就报错', () => {
  // 4a：缓存里没有这一版 → 报错，且不写产物
  const miss = sandbox({ meta: { sha256: sha(WASM_A), bytes: WASM_A.length } })
  const decoy = join(miss.dir, 'cached-other.wasm')
  writeFileSync(decoy, WASM_B)
  const r1 = run(ENSURE, { publicDir: miss.publicDir, env: { YS_WASM: decoy } })
  assert.notEqual(r1.rc, 0)
  assert.match(r1.stderr, /没有与溯源 sha256 一致的候选/)
  assert.equal(existsSync(miss.wasmPath), false, '没有对齐的候选就不许凭空造产物')

  // 4b：缓存里有正确的那版 → 原子拷入并通过，且不留临时文件
  const hit = sandbox({ meta: { sha256: sha(WASM_A), bytes: WASM_A.length } })
  const good = join(hit.dir, 'cached-good.wasm')
  writeFileSync(good, WASM_A)
  const r2 = run(ENSURE, { publicDir: hit.publicDir, env: { YS_WASM: good } })
  assert.equal(r2.rc, 0, r2.stderr)
  assert.equal(sha(readFileSync(hit.wasmPath)), sha(WASM_A))
  assert.deepEqual(readdirSync(hit.publicDir).filter((f) => f.includes('.tmp-')), [], '不许留半截临时文件')
})

test('⑤ sync-wasm：没有期望摘要时拒绝同步；摘要不符时拒绝；对齐时成功且不留临时文件', () => {
  // 5a：溯源缺 + 没给 --expect-sha → 拒
  const a = sandbox({ wasm: WASM_A })
  const candA = join(a.dir, 'cand.wasm')
  writeFileSync(candA, WASM_B)
  const r1 = run(SYNC, { publicDir: a.publicDir, env: { YS_WASM: candA } })
  assert.equal(r1.rc, 2)
  assert.match(r1.stderr, /期望摘要/)
  assert.equal(sha(readFileSync(a.wasmPath)), sha(WASM_A), '拒绝时不许动目标文件')

  // 5b：给了 --expect-sha，但候选不符 → 拒，并列出候选
  const r2 = run(SYNC, { publicDir: a.publicDir, env: { YS_WASM: candA }, args: ['--expect-sha', sha(WASM_A)] })
  assert.equal(r2.rc, 2)
  assert.match(r2.stderr, /没有候选与期望摘要一致/)
  assert.ok(r2.stderr.includes(sha(WASM_B).slice(0, 12)), '要有候选清单（便于人工判断）')
  assert.equal(sha(readFileSync(a.wasmPath)), sha(WASM_A))

  // 5c：对齐 → 成功
  const b = sandbox({})
  const candB = join(b.dir, 'cand-good.wasm')
  writeFileSync(candB, WASM_A)
  const r3 = run(SYNC, { publicDir: b.publicDir, env: { YS_WASM: candB }, args: ['--expect-sha', sha(WASM_A)] })
  assert.equal(r3.rc, 0, r3.stderr)
  assert.equal(sha(readFileSync(b.wasmPath)), sha(WASM_A))
  assert.deepEqual(readdirSync(b.publicDir).filter((f) => f.includes('.tmp-')), [])
})
