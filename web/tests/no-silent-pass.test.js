/**
 * 反证（复审 P2 第 4 条）：**缺内核产物时不许"静默通过"**。
 *
 * 三条性质，缺一不可：
 *   1. 本地缺产物：子进程全部 SKIP、退出 0，`pass=0`（不得计为通过）；
 *   2. CI 缺产物：子进程非 0 退出；
 *   3. **产物就位时**：子进程必须真跑（`pass>0` 且 `skipped=0`）。
 *
 * flake 修复（v5 收口）：第 3 条以前直接跑，遇到 `public/ys_kernel.build.json` 正被
 * `ensure-wasm` 改写（瞬时缺失/半截 JSON）就会 `skipped=1` 而红。现在先做**环境准备**
 * （`scripts/ensure-wasm.mjs` + `waitForArtifacts` 重试），准备不成就显式 skip 并打
 * `SKIP-VACUOUS`（说明"这条断言在无产物环境下不可判定"）——但**不放开判定**：
 * 产物在却出现跳过，仍然判失败（见 classify + 最后一条反证）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { waitForArtifacts } from './helpers/kernel.js'

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const MISSING = '/nonexistent/ys_kernel.wasm'

function runReal(env) {
  // 关键：子进程必须清掉 NODE_TEST_CONTEXT（否则它以为自己仍是父测试的子进程，报告格式会变）
  const childEnv = { ...process.env, ...env }
  delete childEnv.NODE_TEST_CONTEXT
  delete childEnv.NODE_OPTIONS
  try {
    const out = execFileSync(
      process.execPath,
      ['--test', 'tests/wasm-real.test.js'],
      { cwd: webDir, env: childEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    )
    return { code: 0, out }
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout || ''}${err.stderr || ''}` }
  }
}

const collect = (out, key) => {
  const m = out.match(new RegExp(`^# ${key} (\\d+)$`, 'm'))
  return m ? Number(m[1]) : null
}

/** 唯一判定口径：产物就位时必须"真跑且没跳过"，否则不算通过。 */
const classify = (out) => {
  const pass = collect(out, 'pass')
  const skipped = collect(out, 'skipped')
  return { pass, skipped, ok: (pass ?? 0) > 0 && skipped === 0 }
}

/**
 * 环境准备 = **只等，不改产物**。
 *
 * 为什么不在这里跑 `ensure-wasm`：它会为「产物在、溯源缺」的场景走 `wasm:sync`，
 * 从构建缓存拷回一个**可能不同版本**的 wasm，直接把现有产物覆盖成与溯源不匹配的版本
 * （本机实测：140,762 B/daa949… 被换成 111,841 B/0c9e2f…，随后真内核用例全红）。
 * 门禁测试只该**判定**环境，不该**修改**环境；产物缺失就让用例显式 skip（CI 里仍然红）。
 */
function prepareArtifacts() {
  const w = waitForArtifacts(3000)
  return { ok: w.wasm && Boolean(w.meta), out: w.wasm ? '产物与溯源都可读' : '缺少内核产物' }
}

test('缺产物 + 本地：真内核用例必须 SKIP（pass=0），不得计为通过', { timeout: 60000 }, () => {
  const { code, out } = runReal({ YS_WASM: MISSING, CI: '' })
  assert.equal(code, 0, `本地缺产物应当以 0 退出但全部 SKIP：\n${out.slice(0, 400)}`)
  assert.equal(collect(out, 'pass'), 0, 'pass 必须是 0（说明一条真断言都没跑）')
  assert.ok((collect(out, 'skipped') ?? 0) >= 6, `skipped 应 ≥6，实际 ${collect(out, 'skipped')}`)
  assert.match(out, /# SKIP|SKIP/i)
})

test('缺产物 + CI：必须非 0 退出（不许静默跳过）', { timeout: 60000 }, () => {
  const { code, out } = runReal({ YS_WASM: MISSING, CI: '1' })
  assert.notEqual(code, 0, `CI 缺产物必须失败：\n${out.slice(0, 400)}`)
  assert.match(out, /CI 下缺内核产物/)
})

test('有产物时真内核用例真的执行了（pass>0，skipped=0）', { timeout: 180000 }, (t) => {
  const ready = prepareArtifacts()
  if (!ready.ok) {
    // 环境准备失败 ≠ 测试失败：显式 skip，并把"这条断言没判定"喊出来，别让绿报告骗人。
    console.log(`[no-silent-pass] SKIP-VACUOUS 内核产物未就绪，本条在无产物环境下不可判定：${ready.out}`)
    t.skip(`内核产物未就绪（ensure-wasm 失败或产物不可读）：${ready.out}`)
    return
  }
  // 产物就位后跑子进程；若这一跑又撞上改写窗口（skipped>0），重新准备并重试（最多 3 次）。
  // 重试只解决"环境瞬时不可读"，**不放宽判定**：3 次后仍有跳过就红。
  let last = { code: 1, out: '' }
  let c = { pass: 0, skipped: null, ok: false }
  for (let attempt = 1; attempt <= 3; attempt++) {
    last = runReal({ YS_WASM: '', CI: '' })
    c = classify(last.out)
    if (last.code === 0 && c.ok) break
    if (attempt < 3) {
      console.log(`[no-silent-pass] 第 ${attempt} 次子进程结果 pass=${c.pass} skipped=${c.skipped}，重新准备产物后重试`)
      prepareArtifacts()
    }
  }
  assert.equal(last.code, 0)
  assert.ok((c.pass ?? 0) > 0, `跑通时必须有通过的真内核用例：\n${last.out.slice(-400)}`)
  assert.equal(c.skipped, 0, `产物就位时不应有跳过（跳过＝静默放行）：\n${last.out.slice(-400)}`)
})

test('反证：出现跳过就一定判「不通过」（classify 没有被放宽）', () => {
  // 真实 TAP 片段（来自 `node --test tests/wasm-real.test.js` 的输出形态）
  const allRan = ['# tests 11', '# pass 11', '# fail 0', '# skipped 0'].join('\n')
  const oneSkipped = ['# tests 11', '# pass 10', '# fail 0', '# skipped 1'].join('\n')
  const allSkipped = ['# tests 11', '# pass 0', '# fail 0', '# skipped 11'].join('\n')

  assert.deepEqual(classify(allRan), { pass: 11, skipped: 0, ok: true }, '全部真跑才算通过')
  assert.equal(classify(oneSkipped).ok, false, '哪怕只跳过 1 条，也不许算通过')
  assert.equal(classify(allSkipped).ok, false, '全跳过更不许算通过')
  assert.equal(classify('（没有 TAP 汇总）').ok, false, '解析不出计数时必须判不通过（fail closed）')
})
