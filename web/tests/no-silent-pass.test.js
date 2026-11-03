/**
 * 反证（复审 P2 第 4 条）：**缺内核产物时不许"静默通过"**。
 *
 * 用一个不存在的 `YS_WASM` 跑真内核测试文件，断言两种表现之一：
 *   - 本地：报告里是 SKIPPED（`# pass 0`、`# skipped > 0`）；
 *   - CI：非 0 退出（`assert.fail`）。
 * 任何"退出 0 且 pass > 0"都判本用例失败——那说明又回到"看起来绿其实没跑"。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

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

test('缺产物 + 本地：真内核用例必须 SKIP（pass=0），不得计为通过', () => {
  const { code, out } = runReal({ YS_WASM: MISSING, CI: '' })
  assert.equal(code, 0, `本地缺产物应当以 0 退出但全部 SKIP：\n${out.slice(0, 400)}`)
  assert.equal(collect(out, 'pass'), 0, 'pass 必须是 0（说明一条真断言都没跑）')
  assert.ok((collect(out, 'skipped') ?? 0) >= 6, `skipped 应 ≥6，实际 ${collect(out, 'skipped')}`)
  assert.match(out, /# SKIP|SKIP/i)
})

test('缺产物 + CI：必须非 0 退出（不许静默跳过）', () => {
  const { code, out } = runReal({ YS_WASM: MISSING, CI: '1' })
  assert.notEqual(code, 0, `CI 缺产物必须失败：\n${out.slice(0, 400)}`)
  assert.match(out, /CI 下缺内核产物/)
})

test('有产物时真内核用例真的执行了（pass>0，skipped=0）', () => {
  const { code, out } = runReal({ YS_WASM: '', CI: '' })
  assert.equal(code, 0)
  assert.ok((collect(out, 'pass') ?? 0) > 0, '跑通时必须有通过的真内核用例')
  assert.equal(collect(out, 'skipped'), 0, '产物就位时不应有跳过')
})
