/**
 * 真内核测试的统一入口：**缺产物时用框架的 skip，而不是裸 return**（复审 P2）。
 *
 * - 本地缺产物 → `t.skip(...)`，报告里显示 SKIPPED，不计入 pass；
 * - `CI` 下缺产物 → 直接 `assert.fail(...)`，让流水线红，不许“全绿但一条真断言都没跑”。
 */
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

export const WASM_PATH = process.env.YS_WASM || resolve(here, '../../public/ys_kernel.wasm')
export const BUILD_META_PATH = resolve(here, '../../public/ys_kernel.build.json')

export function kernelPathOrSkip(t) {
  if (existsSync(WASM_PATH)) return WASM_PATH
  if (process.env.CI) {
    assert.fail(`CI 下缺内核产物：${WASM_PATH}（先跑 npm run wasm:rebuild）`)
  }
  t.skip(`没找到内核产物：${WASM_PATH}（npm run wasm:rebuild 生成）`)
  return null
}

export function buildMetaOrSkip(t) {
  if (existsSync(BUILD_META_PATH)) return BUILD_META_PATH
  if (process.env.CI) assert.fail(`CI 下缺构建溯源：${BUILD_META_PATH}`)
  t.skip(`没有 ys_kernel.build.json（npm run wasm:rebuild 生成）`)
  return null
}
