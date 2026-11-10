/**
 * 真内核测试的统一入口：**缺产物时用框架的 skip，而不是裸 return**（复审 P2）。
 *
 * - 本地缺产物 → `t.skip(...)`，报告里显示 SKIPPED，不计入 pass；
 * - `CI` 下缺产物 → 直接 `assert.fail(...)`，让流水线红，不许“全绿但一条真断言都没跑”。
 *
 * v5 收口补充（flake 修复）：`public/ys_kernel.build.json` 可能正被 `scripts/ensure-wasm.mjs`
 * 改写（先写临时文件再 rename），窗口内 `existsSync` 为假或读到半截 JSON。这里对**溯源文件**
 * 做「短重试 + 容忍半截 JSON」：等到它就位再判断；等不到才 skip，且原因写清楚（这是环境准备，
 * 不是"通过"）。
 *
 * 测试可用 `YS_BUILD_META` 把溯源指到别处（用于造"产物在、溯源缺"的反证）。
 */
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

export const WASM_PATH = process.env.YS_WASM || resolve(here, '../../public/ys_kernel.wasm')
export const BUILD_META_PATH = process.env.YS_BUILD_META || resolve(here, '../../public/ys_kernel.build.json')

const RETRY_MS = 100
const RETRY_TIMES = 20 // 合计最多等 2s：足够跨过 ensure-wasm 的写窗口

const sleep = (ms) => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

/** 读构建溯源；文件缺失或正被改写（半截 JSON）都按"暂时读不到"处理，短重试。 */
export function readBuildMeta() {
  for (let i = 0; i < RETRY_TIMES; i++) {
    if (existsSync(BUILD_META_PATH)) {
      try {
        const meta = JSON.parse(readFileSync(BUILD_META_PATH, 'utf8'))
        if (meta && typeof meta === 'object') return meta
      } catch {
        // 半截 JSON / EBUSY：正在被 rename 覆盖，下一轮再读
      }
    }
    sleep(RETRY_MS)
  }
  return null
}

/** 等产物与溯源都可用（最多 timeoutMs）；返回 { wasm:boolean, meta:object|null } */
export function waitForArtifacts(timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const meta = readBuildMeta()
    if (existsSync(WASM_PATH) && meta) return { wasm: true, meta }
    if (Date.now() > deadline) break
    sleep(RETRY_MS)
  }
  return { wasm: existsSync(WASM_PATH), meta: readBuildMeta() }
}

export function kernelPathOrSkip(t) {
  if (existsSync(WASM_PATH)) return WASM_PATH
  if (process.env.CI) {
    assert.fail(`CI 下缺内核产物：${WASM_PATH}（先跑 npm run wasm:rebuild）`)
  }
  t.skip(`没找到内核产物：${WASM_PATH}（npm run wasm:rebuild 生成）`)
  return null
}

export function buildMetaOrSkip(t) {
  const meta = readBuildMeta()
  if (meta) return BUILD_META_PATH
  if (process.env.CI) assert.fail(`CI 下缺构建溯源：${BUILD_META_PATH}`)
  t.skip(`没有可解析的 ys_kernel.build.json：${BUILD_META_PATH}（npm run wasm:rebuild 或 wasm:sync --commit 生成；`
    + '文件缺失或正在被改写都算"环境未就绪"，不计入通过）')
  return null
}
