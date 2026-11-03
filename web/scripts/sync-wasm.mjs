#!/usr/bin/env node
/**
 * 把端侧内核的 wasm 产物同步到前端静态目录。
 *
 * 产物不入库（根 `.gitignore` 忽略 `*.wasm`），所以部署/本地联调都要先跑这一步。
 * 查找顺序：YS_WASM 环境变量 → CARGO_TARGET_DIR → /.cache/rust-web → /.cache/rust。
 *
 * 用法：npm run wasm:sync
 */
import { copyFileSync, existsSync, mkdirSync, statSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const target = resolve(here, '../public/ys_kernel.wasm')

const candidates = [
  process.env.YS_WASM,
  process.env.CARGO_TARGET_DIR &&
    resolve(process.env.CARGO_TARGET_DIR, 'wasm32-unknown-unknown/release/yanshu_sm.wasm'),
  '/.cache/rust-web/wasm32-unknown-unknown/release/yanshu_sm.wasm',
  '/.cache/rust/wasm32-unknown-unknown/release/yanshu_sm.wasm',
].filter(Boolean)

const found = candidates.find((p) => existsSync(p))
if (!found) {
  console.error('没找到 yanshu_sm.wasm。先在仓库根构建：')
  console.error(
    '  cd crypto && CARGO_TARGET_DIR=/.cache/rust-web cargo build --release --target wasm32-unknown-unknown -p yanshu-sm',
  )
  console.error('或设置 YS_WASM=/path/to/yanshu_sm.wasm')
  process.exit(2)
}

mkdirSync(dirname(target), { recursive: true })
copyFileSync(found, target)
const size = statSync(target).size
console.log(`已同步：${found} → public/ys_kernel.wasm（${size} 字节）`)
