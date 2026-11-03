#!/usr/bin/env node
/**
 * 与内核的 `SIG_INPUT` 向量逐字节对账。
 *
 *   cd web && npm run siginput:check
 *   YS_SIGINPUT_VECTORS=/path/to/sm2-verify-vectors.json npm run siginput:check
 *
 * 不一致时打印两侧 hex 与**第一个差异字节的偏移**，便于判断是字段顺序、宽度还是前缀问题。
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { checkSigInputVectors } from '../src/net/siginput-vectors.js'

const here = dirname(fileURLToPath(import.meta.url))
const path = process.env.YS_SIGINPUT_VECTORS || resolve(here, '../tests/fixtures/sm2-verify-vectors.json')
const vectors = JSON.parse(readFileSync(path, 'utf8'))

console.log(`向量文件：${path}`)
console.log(`meta：user_id=${vectors.meta?.user_id} entl=${vectors.meta?.entl}\n`)

let failed = 0
for (const r of checkSigInputVectors(vectors)) {
  if (r.ok) {
    console.log(`✅ ${r.purpose.padEnd(16)} len=${r.actualLen} 逐字节一致`)
  } else {
    failed += 1
    console.log(`❌ ${r.purpose.padEnd(16)} 期望 len=${r.expectedLen}（声明 ${r.declaredLen}）/ 实际 ${r.actualLen}，首个差异偏移 ${r.diffAt}`)
    console.log(`   expected = ${r.expected}`)
    console.log(`   actual   = ${r.actual}`)
  }
}

console.log(`\n合计 ${vectors.sig_input_samples.length} 组，失败 ${failed} 组`)
process.exit(failed === 0 ? 0 : 1)
