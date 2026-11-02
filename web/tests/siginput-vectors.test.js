/**
 * `SIG_INPUT` 与内核向量逐字节对齐（vendored：`tests/fixtures/sm2-verify-vectors.json`）。
 *
 * 覆盖七种 PURPOSE；任何字段顺序/宽度/前缀/CODE 位置/昵称 `u16be` 前缀被改动，这里立刻红。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { checkSigInputVectors } from '../src/net/siginput-vectors.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(resolve(here, 'fixtures/sm2-verify-vectors.json'), 'utf8'))

test('SIG_INPUT 七种 PURPOSE 与内核向量逐字节一致', () => {
  const results = checkSigInputVectors(vectors)
  const bad = results.filter((r) => !r.ok)
  assert.equal(
    bad.length,
    0,
    bad.map((r) => `${r.purpose}: len ${r.expectedLen}/${r.actualLen}, diff@${r.diffAt}`).join('; '),
  )
  assert.equal(results.length, 7)
  // 长度也要与向量声明一致
  for (const r of results) assert.equal(r.actualLen, r.declaredLen, `${r.purpose} 长度不符`)
})

test('向量 meta 的 ZA 口径与实现约定一致（ID=1234567812345678、ENTL=0x0080）', () => {
  assert.equal(vectors.meta.user_id, '1234567812345678')
  assert.match(String(vectors.meta.entl), /0x0080/)
  assert.match(String(vectors.meta.signed_digest), /ZA/)
})
