/**
 * "默认解包不得静默接受两种布局"的回归：用旧布局内核（HEADER 40）产一个包，
 * 喂给当前契约内核的默认解包入口，必须被拒。
 *
 * 旧产物不在仓库里（`*.wasm` 被忽略），找不到就 skip——不伪装 PASS。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { instantiateKernel } from '../src/crypto/wasm.js'
import { kernelPathOrSkip } from './helpers/kernel.js'

const here = dirname(fileURLToPath(import.meta.url))

test('旧布局包喂给契约内核：默认解包入口必须拒绝', async (t) => {
  const newPath = kernelPathOrSkip(t)
  if (!newPath) return
  const legacyCandidates = [process.env.YS_WASM_LEGACY, resolve(here, '../public/ys_kernel-legacy.wasm')].filter(Boolean)
  const legacyPath = legacyCandidates.find((p) => existsSync(p))
  if (!legacyPath) {
    if (process.env.CI) assert.fail('CI 下缺旧布局产物（public/ys_kernel-legacy.wasm）')
    t.skip('缺旧布局产物（可选回归，不影响契约布局结论）')
    return
  }
  const legacy = await instantiateKernel(readFileSync(legacyPath))
  assert.equal(legacy.headerLen, 40, '旧产物应是 HEADER 40')

  const oldAlice = legacy.generateIdentity()
  const oldBob = legacy.generateIdentity()
  const data = new Uint8Array(200).map((_, i) => (i * 11) & 0xff)
  const legacyPack = legacy.pack({
    data,
    name: 'legacy.bin',
    mime: 'application/octet-stream',
    recipientPublic: oldBob.publicKey,
    senderPrivate: oldAlice.privateKey,
  })
  assert.equal(new TextDecoder().decode(legacyPack.subarray(0, 4)), 'YSPK', '旧包也带 YSPK 魔数')

  const kernel = await instantiateKernel(readFileSync(newPath))
  const bob = kernel.generateIdentity()

  let error = null
  try {
    kernel.unpack({ pack: legacyPack, recipientPrivate: bob.privateKey })
  } catch (err) {
    error = err
  }
  assert.ok(error, '旧包必须被拒，不得返回明文')
  assert.match(error.code, /^CRYPTO_/, `错误码应映射到端侧错误：${error.code}`)
  console.log(`[legacy-reject] ${error.code}: ${error.message}`)

  let metaError = null
  try {
    kernel.unpackMeta({ pack: legacyPack, recipientPrivate: bob.privateKey })
  } catch (err) {
    metaError = err
  }
  assert.ok(metaError, '清单入口同样必须拒绝旧包')
})
