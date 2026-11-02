#!/usr/bin/env node
/**
 * 最小复现：`SIG_INPUT` 用**头码**构造、请求**路径码**与头码不同 → 期望 `AUTH_CODE_MISMATCH`。
 *
 *   node web/scripts/repro-code-mismatch.mjs                      # 默认打宿主 18080
 *   CORE_BASE=http://127.0.0.1:18090/v1 node web/scripts/repro-code-mismatch.mjs
 *
 * 只读会话：注册两个身份（占用两个 4 位码），然后发一次 PATCH。
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { instantiateKernel } from '../src/crypto/wasm.js'
import { createClient } from '../src/net/client.js'
import { createApi } from '../src/net/api.js'
import { createIdentityManager } from '../src/store/identity.js'
import { memoryBackend } from '../src/store/db.js'
import { authHeaders, fields } from '../src/net/auth.js'

const here = dirname(fileURLToPath(import.meta.url))
const base = process.env.CORE_BASE || 'http://127.0.0.1:18080/v1'
const client = createClient({ baseUrl: base })
const kernelBytes = readFileSync(resolve(here, '../public/ys_kernel.wasm'))

async function peer(nick) {
  const kernel = await instantiateKernel(kernelBytes)
  const identity = createIdentityManager({ kernel, backend: memoryBackend() })
  await identity.loadOrCreate()
  const api = createApi({ client, kernel, session: identity.session })
  await identity.register({ api, nickname: nick })
  return { kernel, api, session: identity.session }
}

const alice = await peer('repro-a')
const bob = await peer('repro-b')

const { headers } = await authHeaders({
  client,
  kernel: alice.kernel,
  privateKey: alice.session.privateKey,
  code: alice.session.code,
  purpose: 'NICKNAME_UPDATE',
  fieldBytes: fields.NICKNAME_UPDATE({ code: alice.session.code, nickname: 'mismatch' }),
})

// 关键：签名覆盖的是 alice 的码，路径给 bob 的码
const res = await fetch(`${base}/codes/${bob.session.code}`, {
  method: 'PATCH',
  headers: { ...headers, 'Content-Type': 'application/json' },
  body: JSON.stringify({ nickname: 'mismatch' }),
})
const text = await res.text()
console.log(
  JSON.stringify(
    {
      base,
      headerCode: alice.session.code,
      pathCode: bob.session.code,
      http: res.status,
      body: text.trim(),
    },
    null,
    2,
  ),
)
