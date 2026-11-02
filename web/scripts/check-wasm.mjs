#!/usr/bin/env node
/**
 * 核验当前 `public/ys_kernel.wasm` 到底是不是契约布局，并逐项打印"四个布局特征"。
 *
 *   cd web && npm run wasm:check
 *
 * 与 `wasm:rebuild` 的区别：这个只**检查已有产物**（不重建），适合回答
 * "我手上这个 .wasm 是哪来的、符不符合契约"。
 */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const wasmPath = join(webDir, 'public/ys_kernel.wasm')
const metaPath = join(webDir, 'public/ys_kernel.build.json')

if (!existsSync(wasmPath)) {
  console.error('没有 public/ys_kernel.wasm；先 npm run wasm:rebuild')
  process.exit(2)
}

const bytes = readFileSync(wasmPath)
const module = new WebAssembly.Module(bytes)
const imports = WebAssembly.Module.imports(module)
const e = new WebAssembly.Instance(module, {}).exports
const fns = Object.keys(e).filter((k) => typeof e[k] === 'function')
const build = existsSync(metaPath) ? JSON.parse(readFileSync(metaPath, 'utf8')) : null

const mem = () => new Uint8Array(e.memory.buffer)
const write = (data) => {
  const p = e.ys_alloc(data.length)
  mem().set(data, p)
  return p
}
const read = (p, n) => mem().slice(p, p + n)
const hex = (b) => Buffer.from(b).toString('hex')
const seed = () => crypto.getRandomValues(new Uint8Array(32))

const facts = {}
facts.commit = build?.commit || '(无溯源文件)'
facts.sha256 = createHash('sha256').update(bytes).digest('hex')
facts.bytes = bytes.length
facts.imports = imports.length
facts.exports = fns.length
facts.ysVersion = `0x${e.ys_version().toString(16)}`
facts.headerLen = e.ys_header_len()

// —— 1) 公钥：内核出 64（X‖Y），wire 形态 65（0x04‖X‖Y）
const privA = e.ys_alloc(32)
const pubA = e.ys_alloc(64)
e.ys_sm2_keygen(write(seed()), 32, privA, pubA)
const privB = e.ys_alloc(32)
const pubB = e.ys_alloc(64)
e.ys_sm2_keygen(write(seed()), 32, privB, pubB)
const pubB64 = read(pubB, 64)
const pubB65 = new Uint8Array(65)
pubB65[0] = 0x04
pubB65.set(pubB64, 1)

// —— 2) 签名：必须是 DER（70..72）
const msg = new TextEncoder().encode('YSAUTH1-probe')
const der = (() => {
  if (typeof e.ys_sm2_sign_der === 'function') {
    const out = e.ys_alloc(128)
    const outLen = e.ys_alloc(4)
    const rc = e.ys_sm2_sign_der(privA, write(seed()), 32, write(msg), msg.length, out, 128, outLen)
    if (rc !== 0) throw new Error(`ys_sm2_sign_der rc=${rc}`)
    const n = new DataView(e.memory.buffer).getUint32(outLen, true)
    return read(out, n)
  }
  const sig = e.ys_alloc(64)
  if (e.ys_sm2_sign(privA, write(seed()), 32, write(msg), msg.length, sig) !== 0) throw new Error('sign failed')
  return read(sig, 64) // 裸 R‖S：说明不是契约的 DER 口径
})()

// —— 3) 打包 → 清单 JSON（sender_pub 应为 65 字节 hex、sender_code 4 位）
const data = new Uint8Array(500).map((_, i) => (i * 7) & 0xff)
const name = new TextEncoder().encode('probe.bin')
const mime = new TextEncoder().encode('application/octet-stream')
const ext = new TextEncoder().encode('bin')
const cap = data.length + 70000
const outPack = e.ys_alloc(cap)
const outLen = e.ys_alloc(4)
const packRc =
  typeof e.ys_pack_v1 === 'function'
    ? e.ys_pack_v1(
        write(pubB65), // 实测 _v1 要 65 字节；若内核改成 64 会返回 -19，下面会显式标注
        privA,
        write(name),
        name.length,
        write(mime),
        mime.length,
        write(ext),
        ext.length,
        BigInt(Date.now()),
        0,
        write(seed()),
        32,
        write(data),
        data.length,
        outPack,
        cap,
        outLen,
      )
    : e.ys_pack(write(pubB64), privA, write(name), name.length, write(mime), mime.length, 0, write(seed()), 32, write(data), data.length, outPack, cap, outLen)
const packLen = new DataView(e.memory.buffer).getUint32(outLen, true)
const pack = read(outPack, packLen)

const metaOut = e.ys_alloc(8192)
const metaLen = e.ys_alloc(4)
const metaRc =
  typeof e.ys_unpack_meta_v1 === 'function'
    ? e.ys_unpack_meta_v1(write(pack), pack.length, privB, metaOut, 8192, metaLen)
    : e.ys_unpack_meta(write(pack), pack.length, privB, 0, metaOut, 8192, metaLen)
const metaJson = metaRc === 0 ? JSON.parse(new TextDecoder().decode(read(metaOut, new DataView(e.memory.buffer).getUint32(metaLen, true)))) : null

// —— 4) 解包：6 参原型应"只给私钥"即可；7 参原型传 NULL 也应可用
const plainCap = data.length + 4096
const plainOut = e.ys_alloc(plainCap)
const plainLen = e.ys_alloc(4)
const unpackRc =
  typeof e.ys_unpack_v1 === 'function'
    ? e.ys_unpack_v1(write(pack), pack.length, privB, plainOut, plainCap, plainLen)
    : e.ys_unpack(write(pack), pack.length, privB, 0, plainOut, plainCap, plainLen)
const plain = unpackRc === 0 ? read(plainOut, new DataView(e.memory.buffer).getUint32(plainLen, true)) : null

// —— 5) 版本闸门：改 VERSION_MAJOR 必须拒绝（契约 §2.3 第四条）
let versionGate = false
try {
  const bad = new Uint8Array(pack)
  bad[4] = 0x02
  const out2 = e.ys_alloc(plainCap)
  const len2 = e.ys_alloc(4)
  const rc =
    typeof e.ys_unpack_v1 === 'function'
      ? e.ys_unpack_v1(write(bad), bad.length, privB, out2, plainCap, len2)
      : e.ys_unpack(write(bad), bad.length, privB, 0, out2, plainCap, len2)
  versionGate = rc === -5
} catch {
  versionGate = false
}

const signals = {
  versionGate,
  header112: facts.headerLen === 112,
  version1: facts.ysVersion === '0x10000',
  senderPub65: Boolean(metaJson && /^04[0-9a-f]{128}$/.test(metaJson.sender_pub || '')),
  senderCode4: Boolean(metaJson && /^[0-9A-HJKMNP-TV-Z]{4}$/.test(metaJson.sender_code || '')),
  signatureDer: der.length >= 70 && der.length <= 72 && der[0] === 0x30,
  unpackNoSenderKey: unpackRc === 0 && typeof e.ys_unpack_v1 === 'function' && e.ys_unpack_v1.length === 6,
  packV1: typeof e.ys_pack_v1 === 'function',
  zeroImport: imports.length === 0,
}

console.log('产物：')
console.log(JSON.stringify({ ...facts, packRc, metaRc, unpackRc, signatureBytes: der.length }, null, 2))
console.log('\n四个布局特征：')
console.log(
  JSON.stringify(
    {
      'HEADER=112': signals.header112,
      '公钥 65 字节含 0x04（清单 sender_pub）': signals.senderPub65,
      'DER 签名 70..72': signals.signatureDer,
      '解包不再需要发送方公钥（6 参 _v1）': signals.unpackNoSenderKey,
      '清单带 4 位 sender_code': signals.senderCode4,
      '版本闸门（改版本字节必拒）': signals.versionGate,
      'ys_pack_v1 存在': signals.packV1,
      '0 import': signals.zeroImport,
    },
    null,
    2,
  ),
)

const failed = Object.entries(signals).filter(([, ok]) => !ok).map(([k]) => k)
if (failed.length) {
  console.error('\n不符合契约布局：' + failed.join(', '))
  process.exit(1)
}
if (plain && Buffer.compare(Buffer.from(plain), Buffer.from(data)) !== 0) {
  console.error('\n解包明文与原文不一致')
  process.exit(1)
}
console.log('\n结论：当前产物是契约布局（YSPK/1.0），且只给收件人私钥即可解包。')
