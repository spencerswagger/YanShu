#!/usr/bin/env node
/**
 * 核验当前 `public/ys_kernel.wasm` 是不是契约布局，并逐项打印判据。
 *
 *   cd web && npm run wasm:check
 *
 * 与 `wasm:rebuild` 的区别：这个只**检查已有产物**（不重建）。
 * 判据取 `CRYPTO-PACK §2.3` 四条 + 公钥/签名/清单形态，全部真跑，不靠"不是桩"推断。
 */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { V1_SAMPLE_HEX, V1_RECIPIENT_PRIVATE_HEX, V1_EXPECTED } from '../src/crypto/fixtures.js'

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const wasmPath = join(webDir, 'public/ys_kernel.wasm')
const metaPath = join(webDir, 'public/ys_kernel.build.json')

if (!existsSync(wasmPath)) {
  console.error('没有 public/ys_kernel.wasm；先 npm run wasm:rebuild')
  process.exit(2)
}

const bytes = readFileSync(wasmPath)
const module = new WebAssembly.Module(bytes)
const imports = WebAssembly.Module.imports(module).length
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
const u32 = (p) => new DataView(e.memory.buffer).getUint32(p, true)
const seed = () => crypto.getRandomValues(new Uint8Array(32))

const facts = {
  commit: build?.commit || '(无溯源文件)',
  sha256: createHash('sha256').update(bytes).digest('hex'),
  bytes: bytes.length,
  imports,
  exports: fns.length,
  ysVersion: `0x${e.ys_version().toString(16)}`,
  headerLen: e.ys_header_len(),
}

// —— 密钥对与两种公钥形态
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

// —— 1) DER 签名（严格 DER 下 r/s 前导零会短到 68）
let der = null
if (typeof e.ys_sm2_sign_der === 'function') {
  const out = e.ys_alloc(128)
  const outLen = e.ys_alloc(4)
  const msg = write(new TextEncoder().encode('YSAUTH1-probe'))
  const rc = e.ys_sm2_sign_der(privA, write(seed()), 32, msg, 14, out, 128, outLen)
  if (rc === 0) der = read(out, u32(outLen))
}

// —— 2) 打包：`ys_pack_v1` 在不同轮次要过 65 / 64 两种公钥形态，两种都试
const data = new Uint8Array(500).map((_, i) => (i * 7) & 0xff)
const name = new TextEncoder().encode('probe.bin')
const mime = new TextEncoder().encode('application/octet-stream')
const ext = new TextEncoder().encode('bin')
const cap = data.length + 70000

function packOnce(keyBytes) {
  const out = e.ys_alloc(cap)
  const outLen = e.ys_alloc(4)
  const rc = e.ys_pack_v1(
    write(keyBytes),
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
    out,
    cap,
    outLen,
  )
  return { rc, out, len: u32(outLen) }
}

let packRc
let packKeyForm = 'n/a'
let pack = null
if (typeof e.ys_pack_v1 === 'function') {
  let r = packOnce(pubB65)
  packKeyForm = '65'
  if (r.rc !== 0) {
    r = packOnce(pubB64)
    packKeyForm = '64'
  }
  packRc = r.rc
  if (r.rc === 0) pack = read(r.out, r.len)
} else {
  const out = e.ys_alloc(cap)
  const outLen = e.ys_alloc(4)
  packRc = e.ys_pack(
    write(pubB64),
    privA,
    write(name),
    name.length,
    write(mime),
    mime.length,
    0,
    write(seed()),
    32,
    write(data),
    data.length,
    out,
    cap,
    outLen,
  )
  packKeyForm = '64(ys_pack)'
  if (packRc === 0) pack = read(out, u32(outLen))
}

// —— 3) 清单（6 参自证优先；否则 7 参传 0）
const selfMeta = ['ys_unpack_meta_v2', 'ys_unpack_meta_v1'].find((n) => typeof e[n] === 'function' && e[n].length === 6)
const selfUnpack = ['ys_unpack_v2', 'ys_unpack_v1'].find((n) => typeof e[n] === 'function' && e[n].length === 6)
let metaRc = -99
let metaJson = null
if (pack) {
  const out = e.ys_alloc(8192)
  const outLen = e.ys_alloc(4)
  const p = write(pack)
  metaRc = selfMeta
    ? e[selfMeta](p, pack.length, privB, out, 8192, outLen)
    : e.ys_unpack_meta(p, pack.length, privB, 0, out, 8192, outLen)
  if (metaRc === 0) metaJson = JSON.parse(new TextDecoder().decode(read(out, u32(outLen))))
}

// —— 4) 解包（只给收件人私钥）
let unpackRc = -99
let plain = null
if (pack) {
  const out = e.ys_alloc(data.length + 4096)
  const outLen = e.ys_alloc(4)
  const p = write(pack)
  unpackRc = selfUnpack
    ? e[selfUnpack](p, pack.length, privB, out, data.length + 4096, outLen)
    : e.ys_unpack(p, pack.length, privB, 0, out, data.length + 4096, outLen)
  if (unpackRc === 0) plain = read(out, u32(outLen))
}

// —— 5) 版本闸门：改 VERSION_MAJOR 必须报 -5
let versionGate = false
if (pack && selfUnpack) {
  const bad = new Uint8Array(pack)
  bad[4] = 0x02
  const out = e.ys_alloc(data.length + 4096)
  const outLen = e.ys_alloc(4)
  versionGate = e[selfUnpack](write(bad), bad.length, privB, out, data.length + 4096, outLen) === -5
}

// —— 6) 契约 §15 的 V1 样例：真解一次 + 改版本字节必须被拒（§2.3 第 3、4 条）
let v1Sample = false
let v1VersionGate = false
try {
  const sample = Uint8Array.from(Buffer.from(V1_SAMPLE_HEX, 'hex'))
  const priv = Uint8Array.from(Buffer.from(V1_RECIPIENT_PRIVATE_HEX, 'hex'))
  const out = e.ys_alloc(8192)
  const outLen = e.ys_alloc(4)
  const p = write(sample)
  const privPtr = write(priv)
  const meta =
    selfMeta && e[selfMeta](p, sample.length, privPtr, out, 8192, outLen) === 0
      ? JSON.parse(new TextDecoder().decode(read(out, u32(outLen))))
      : null
  const plainOut = e.ys_alloc(64)
  const plainLen = e.ys_alloc(4)
  const pr = selfUnpack ? e[selfUnpack](p, sample.length, privPtr, plainOut, 64, plainLen) : -99
  const plainHex = pr === 0 ? Buffer.from(read(plainOut, u32(plainLen))).toString('hex') : ''
  v1Sample = Boolean(meta && meta.name === V1_EXPECTED.name && meta.mime === V1_EXPECTED.mime && plainHex === V1_EXPECTED.plaintextHex)

  const bad = new Uint8Array(sample)
  bad[4] = 0x02
  const out2 = e.ys_alloc(64)
  const len2 = e.ys_alloc(4)
  const rc = selfUnpack ? e[selfUnpack](write(bad), bad.length, privPtr, out2, 64, len2) : -99
  v1VersionGate = rc === -5
} catch (err) {
  v1Sample = false
  v1VersionGate = false
}

// —— 7) 码派生：契约 §15.1 的 PB_S → AWQW（wasm 与原生必须逐字符一致）
const PB_S_HEX =
  '04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d'
const pbS64 = Uint8Array.from(Buffer.from(PB_S_HEX.slice(2), 'hex'))
const codeOut = e.ys_alloc(4)
const codeRc = e.ys_user_code(write(pbS64), codeOut)
const codeString = codeRc === 0 ? Buffer.from(read(codeOut, 4)).toString('ascii') : ''
// 反面：误传 65 字节（含 0x04）会得到另一个码 —— 这正是"wasm 算出别的码"的常见根因
const code65Out = e.ys_alloc(4)
const code65Rc = e.ys_user_code(write(Uint8Array.from(Buffer.from(PB_S_HEX, 'hex'))), code65Out)
const code65String = code65Rc === 0 ? Buffer.from(read(code65Out, 4)).toString('ascii') : ''

const signals = {
  '码派生 PB_S → AWQW（64 字节入参）': codeString === 'AWQW',
  'V1 样例包解包成功（§2.3 第 3 条）': v1Sample,
  'V1 样例改版本字节必拒（§2.3 第 4 条）': v1VersionGate,
  'HEADER=112': facts.headerLen === 112,
  '版本 0x10000': facts.ysVersion === '0x10000',
  '清单 sender_pub 为 65 字节含 0x04': Boolean(metaJson && /^04[0-9a-f]{128}$/.test(metaJson.sender_pub || '')),
  '清单带 4 位 sender_code': Boolean(metaJson && /^[0-9A-HJKMNP-TV-Z]{4}$/.test(metaJson.sender_code || '')),
  'DER 签名 68..72': Boolean(der && der.length >= 68 && der.length <= 72 && der[0] === 0x30),
  '解包不需要发送方公钥（6 参自证）': Boolean(selfUnpack) && unpackRc === 0,
  '版本闸门（改版本字节必拒 -5）': versionGate,
  '打包成功': packRc === 0,
  '0 import': imports === 0,
}

console.log('产物：')
console.log(
  JSON.stringify(
    { ...facts, packRc, packKeyForm, metaRc, unpackRc, signatureBytes: der?.length ?? null, codeString, code65String },
    null,
    2,
  ),
)
console.log('\n判据：')
console.log(JSON.stringify(signals, null, 2))

const failed = Object.entries(signals).filter(([, ok]) => !ok).map(([k]) => k)
if (failed.length) {
  console.error('\n不符合契约布局：' + failed.join('、'))
  process.exit(1)
}
if (!plain || Buffer.compare(Buffer.from(plain), Buffer.from(data)) !== 0) {
  console.error('\n解包明文与原文不一致')
  process.exit(1)
}
console.log(`\n结论：契约布局（YSPK/1.0），6 参自证解包 = ${selfUnpack}，只给收件人私钥即可解包，明文逐字节一致。`)
