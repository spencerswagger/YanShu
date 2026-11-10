/**
 * 端侧内核产物的**版本绑定**工具（ensure-wasm / sync-wasm / 回归测试共用）。
 *
 * 背景：WASM 是 sm2/sm3/sm4 内核，产物与 `public/ys_kernel.build.json`（溯源）必须**强绑定**。
 * 以前 `ensure-wasm` 在「产物在、溯源缺」时会从构建缓存拷回**另一个版本**并当作成功——
 * 等于静默换掉加密实现。这里把判定收敛成纯函数，任何不一致都报错，绝不"顺手换成缓存里的另一版"。
 */
import { createHash } from 'node:crypto'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'

export const WASM_NAME = 'ys_kernel.wasm'
export const META_NAME = 'ys_kernel.build.json'

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

export function describe(path) {
  if (!existsSync(path)) return { path, exists: false }
  const st = statSync(path)
  return { path, exists: true, bytes: st.size, sha256: sha256File(path) }
}

/**
 * 校验「产物 ↔ 溯源」是否绑定。
 * 返回 `{ ok:true, sha, bytes, meta }` 或 `{ ok:false, code, … }`（附两边的大小/摘要，便于人工比对）。
 */
export function verifyArtifact({ wasmPath, metaPath }) {
  if (!existsSync(wasmPath)) return { ok: false, code: 'NO_WASM', wasm: describe(wasmPath) }
  if (!existsSync(metaPath)) {
    return { ok: false, code: 'NO_META', wasm: describe(wasmPath), meta: { path: metaPath, exists: false } }
  }
  let meta
  try {
    meta = JSON.parse(readFileSync(metaPath, 'utf8'))
  } catch (err) {
    return { ok: false, code: 'BAD_META', detail: err.message, wasm: describe(wasmPath) }
  }
  const wasm = describe(wasmPath)
  if (!meta.sha256) return { ok: false, code: 'META_NO_SHA', wasm, meta }
  if (String(meta.sha256).toLowerCase() !== wasm.sha256) {
    return { ok: false, code: 'SHA_MISMATCH', wasm, metaSha: meta.sha256, metaBytes: meta.bytes }
  }
  if (meta.bytes && Number(meta.bytes) !== wasm.bytes) {
    return { ok: false, code: 'BYTES_MISMATCH', wasm, metaSha: meta.sha256, metaBytes: meta.bytes }
  }
  return { ok: true, sha: wasm.sha256, bytes: wasm.bytes, meta }
}

/** 原子写：先写临时文件再 rename，避免被读到半截（Gate 的 helpers 已按容忍半截处理，但根因在这里） */
export function atomicCopyFile(from, to) {
  mkdirSync(dirname(to), { recursive: true })
  const tmp = join(dirname(to), `.${basename(to)}.tmp-${process.pid}-${Date.now()}`)
  try {
    copyFileSync(from, tmp)
    renameSync(tmp, to)
  } catch (err) {
    try {
      if (existsSync(tmp)) unlinkSync(tmp)
    } catch {
      /* 清理失败不掩盖原始错误 */
    }
    throw err
  }
}

/** 原子写 JSON（先写临时文件再 rename），避免测试读到半截溯源 */
export function atomicWriteJson(path, value) {
  mkdirSync(dirname(path), { recursive: true })
  const tmp = join(dirname(path), `.${basename(path)}.tmp-${process.pid}-${Date.now()}`)
  try {
    writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n')
    renameSync(tmp, path)
  } catch (err) {
    try {
      if (existsSync(tmp)) unlinkSync(tmp)
    } catch {
      /* 清理失败不掩盖原始错误 */
    }
    throw err
  }
}

/**
 * 实例化产物并读出**产物自身能证明的事实**（版本 / 包头 / 导出 / 是否 0 import）。
 *
 * 用途：`wasm:sync --commit` 写溯源时，sha256/bytes/版本/头长都从字节现算，
 * 只有 commit 是调用方声明的（跟 Dockerfile 的 `YS_KERNEL_COMMIT` 同口径）——
 * 绝不凭记忆写死"另一个版本"的字段。不是合法 wasm 时抛错，由调用方决定退出码。
 */
export function probeKernel(bytes) {
  const module = new WebAssembly.Module(bytes)
  const imports = WebAssembly.Module.imports(module).length
  if (imports !== 0) {
    // 0 import 是内核的硬约定（wazero / 浏览器两边都必须能空导入实例化），这里先拒，别等到实例化报无意义的错
    throw new Error(`产物有 ${imports} 个 import（应为 0）`)
  }
  const e = new WebAssembly.Instance(module, {}).exports
  const fns = Object.keys(e).filter((k) => typeof e[k] === 'function')
  if (typeof e.ys_version !== 'function') {
    throw new Error('产物没有 ys_version 导出（不是雁书端侧内核）')
  }
  return {
    imports,
    exports: fns.length,
    hasMemory: !!e.memory,
    ysVersion: `0x${(e.ys_version() >>> 0).toString(16)}`,
    headerLen: typeof e.ys_header_len === 'function' ? e.ys_header_len() : null,
    unpackV1Arity: typeof e.ys_unpack_v1 === 'function' ? e.ys_unpack_v1.length : null,
    hasSignDer: typeof e.ys_sm2_sign_der === 'function',
    hasPackV1: typeof e.ys_pack_v1 === 'function',
  }
}

/** 从候选路径里挑出与期望摘要一致的那个（没有期望摘要时返回 null，绝不自作主张） */
export function pickMatchingCandidate(candidates, expectSha) {
  const want = String(expectSha || '').toLowerCase()
  if (!want) return { hit: null, scanned: candidates.map(describe) }
  const scanned = []
  for (const p of candidates) {
    const d = describe(p)
    scanned.push(d)
    if (d.exists && d.sha256 === want) return { hit: d, scanned }
  }
  return { hit: null, scanned }
}

/** 人类可读的候选列表（路径 / 大小 / 摘要前 12 位） */
export function formatScanned(scanned) {
  if (!scanned.length) return '  （没有候选路径）'
  return scanned
    .map((d) =>
      d.exists
        ? `  ${d.path}  ${d.bytes} B  ${d.sha256.slice(0, 12)}…`
        : `  ${d.path}  （不存在）`,
    )
    .join('\n')
}
