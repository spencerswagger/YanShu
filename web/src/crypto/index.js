/**
 * 端侧内核门面：决定用真 WASM、还是"未就绪"替身，并把桩挡在生产之外。
 *
 * 规则（别为了跑通而放松）：
 * 1. `auto`（默认）：能加载 wasm 就用真内核；加载失败 → `UnavailableKernel`，
 *    所有加密操作报 `CRYPTO_NOT_READY`，UI 只能显示"内核未就绪"，**不允许**降级成假加密。
 * 2. `wasm`：强制真内核，失败即失败（联调用）。
 * 3. `stub-fake`：只在非生产构建允许；生产构建直接抛错。
 *
 * `kernel.isRealCrypto` 让 UI/日志如实标注当前是否真加密。
 */
import { config } from '../config.js'
import { loadKernelWasm, instantiateKernel } from './wasm.js'
import { UnavailableKernel, DevStubKernel } from './stub.js'
import { CryptoError } from './errors.js'

let pending = null

export function createKernel(options = {}) {
  if (pending) return pending
  pending = boot(options).catch((err) => {
    pending = null
    throw err
  })
  return pending
}

/** 测试用：清掉已缓存的实例。 */
export function resetKernel() {
  pending = null
}

async function boot({ mode = config.cryptoMode, wasmUrl = config.wasmUrl, isProd = config.isProd, wasmBytes } = {}) {
  if (mode === 'stub-fake') {
    if (isProd) {
      throw new CryptoError('CRYPTO_ABI_MISMATCH', '生产构建禁止开发桩（stub-fake）：桩不提供任何加密')
    }
    return new DevStubKernel()
  }

  if (mode === 'wasm' || mode === 'auto') {
    try {
      if (wasmBytes) return await instantiateKernel(wasmBytes)
      return await loadKernelWasm(wasmUrl)
    } catch (err) {
      if (mode === 'wasm') throw err
      return new UnavailableKernel(err.message)
    }
  }

  return new UnavailableKernel(`未知的加密内核模式：${mode}`)
}

/**
 * 标签判定的**唯一位置**（薄函数）：UI 只读这里的结果，不自己推断。
 *
 * 依据是 `kernel.selfTest()` 的真跑结果（CRYPTO-PACK §2.3 四条：版本 / HEADER 112 /
 * 打包解包往返 / 改版本字节必报 CRYPTO_VERSION_UNSUPPORTED）。
 * 注意：内核没有 `ys_layout_of()` / `ys_get_layout()` 这类"自报布局"的导出，别照不存在的符号写。
 */
export function describeKernel(kernel, selfTest) {
  if (!kernel || kernel.mode === 'unavailable') {
    return { mode: 'unavailable', label: '内核未就绪', contractOk: false, failed: [], note: kernel?.reason || '' }
  }
  if (kernel.mode === 'stub-fake') {
    return { mode: 'stub-fake', label: '开发桩（未加密）', contractOk: false, failed: ['stub'], note: '' }
  }
  const result = selfTest || kernel.selfTestResult || null
  const failed = result ? Object.entries(result.checks).filter(([, ok]) => !ok).map(([k]) => k) : ['selfTest']
  const contractOk = Boolean(result?.ok)
  return {
    mode: contractOk ? 'wasm' : 'wasm-noncontract',
    label: contractOk ? '真实加密 · 契约布局内核（YSPK/1.0）' : '真实加密 · 非契约布局内核（待对齐）',
    contractOk,
    failed,
    note: contractOk ? '' : `未通过：${failed.join('、')}`,
  }
}

export { CryptoError }
