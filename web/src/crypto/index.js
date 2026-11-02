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

export { CryptoError }
