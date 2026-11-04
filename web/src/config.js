/**
 * 运行时配置。
 *
 * 只从构建期环境变量读，不落任何密钥/凭据。
 * 环境变量（Vite 前缀 VITE_）：
 *   VITE_YS_API_BASE  中转 API 基址，默认 `/v1`（dev 由 vite 反代到本地中转）
 *   VITE_YS_WASM_URL  端侧内核 wasm 地址，默认 `/ys_kernel.wasm`
 *   VITE_YS_CRYPTO    auto | wasm | stub-fake  （auto：有 wasm 就用，没有就报"未就绪"）
 */
const env = (import.meta && import.meta.env) || {}

export const config = {
  /** 中转 API 基址，末尾不带斜杠 */
  apiBase: (env.VITE_YS_API_BASE || '/v1').replace(/\/+$/, ''),

  /** 端侧内核 wasm 产物地址（Rune 产出，未到位时保持默认即可） */
  wasmUrl: env.VITE_YS_WASM_URL || '/ys_kernel.wasm',

  /**
   * 加密内核选择。
   * auto      —— 能加载 wasm 就用真内核；加载不到就把错误如实抛给 UI（绝不静默降级成假加密）
   * wasm      —— 强制真内核，加载失败即失败
   * stub-fake —— 开发桩：明文字节走"可逆异或"只为打通 UI/传输流程，**不是加密**；
   *              生产构建里被强制拒绝（见 crypto/index.js）
   */
  cryptoMode: env.VITE_YS_CRYPTO || 'auto',

  /** 生产构建标记：桩在生产里一律拒绝启用 */
  isProd: Boolean(env.PROD),

  /** 超过这个大小就走内核流式接口（常量内存）；小文件仍走整包，路径更短 */
  streamThresholdBytes: 8 * 1024 * 1024,

  /** 默认块大小（契约 §14：生产默认 1 MiB，读方以包内头为准） */
  chunkSize: 1048576,

  /** 上传并发块数（块小、失败重试按块，取 3 兼顾手机与 600 次/分钟限速） */
  uploadConcurrency: 3,

  /** 默认 TTL 与下载次数（服务端会夹到 [3600,86400] / [1,3]） */
  defaultTtlSeconds: 86400,
  defaultMaxDownloads: 1,

  /** 429 / 5xx 退避序列（团队统一：5s→20s→60s，最多 3 次） */
  backoffMs: [5000, 20000, 60000],

  /** 单文件上限（与服务端 /v1/config 的 max_plaintext_size 对齐，取回后以服务端值覆盖） */
  maxPlaintextSize: 4294967296,

  /**
   * 端侧内核当前是**整包**接口（ys_pack 一次吃整份明文），所以要给内存留上限：
   * 明文 + 密文包同时在内存里，取 64 MiB 作为可用上限；超过提示等流式接口（Ark 已排期）。
   */
  /** 整包接口（无流式内核时）的硬上限 */
  maxPackSize: 64 * 1024 * 1024,

  /** 刷新后续传要用：把 ≤8 MiB 的密文包留在本机 IndexedDB（更大就只能在当前页面内续传） */
  maxPersistPack: 8 * 1024 * 1024,

  /** 撞码自动重生成密钥对的次数（任务口径：自动重试一次，之后由用户手动点） */
  autoCodeRetries: 1,
}
