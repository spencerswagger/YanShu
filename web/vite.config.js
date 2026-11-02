import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

/**
 * 严格 CSP（只在生产构建注入；dev 下 Vite HMR 需要 inline + ws，注入会自断热更新）。
 *
 * 约束来源：REQUIREMENTS §7 纪律「前端零第三方脚本 + 严格 CSP」。
 * - script-src 'self'：禁止任何外链脚本 / inline 脚本（Vue 运行时已打进 bundle，无 eval）。
 * - connect-src 里额外放开中转地址：构建时用 VITE_YS_API_BASE 指定的远端时，需要显式加白。
 */
function strictCsp() {
  const apiBase = process.env.VITE_YS_API_BASE || ''
  let connect = "'self'"
  if (apiBase.startsWith('http')) {
    const origin = new URL(apiBase).origin
    connect += ` ${origin}`
  }
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    `connect-src ${connect}`,
    "img-src 'self' data:",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ')

  return {
    name: 'yanshu-strict-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<meta charset="UTF-8" />',
        `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      )
    },
  }
}

export default defineConfig({
  plugins: [vue(), strictCsp()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      // dev 下把 /v1 反代到本地中转，避免 CORS 与 CSP 折腾
      '/v1': {
        target: process.env.VITE_YS_RELAY_ORIGIN || 'http://127.0.0.1:8787',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    target: 'es2020',
  },
})
