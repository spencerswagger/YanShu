/**
 * 前端日志（给"运行记录"面板用）。
 *
 * 纪律（REQUIREMENTS §7 / API.md §12）：日志里**不许**出现明文、文件名、密钥材料、签名原文、
 * prelude/块内容，也不许出现完整 URL 的查询串。这里只允许传字符串摘要，
 * 结构化字段白名单见 `safe()`。
 */

const MAX_ENTRIES = 200
const entries = []
const listeners = new Set()

const ALLOWED_KEYS = new Set(['code', 'status', 'ms', 'bytes', 'chunks', 'path', 'method', 'mode', 'retryAfter'])

function safe(fields = {}) {
  const out = {}
  for (const [k, v] of Object.entries(fields)) {
    if (!ALLOWED_KEYS.has(k)) continue
    if (v === undefined || v === null) continue
    out[k] = typeof v === 'number' || typeof v === 'boolean' ? v : String(v).slice(0, 64)
  }
  return out
}

export function log(level, message, fields) {
  const entry = { t: Date.now(), level, message: String(message).slice(0, 200), fields: safe(fields) }
  entries.push(entry)
  if (entries.length > MAX_ENTRIES) entries.shift()
  for (const fn of listeners) fn(entry)
  if (level === 'error') console.warn('[yanshu]', entry.message, entry.fields)
}

export const info = (m, f) => log('info', m, f)
export const warn = (m, f) => log('warn', m, f)
export const error = (m, f) => log('error', m, f)

export function entriesSnapshot() {
  return [...entries]
}

export function subscribe(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

export function clearLog() {
  entries.length = 0
}
