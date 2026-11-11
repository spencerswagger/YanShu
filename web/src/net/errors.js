/**
 * 错误 → 用户文案（唯一映射表，UI 只读这里）。
 *
 * 规则：
 * - HTTP 侧按 `error.code` 分支（API.md §0.2：不得匹配 message）；
 * - 三种终结态（撤回 / 过期 / 已取走）文案与动作固定（API.md §5.3）；
 * - 端侧 `CRYPTO_*` 走 crypto/errors.js，不上行、不混用命名空间。
 */
import { ApiError } from './client.js'
import { isCryptoError, cryptoMessage } from '../crypto/errors.js'

const TERMINAL = {
  TRANSFER_REVOKED: { title: '对方已撤回', hint: '停止重试，清理本地半成品。', action: 'clear' },
  TRANSFER_EXPIRED: { title: '已过期', hint: '对方未在有效期内取走，可以让对方重发。', action: 'clear' },
  TRANSFER_CONSUMED: { title: '已被取走', hint: '这条传输已经用掉了（一次性）。', action: 'clear' },
}

const HTTP = {
  RATE_LIMITED: { title: '操作太频繁', hint: '已按服务端要求等待，可稍后重试。', retry: true },
  CODE_NOT_FOUND: { title: '码不对', hint: '这个码没注册，或对方换了浏览器（清缓存等于换人）。' },
  CODE_LOCKED: { title: '查询失败次数过多', hint: '等锁定时间过去再试，别连续试。', retry: true },
  CODE_TAKEN: { title: '码被占用', hint: '已重新生成密钥对重试一次；仍冲突请点"再试一次"。' },
  PUBKEY_TAKEN: { title: '本机身份与服务端不一致', hint: '可清除本地身份后重新生成。' },
  TRANSFER_NOT_FOUND: { title: '传输不存在', hint: '可能已被清理，从列表移除即可。', action: 'clear' },
  TRANSFER_NOT_READY: { title: '对方还没传完', hint: '等对方完成上传后再取。', retry: true },
  PRELUDE_CONFLICT: { title: '包已定稿，不能改', hint: '签名已绑定 prelude；这条传输只能重发。' },
  CHUNK_CONFLICT: { title: '块内容冲突', hint: '同一块序号已有不同内容，停止重传并核对传输 id。' },
  DOWNLOAD_NOT_STARTED: { title: '下载流程没开始', hint: '先取 prelude 再取块。' },
  TRANSFER_STATE_CONFLICT: { title: '状态不允许这个操作', hint: '刷新状态后再试，别硬来。' },
  SIZE_LIMIT_EXCEEDED: { title: '文件太大', hint: '声明值超过上限（明文 4 GiB / 块数 1048576 / prelude 4 MiB），请拆分文件。' },
  INSUFFICIENT_STORAGE: { title: '服务器配额不足', hint: '存储/配额类错误（不是限速），稍后再来，别按 Retry-After 循环重试。' },
  PAYLOAD_TOO_LARGE: { title: '单个请求体太大', hint: '减小切片后重传该块。' },
  SERVICE_UNAVAILABLE: { title: '服务暂时不可用', hint: '已按退避重试，稍后再说。', retry: true },
  INTERNAL: { title: '服务端内部错误', hint: '已按 5s→20s→60s 退避重试过。', retry: true },
  // 路由级（§0.2 / ADR-0003）：路径或方法不在服务端接口表里 = 前后端版本没对齐，用户只需刷新
  ROUTE_NOT_FOUND: { title: '页面版本不一致', hint: '这个地址服务端不认识，刷新页面后再试。' },
  METHOD_NOT_ALLOWED: { title: '页面版本不一致', hint: '这个操作服务端不支持，刷新页面后再试。' },
  AUTH_MISSING: { title: '缺少鉴权头', hint: '内部错误，刷新页面重试。' },
  AUTH_SIGNATURE_INVALID: { title: '签名不被接受', hint: '挑战可能已作废，重新发起一次。', retry: true },
  AUTH_CODE_MISMATCH: { title: '码与签名不一致', hint: '内部状态异常：用同一个码重算签名后再试。' },
  AUTH_CHALLENGE_INVALID: { title: '挑战过期或已用', hint: '重新申请挑战后再试一次。', retry: true },
  NETWORK_ERROR: { title: '网络不可达', hint: '检查网络后重试。', retry: true },
  FILE_TOO_LARGE: { title: '文件太大', hint: '端侧内核当前是整包接口，请等流式接口（已排期）或先拆分文件。' },
  RESUME_UNAVAILABLE: { title: '无法续传', hint: '本机没有保留密文包（超过 8 MiB 或已清理），请重新发送。' },
  // 落盘（前端本地，不是服务端错误）：大文件必须流式写盘，不能整包进内存
  SAVE_MEMORY_LIMIT: { title: '文件太大，浏览器不能整包保存', hint: '请用 Chrome/Edge 打开，或让对方拆分后再发。' },
  SAVE_UNSUPPORTED_LARGE: { title: '这个浏览器不能流式落盘', hint: '请用 Chrome/Edge 打开；文件已留在服务端，可以稍后重试。' },
  SAVE_PICKER_UNAVAILABLE: { title: '未使用「选择保存位置」', hint: '已改走浏览器内部暂存，收完会自动下载。' },
}

export function describeError(err) {
  if (!err) return { title: '未知错误', hint: '', retry: false, terminal: false }
  if (isCryptoError(err)) {
    return { title: cryptoMessage(err), hint: '端侧错误，不会上传服务端。', retry: false, terminal: false, crypto: true }
  }
  if (err.name === 'AbortError') {
    return { title: '已取消', hint: '', retry: false, terminal: false }
  }
  if (err instanceof ApiError || err.code) {
    const code = err.code
    if (TERMINAL[code]) return { ...TERMINAL[code], terminal: true }
    if (HTTP[code]) {
      const entry = HTTP[code]
      const wait = err.retryAfter ? `（约 ${err.retryAfter} 秒后可重试）` : ''
      return { ...entry, hint: entry.hint + wait, terminal: false }
    }
    return { title: `请求失败（${code}）`, hint: err.message || '', retry: Boolean(err.retryable), terminal: false }
  }
  return { title: err.message || '操作失败', hint: '', retry: false, terminal: false }
}
