/**
 * 本机身份（SM2 密钥对 + 4 位码）。
 *
 * 红线（REQUIREMENTS §2 / API.md §0.3）：
 * - **私钥只在本机**：只写 IndexedDB，不上传、不备份、不导出、不进日志；
 * - 上 wire 的只有 `public_key`（65 字节未压缩点，base64url）；
 * - 清缓存 = 换人：这是产品定位（一次性传输）决定的可接受后果。
 *
 * 撞码（API.md §4.3）：服务端回 `409 CODE_TAKEN` 时**丢弃当前密钥对、重新生成**，
 * 自动重试一次（任务口径），之后由用户手动点"再试一次"；总次数受 §4.3 的 8 次上限保护。
 * 绝不自动加长码、绝不复用别人的码。
 */
import { config } from '../config.js'
import { encode as b64uEncode, decode as b64uDecode } from '../lib/base64url.js'
import { info, warn } from '../lib/log.js'

const KEY = 'self'

function defaultNickname(code) {
  return `雁${code}`
}

export function createIdentityManager({ kernel, backend, onCreate }) {
  /** 会话对象是**活的**：撞码重生成时原地替换，api/UI 都持同一引用。 */
  const session = {
    identity: null,
    publicKey: null,
    code: null,
    check: null,
    nickname: '',
    registered: false,
    createdAt: null,
  }

  function adopt(record) {
    session.identity = b64uDecode(record.identity)
    session.publicKey = b64uDecode(record.publicKey)
    session.code = record.code
    session.check = record.check
    session.nickname = record.nickname || defaultNickname(record.code)
    session.registered = Boolean(record.registered)
    session.createdAt = record.createdAt || Date.now()
  }

  async function persist() {
    await backend.put(KEY, {
      identity: b64uEncode(session.identity), // 私钥，仅本机
      publicKey: b64uEncode(session.publicKey),
      code: session.code,
      check: session.check,
      nickname: session.nickname,
      registered: session.registered,
      createdAt: session.createdAt,
    })
  }

  async function generate() {
    const blob = kernel.generateIdentity()
    const publicKey = kernel.identityPublic(blob)
    const { code, check } = kernel.identityCode(blob)
    session.identity = blob
    session.publicKey = publicKey
    session.code = code
    session.check = check
    session.nickname = session.nickname || defaultNickname(code)
    session.registered = false
    session.createdAt = Date.now()
    await persist()
    info('已生成密钥对与本机码', { code })
    onCreate?.({ ...session })
  }

  /** 首次进入或本地无身份时调用。 */
  async function loadOrCreate() {
    const record = await backend.get(KEY)
    if (record) {
      adopt(record)
      info('载入本机身份', { code: session.code })
      return session
    }
    await generate()
    return session
  }

  /** 丢弃当前密钥对，重新生成（撞码 / 本地状态异常时用）。 */
  async function rotate() {
    warn('丢弃当前密钥对并重新生成', { code: session.code })
    session.nickname = ''
    await generate()
    session.nickname = defaultNickname(session.code)
    await persist()
    return session
  }

  async function setNickname(nickname) {
    session.nickname = nickname
    await persist()
  }

  /**
   * 注册到中转（写操作走签名挑战）。
   * @returns {Promise<{ok:true, response:object, collisions:number}>}
   */
  async function register({ api, nickname, autoRetries = config.autoCodeRetries, maxAttempts = 8 } = {}) {
    let collisions = 0
    const wanted = nickname || session.nickname || defaultNickname(session.code)
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const response = await api.register({ nickname: wanted })
        session.nickname = response?.nickname || wanted
        session.registered = true
        await persist()
        info('注册成功', { code: session.code })
        return { ok: true, response, collisions }
      } catch (err) {
        if (err.code === 'CODE_TAKEN' && collisions < autoRetries) {
          collisions += 1
          warn('码被占用，自动换密钥对重试一次', { code: session.code })
          await rotate()
          continue
        }
        if (err.code === 'PUBKEY_TAKEN') {
          warn('公钥已在别的码下注册，清本地身份重来', { code: session.code })
          await rotate()
          continue
        }
        throw err
      }
    }
    const err = new Error('注册重试次数用尽')
    err.code = 'CODE_TAKEN'
    err.collisions = collisions
    throw err
  }

  return { session, loadOrCreate, generate, rotate, register, setNickname, persist }
}
