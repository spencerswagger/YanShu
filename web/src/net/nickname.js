/**
 * 昵称更新：`POST /v1/challenges(NICKNAME_UPDATE)` → 端侧签名 → `PATCH /v1/codes/{code}`。
 *
 * 为什么单独抽一层：这段有"挑战过期自动重取一次"的分支，写在组件里没法测；
 * 抽成纯函数后可以用假 api 精确验证三条路径（成功 / 过期重试一次 / 连续过期失败）。
 */
export const NICK_MAX = 16

export class NicknameError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'NicknameError'
    this.code = code
  }
}

/**
 * @param {object} p
 * @param {{patchNickname: Function}} p.api
 * @param {{session: {code: string}, setNickname?: Function}} p.identity
 * @param {string} p.nickname
 * @returns {Promise<{retried: boolean, nickname: string, response: object}>}
 */
export async function updateNickname({ api, identity, nickname }) {
  const value = String(nickname ?? '').trim()
  const len = [...value].length
  if (!len) throw new NicknameError('NICKNAME_EMPTY', '昵称不能为空')
  if (len > NICK_MAX) {
    throw new NicknameError('NICKNAME_TOO_LONG', `上限 ${NICK_MAX} 字符，当前 ${len}`)
  }
  const code = identity?.session?.code
  if (!api || !code) throw new NicknameError('NICKNAME_NO_SESSION', '中转未连接')

  const attempt = () => api.patchNickname({ code, nickname: value })
  let retried = false
  let response
  try {
    response = await attempt()
  } catch (err) {
    // 挑战 60 秒有效：过期只重取一次，避免打转（再失败就如实抛给界面）
    if (err?.code !== 'AUTH_CHALLENGE_INVALID') throw err
    retried = true
    response = await attempt()
  }

  if (typeof identity?.setNickname === 'function') await identity.setNickname(value)
  return { retried, nickname: value, response }
}
