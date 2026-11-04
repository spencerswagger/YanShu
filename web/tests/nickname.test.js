/**
 * 昵称更新三条路径（对应 `src/net/nickname.js`）：
 *   ① 成功；② 挑战过期 → 自动重取一次并成功；③ 连续过期 → 只重试一次后如实失败；
 *   另外两条本地校验：过长（>16）、空。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { updateNickname, NICK_MAX } from '../src/net/nickname.js'

function fakeIdentity(code = 'AWQW') {
  const calls = []
  return {
    session: { code },
    calls,
    async setNickname(v) {
      calls.push(v)
    },
  }
}

test('昵称：成功更新并写回本机身份', async () => {
  const identity = fakeIdentity()
  let calls = 0
  const api = {
    patchNickname: async ({ code, nickname }) => {
      calls += 1
      assert.equal(code, 'AWQW')
      assert.equal(nickname, '阿雁')
      return { code, nickname }
    },
  }
  const result = await updateNickname({ api, identity, nickname: '  阿雁  ' })
  assert.equal(calls, 1)
  assert.equal(result.retried, false)
  assert.equal(result.nickname, '阿雁')
  assert.deepEqual(identity.calls, ['阿雁'])
})

test('昵称：挑战过期 → 自动重取一次并成功', async () => {
  const identity = fakeIdentity()
  let calls = 0
  const api = {
    patchNickname: async ({ nickname }) => {
      calls += 1
      if (calls === 1) {
        const err = new Error('challenge invalid')
        err.code = 'AUTH_CHALLENGE_INVALID'
        throw err
      }
      return { nickname }
    },
  }
  const result = await updateNickname({ api, identity, nickname: '阿龟' })
  assert.equal(calls, 2, '必须恰好重试一次')
  assert.equal(result.retried, true)
  assert.equal(result.nickname, '阿龟')
})

test('昵称：连续过期只重试一次，第二次仍失败就抛出', async () => {
  const identity = fakeIdentity()
  let calls = 0
  const api = {
    patchNickname: async () => {
      calls += 1
      const err = new Error('challenge invalid')
      err.code = 'AUTH_CHALLENGE_INVALID'
      throw err
    },
  }
  await assert.rejects(() => updateNickname({ api, identity, nickname: '阿雁' }), (err) => {
    assert.equal(err.code, 'AUTH_CHALLENGE_INVALID')
    return true
  })
  assert.equal(calls, 2, '最多两次，不许打转')
  assert.deepEqual(identity.calls, [], '失败时不得写回本机昵称')
})

test(`昵称：超过 ${NICK_MAX} 字符本地拒绝，不打接口`, async () => {
  const identity = fakeIdentity()
  let called = false
  const api = {
    patchNickname: async () => {
      called = true
      return {}
    },
  }
  await assert.rejects(
    () => updateNickname({ api, identity, nickname: '阿'.repeat(NICK_MAX + 1) }),
    (err) => {
      assert.equal(err.code, 'NICKNAME_TOO_LONG')
      assert.match(err.message, new RegExp(String(NICK_MAX)))
      return true
    },
  )
  assert.equal(called, false)
})

test('昵称：空值本地拒绝', async () => {
  const identity = fakeIdentity()
  const api = { patchNickname: async () => ({}) }
  await assert.rejects(() => updateNickname({ api, identity, nickname: '   ' }), (err) => {
    assert.equal(err.code, 'NICKNAME_EMPTY')
    return true
  })
})

test('昵称：非挑战类错误原样抛出（不误判成过期）', async () => {
  const identity = fakeIdentity()
  let calls = 0
  const api = {
    patchNickname: async () => {
      calls += 1
      const err = new Error('signature rejected')
      err.code = 'AUTH_SIGNATURE_INVALID'
      throw err
    },
  }
  await assert.rejects(() => updateNickname({ api, identity, nickname: '阿雁' }), (err) => {
    assert.equal(err.code, 'AUTH_SIGNATURE_INVALID')
    return true
  })
  assert.equal(calls, 1, '签名错不该触发重试')
})
