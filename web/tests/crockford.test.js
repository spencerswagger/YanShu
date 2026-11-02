import test from 'node:test'
import assert from 'node:assert/strict'
import { normalize, valueOf, checkChar, display, verifyInput } from '../src/lib/crockford.js'

test('归一化：大小写 / 分隔符 / O→0 / I,L→1', () => {
  assert.equal(normalize('awqw'), 'AWQW')
  assert.equal(normalize('AW-QW'), 'AWQW')
  assert.equal(normalize('a w q w'), 'AWQW')
  assert.equal(normalize('OIL1'), '0111')
  assert.equal(normalize('AWQWU'), null, 'U 一律拒绝')
  assert.equal(normalize('AWQ'), null)
  assert.equal(normalize('AWQ!'), null)
})

test('校验字符：契约样例 AWQW → X（CRYPTO-PACK §15.1）', () => {
  assert.equal(valueOf('AWQW'), 357116)
  assert.equal(checkChar('AWQW'), 'X')
  assert.equal(display('AWQW'), 'AWQW-X')
})

test('verifyInput 拦下打错的校验位', () => {
  assert.deepEqual(verifyInput('awqw-x'), { ok: true, code: 'AWQW' })
  assert.deepEqual(verifyInput('AWQW'), { ok: true, code: 'AWQW' })
  assert.equal(verifyInput('AWQW-R').ok, false)
  assert.equal(verifyInput('AWQW-R').reason, 'check')
  assert.equal(verifyInput('AW!W').reason, 'format')
  assert.equal(verifyInput('').reason, 'format')
})
