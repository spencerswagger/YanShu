import test from 'node:test'
import assert from 'node:assert/strict'
import { encode, decode, Base64UrlError } from '../src/lib/base64url.js'

test('base64url 无填充往返', () => {
  for (const len of [0, 1, 2, 3, 4, 31, 32, 65, 129]) {
    const input = new Uint8Array(len)
    for (let i = 0; i < len; i++) input[i] = (i * 37 + 11) & 0xff
    const text = encode(input)
    assert.equal(text.includes('='), false)
    assert.deepEqual([...decode(text)], [...input])
  }
})

test('base64url 拒绝填充与非法长度（契约 §3.2）', () => {
  assert.throws(() => decode('AA=='), Base64UrlError)
  assert.throws(() => decode('A'), Base64UrlError)
  assert.throws(() => decode('AAAAA'), Base64UrlError, 'len % 4 == 1 必须拒绝')
})

test('base64url 已知向量', () => {
  assert.equal(encode(new TextEncoder().encode('hi')), 'aGk')
  assert.equal(encode(new Uint8Array([0xff, 0xfe, 0xfd])), '__79')
})
