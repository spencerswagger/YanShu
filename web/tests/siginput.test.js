import test from 'node:test'
import assert from 'node:assert/strict'
import { buildSigInput, fields, PURPOSES } from '../src/net/auth.js'
import { hex, ascii, u32be, u64be } from '../src/lib/bytes.js'

test('SIG_INPUT 布局：YSAUTH1 ‖ PURPOSE ‖ NONCE ‖ 字段串（API.md §1.3）', () => {
  const nonce = new Uint8Array(32)
  const input = buildSigInput('TRANSFER_CREATE', nonce, new Uint8Array(0))
  assert.equal(input.length, 7 + 1 + 32)
  assert.equal(new TextDecoder().decode(input.slice(0, 7)), 'YSAUTH1')
  assert.equal(input[7], PURPOSES.TRANSFER_CREATE)
})

test('TRANSFER_CREATE 字段串顺序与宽度', () => {
  const fieldsBytes = fields.TRANSFER_CREATE({
    senderCode: 'AWQW',
    recipientCode: 'WTJF',
    plaintextSize: 5,
    chunkSize: 1048576,
    chunkCount: 1,
    preludeLen: 485,
    preludeSm3: new Uint8Array(32).fill(0x11),
  })
  const expected = new Uint8Array([
    ...ascii('AWQW'),
    ...ascii('WTJF'),
    ...u64be(5),
    ...u32be(1048576),
    ...u32be(1),
    ...u32be(485),
    ...new Uint8Array(32).fill(0x11),
  ])
  assert.equal(hex(fieldsBytes), hex(expected))
  assert.equal(fieldsBytes.length, 4 + 4 + 8 + 4 + 4 + 4 + 32)
})

test('REGISTER / INBOX_LIST / ACK 字段串', () => {
  const pub = new Uint8Array(65).fill(0x04)
  assert.equal(fields.REGISTER({ code: 'AWQW', publicKey: pub }).length, 4 + 65)
  assert.equal(hex(fields.INBOX_LIST({ code: 'AWQW' })), hex(ascii('AWQW')))
  assert.equal(fields.TRANSFER_ACK({ receiverCode: 'WTJF', transferId: 'a'.repeat(32) }).length, 4 + 32)
})

test('unpurpose 拒绝', () => {
  assert.throws(() => buildSigInput('NOPE', new Uint8Array(32), new Uint8Array(0)))
  assert.throws(() => buildSigInput('REGISTER', new Uint8Array(31), new Uint8Array(0)))
})
