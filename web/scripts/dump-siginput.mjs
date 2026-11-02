#!/usr/bin/env node
/**
 * 打印七种 PURPOSE 的 `SIG_INPUT` 逐字节 hex（固定输入，便于与服务端/Rune 对账）。
 *
 *   cd web && npm run siginput:dump
 *
 * 输出可直接贴给 Core 当"同一份输入、同一串字节"的对照；任何一侧字段顺序/宽度/
 * 前缀不一致，hex 立刻不同。字段定义见 `docs/API.md §1.3`。
 */
import { buildSigInput, fields, PURPOSES } from '../src/net/auth.js'
import { hex } from '../src/lib/bytes.js'

const nonce = new Uint8Array(32) // 全 0，便于对账
const code = 'AWQW'
const peer = 'WTJF'
const transferId = 'a'.repeat(32)
const publicKey = new Uint8Array(65)
publicKey[0] = 0x04
for (let i = 1; i < 65; i++) publicKey[i] = i

const cases = {
  REGISTER: fields.REGISTER({ code, publicKey }),
  NICKNAME_UPDATE: fields.NICKNAME_UPDATE({ code, nickname: '阿雁' }),
  TRANSFER_CREATE: fields.TRANSFER_CREATE({
    senderCode: code,
    recipientCode: peer,
    plaintextSize: 5,
    chunkSize: 1048576,
    chunkCount: 1,
    preludeLen: 485,
    preludeSm3: new Uint8Array(32).fill(0x11),
  }),
  TRANSFER_REVOKE: fields.TRANSFER_REVOKE({ senderCode: code, transferId }),
  INBOX_LIST: fields.INBOX_LIST({ code }),
  WS_HELLO: fields.WS_HELLO({ code }),
  TRANSFER_ACK: fields.TRANSFER_ACK({ receiverCode: code, transferId }),
}

console.log('nonce = 32×00，code = AWQW，peer = WTJF，transfer_id = 32×"a"')
console.log('')
for (const [purpose, fieldBytes] of Object.entries(cases)) {
  const input = buildSigInput(purpose, nonce, fieldBytes)
  console.log(`${purpose} (0x0${PURPOSES[purpose]}) len=${input.length}`)
  console.log(`  fields = ${hex(fieldBytes)}`)
  console.log(`  input  = ${hex(input)}`)
  console.log('')
}
