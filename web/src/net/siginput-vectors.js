/**
 * `SIG_INPUT` 与内核向量逐字节对账（数据源：`vectors/sm2-verify-vectors.json`，已 vendored 到
 * `web/tests/fixtures/sm2-verify-vectors.json`）。
 *
 * 目的：把"字段顺序 / 宽度 / 前缀 / CODE 位置 / nickname 的 u16be 前缀"这些最容易漂的东西钉死。
 * 任何一处构造被改动，这里立刻红——不靠人肉 diff。
 *
 * 注意：`ZA`/`e = SM3(ZA‖SIG_INPUT)` 由内核在验签内部完成，调用方只传**原文**；本文件只比原文。
 */
import { buildSigInput, fields } from './auth.js'
import { hex } from '../lib/bytes.js'

const FIELD = (sample, name) => {
  const hit = sample.fields.find((f) => f.field === name || f.field.startsWith(`${name}(`))
  return hit ? hit.hex : null
}
const asciiOf = (hexStr) => Buffer.from(hexStr, 'hex').toString('ascii')
const bytesOf = (hexStr) => Uint8Array.from(Buffer.from(hexStr, 'hex'))
const u64 = (hexStr) => Number(BigInt(`0x${hexStr}`))

/** 把一条向量还原成我们构造器需要的入参。 */
function paramsOf(sample) {
  const purpose = sample.purpose
  const nonce = bytesOf(FIELD(sample, 'NONCE'))
  if (purpose === 'REGISTER') {
    return { nonce, input: fields.REGISTER({ code: asciiOf(FIELD(sample, 'CODE')), publicKey: bytesOf(FIELD(sample, 'PUBKEY')) }) }
  }
  if (purpose === 'NICKNAME_UPDATE') {
    const nick = new TextDecoder().decode(bytesOf(FIELD(sample, 'NICKNAME')))
    return { nonce, input: fields.NICKNAME_UPDATE({ code: asciiOf(FIELD(sample, 'CODE')), nickname: nick }) }
  }
  if (purpose === 'TRANSFER_CREATE') {
    return {
      nonce,
      input: fields.TRANSFER_CREATE({
        senderCode: asciiOf(FIELD(sample, 'SENDER_CODE')),
        recipientCode: asciiOf(FIELD(sample, 'RECIPIENT_CODE')),
        plaintextSize: u64(FIELD(sample, 'PLAINTEXT_SIZE')),
        chunkSize: u64(FIELD(sample, 'CHUNK_SIZE')),
        chunkCount: u64(FIELD(sample, 'CHUNK_COUNT')),
        preludeLen: u64(FIELD(sample, 'PRELUDE_LEN')),
        preludeSm3: bytesOf(FIELD(sample, 'PRELUDE_SM3')),
      }),
    }
  }
  if (purpose === 'TRANSFER_REVOKE') {
    return {
      nonce,
      input: fields.TRANSFER_REVOKE({
        senderCode: asciiOf(FIELD(sample, 'SENDER_CODE')),
        transferId: asciiOf(FIELD(sample, 'TRANSFER_ID')),
      }),
    }
  }
  if (purpose === 'INBOX_LIST') return { nonce, input: fields.INBOX_LIST({ code: asciiOf(FIELD(sample, 'CODE')) }) }
  if (purpose === 'WS_HELLO') return { nonce, input: fields.WS_HELLO({ code: asciiOf(FIELD(sample, 'CODE')) }) }
  if (purpose === 'TRANSFER_ACK') {
    return {
      nonce,
      input: fields.TRANSFER_ACK({
        receiverCode: asciiOf(FIELD(sample, 'RECEIVER_CODE')),
        transferId: asciiOf(FIELD(sample, 'TRANSFER_ID')),
      }),
    }
  }
  throw new Error(`未知 PURPOSE：${purpose}`)
}

function firstDiff(a, b) {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i
  return a.length === b.length ? -1 : n
}

/**
 * @param {{sig_input_samples: Array}} vectors
 * @returns {Array<{purpose:string, ok:boolean, expectedLen:number, actualLen:number, diffAt:number, expected:string, actual:string}>}
 */
export function checkSigInputVectors(vectors) {
  return vectors.sig_input_samples.map((sample) => {
    const { nonce, input } = paramsOf(sample)
    const actual = buildSigInput(sample.purpose, nonce, input)
    const expected = bytesOf(sample.sig_input)
    const diffAt = firstDiff(expected, actual)
    return {
      purpose: sample.purpose,
      ok: diffAt === -1 && expected.length === sample.len,
      expectedLen: expected.length,
      declaredLen: sample.len,
      actualLen: actual.length,
      diffAt,
      expected: hex(expected),
      actual: hex(actual),
    }
  })
}
