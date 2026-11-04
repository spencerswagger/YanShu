/**
 * 签名挑战（API.md §1.2 / §1.3）：无账号体系，写操作全靠"一次性挑战 + SM2 签名"。
 *
 * `SIG_INPUT = "YSAUTH1" ‖ PURPOSE(1) ‖ NONCE(32) ‖ 该用途的字段串`
 * 注意：这与包内签名（CRYPTO-PACK §10.2，前缀 `YSSIG1`）是**两件事**，前缀不同，互不复用。
 */
import { ascii, bytes, u16be, u32be, u64be, utf8 } from '../lib/bytes.js'
import { decode as b64uDecode, encode as b64uEncode } from '../lib/base64url.js'
import { normalizeSignature } from '../lib/der.js'

export const PURPOSES = {
  REGISTER: 0x01,
  NICKNAME_UPDATE: 0x02,
  TRANSFER_CREATE: 0x03,
  TRANSFER_REVOKE: 0x04,
  INBOX_LIST: 0x05,
  WS_HELLO: 0x06,
  TRANSFER_ACK: 0x07,
  ABUSE_REPORT: 0x09,
}

const SIGN_PREFIX = 'YSAUTH1'

export function buildSigInput(purposeName, nonce, fields) {
  const purpose = PURPOSES[purposeName]
  if (!purpose) throw new Error(`unknown purpose: ${purposeName}`)
  if (nonce.length !== 32) throw new Error('nonce must be 32 bytes')
  return bytes(ascii(SIGN_PREFIX), Uint8Array.of(purpose), nonce, fields)
}

/** 各用途的字段串（严格按 API.md §1.3 的顺序与宽度）。 */
export const fields = {
  REGISTER: ({ code, publicKey }) => bytes(ascii(code), publicKey),
  NICKNAME_UPDATE: ({ code, nickname }) => {
    const nick = utf8.encode(nickname)
    return bytes(ascii(code), u16be(nick.length), nick)
  },
  TRANSFER_CREATE: ({
    senderCode,
    recipientCode,
    plaintextSize,
    chunkSize,
    chunkCount,
    preludeLen,
    preludeSm3,
  }) =>
    bytes(
      ascii(senderCode),
      ascii(recipientCode),
      u64be(plaintextSize),
      u32be(chunkSize),
      u32be(chunkCount),
      u32be(preludeLen),
      preludeSm3,
    ),
  TRANSFER_REVOKE: ({ senderCode, transferId }) => bytes(ascii(senderCode), ascii(transferId)),
  INBOX_LIST: ({ code }) => ascii(code),
  WS_HELLO: ({ code }) => ascii(code),
  TRANSFER_ACK: ({ receiverCode, transferId }) => bytes(ascii(receiverCode), ascii(transferId)),
  /**
   * 举报（契约 §11.5）：`SIG_INPUT` **定长 76 字节**，无前缀、KID 不参与：
   *   `YSAUTH1`(7) ‖ PURPOSE 0x09(1) ‖ NONCE(32) ‖ REPORTER_CODE(4) ‖ TRANSFER_ID(32)
   * `TRANSFER_ID` 是服务端那串 32 字符 id 的 **ASCII**（不是 hex 解码后的 16 字节）。
   */
  ABUSE_REPORT: ({ code, transferId }) => bytes(ascii(code), ascii(transferId)),
}

/**
 * 申请挑战 → 拼 SIG_INPUT → 内核签名 → 返回鉴权头。
 * @param {object} p
 * @param {object} p.client   HTTP 客户端
 * @param {object} p.kernel   端侧内核
 * @param {Uint8Array} p.privateKey 本机私钥（只在本机内存/IndexedDB，不上传）
 * @param {string} p.code     自己的 4 位码
 * @param {string} p.purpose  见 PURPOSES
 * @param {Uint8Array} p.fieldBytes 字段串
 */
export async function authHeaders({ client, kernel, privateKey, code, purpose, fieldBytes }) {
  const res = await client.post('/challenges', {
    json: { purpose },
    retry: true,
  })
  const challenge = res.json
  if (!challenge?.challenge_id || !challenge?.nonce) {
    throw new Error('挑战响应缺少 challenge_id / nonce')
  }
  const nonce = b64uDecode(challenge.nonce)
  const input = buildSigInput(purpose, nonce, fieldBytes)
  const raw = kernel.sign(privateKey, input)
  const signature = normalizeSignature(raw)
  return {
    challenge,
    headers: {
      'X-YS-Code': code,
      'X-YS-Challenge-Id': challenge.challenge_id,
      'X-YS-Signature': b64uEncode(signature),
    },
  }
}
