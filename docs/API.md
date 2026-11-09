# 雁书 YanShu · HTTP + WebSocket 接口契约（API）

> **本契约版本：v1**（`api_version = "v1"`）
> **冻结日期：2026-11-02**
> **变更需走 ADR**：路径、字段名、错误码、错误码 HTTP 状态、信令消息类型、不变量（如"服务端不见文件名"）的任何改动，都必须先在 `docs/ADR.md` 留 ADR 并评审。
>
> 配套文档：加密包字段级定义见 `docs/CRYPTO-PACK.md`（`YSPK/1.0`）。本文只定义"字节怎么进出"，不定义"字节怎么加解密"。
>
> 本文 **MUST / MUST NOT / SHOULD** 按 RFC 2119 语义解读。

---

## 0. 全局约定

### 0.1 端点与协议

| 项 | 值 |
|---|---|
| HTTP base | `https://<host>/v1` |
| WebSocket | `wss://<host>/v1/ws` |
| 传输 | 普通 HTTPS（不做国密 TLS）；HTTP/1.1 与 HTTP/2 均可 |
| JSON | `Content-Type: application/json; charset=utf-8`，UTF-8 无 BOM |
| 二进制 | `Content-Type: application/octet-stream`，请求体即原始字节 |
| 字段命名 | `snake_case`，**大小写敏感** |
| 未知字段 | **MUST 拒绝**（`400 FIELD_NOT_ALLOWED`）。这是"服务端不落明文"的可测试边界：客户端若试图塞 `filename` 之类的字段，服务端必须报错而不是忽略 |
| 未知查询参数 | **MUST 拒绝**（`400 BAD_REQUEST`） |
| 时间 | RFC 3339 UTC、秒级、`Z` 结尾，如 `2026-11-02T14:00:00Z` |
| 二进制字段 | base64url（RFC 4648 §5）**无填充**；解码方 MUST 拒绝 `=` 与 `len%4==1` |
| ID | 32 位小写 hex（128 bit）。`transfer_id` / `challenge_id` / `download_id` 同构，靠字段名区分 |
| 请求追踪 | 客户端可带 `X-YS-Request-Id`（≤64 字符可打印 ASCII），服务端原样回显 |
| 多值/数组 | JSON 数组，顺序有意义时在字段说明里写明 |

### 0.2 错误信封

所有非 2xx 响应统一：

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "too many requests",
    "scope": "ip",
    "retry_after": 12,
    "request_id": "req_7f3a1c9e"
  }
}
```

- `code`：**唯一权威**，客户端必须按 `code` 分支，**不得**匹配 `message` 文案。
- `message`：给开发者看的英文短句，**不含**任何用户数据、文件名、密钥、IP。
- `scope` / `retry_after`：仅限速类错误出现（见第 12 章）。
- `request_id`：服务端生成，便于对日志；不含用户信息。
- `details`：**可选**对象，只承载结构化、非用户内容的信息。v1 **只允许一个键** `missing`（缺块区间数组，见 §6.6）；新增键必须走 ADR。服务端 MUST NOT 在 `details` 里回显请求体、文件名、明文或任何码以外的用户输入。

```json
{
  "error": {
    "code": "CHUNKS_MISSING",
    "message": "chunks missing",
    "details": { "missing": [ { "start": 2, "count": 1 } ] },
    "request_id": "req_7f3a1c9e"
  }
}
```

### 0.3 已锁死的边界（不重开论证）

- **无注册无登录**：身份 = 密钥对；写操作靠 **SM2 签名挑战**。
- **明确信任服务器**：不做公钥指纹核对。服务器可信，但对**文件名与明文内容**零知识。
- **不做 TURN**，只配 STUN；直传失败静默回落中转。
- 4 位 Crockford Base32 用户码；撞码时**客户端重新生成密钥对**。
- 私钥只在本机（IndexedDB），不上传、不备份、无导出接口。

### 0.4 客户端时间基准（跨端统一，禁止用本机钟算有效期）

服务端返回的一切绝对时间（`expires_at`、`lease_expires_at`、`generated_at`）都是 **UTC RFC 3339**。客户端 **MUST NOT** 用本机 `Date.now()` 直接与这些字段相减——设备钟可能偏几分钟到几小时，偏差会直接把"还能取件"显示成"已过期"（或反之）。

- **基准**：优先用 `/v1/config` 的 `server_time`（§4.1，UTC 秒级），退化到响应头 `Date`；算 `offset = serverTime - performance.now()`，之后用**单调时钟** `performance.now() + offset` 推进。
- **刷新**：**不轮询**；页面重新可见（`visibilitychange`）或收到新的 `Date` 头时重算一次 offset，不累积误差。
- **一致性**：同一屏里"剩余时间展示"与"过期判定（置灰/禁点）" MUST 用同一基准；不允许一处用服务端基准、一处用本机钟。
- **有效期来源**：发送侧 MUST 用 `POST /v1/transfers` 响应里的 `expires_at`（服务端已按 `[3600, 86400]` 夹取），MUST NOT 用本地 `ttl_seconds` 默认值自算——部署可把 TTL 配得更短（§1.5）。
- 该规则对所有端（Web 与后续端）一致，属契约层，不由各端自定。

---

## 1. 身份、码与鉴权

### 1.1 身份三件套

| 项 | 规格 |
|---|---|
| `code` | **固定 4 字符**，Crockford Base32 字母表 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`；由 `SM3(公钥)` 前 20 bit 派生（见 `CRYPTO-PACK.md` §3.4）。**码本身不含校验字符**：传输、入库、比对一律只有这 4 位（校验字符 v1 不启用，见 §15）。服务端的归一化规则见 §1.6 |
| `public_key` | SM2 未压缩点，65 字节，base64url 无填充（编码后 87 字符） |
| `nickname` | UTF-8 NFC，1..32 字节，不允许控制字符与 `<>`，可含中英文；服务端只做长度与字符集校验，不做内容过滤以外的推断 |

### 1.2 签名挑战（所有写操作的门）

1. 客户端 `POST /v1/challenges` 拿一个一次性挑战。
2. 客户端按 §1.3 的公式拼 `SIG_INPUT`，用自己私钥做 SM2 签名（DER 编码）：`e = SM3(ZA ‖ SIG_INPUT)`，`ZA` 用默认 userID `1234567812345678` + `ENTL=0x0080`，逐字节定义见 `CRYPTO-PACK.md` §10.2；**`ZA` 由算法内部参与，不要拼进 `SIG_INPUT`**。
3. 客户端把签名放进请求头，与业务请求一起提交。
4. 服务端：验签 + 校验挑战未过期/未使用/用途一致 + 校验 `X-YS-Code` 与 `SIG_INPUT` 里被签名的 `CODE(4)` 逐字节相同（不符 → `AUTH_CODE_MISMATCH`）；成功后**立即作废**该挑战。

> **唯一口径（不要两套）**：挑战只绑 `purpose` + 时间窗；**码绑定在签名里**（`SIG_INPUT` 的 `CODE(4)` 字段），服务端验签后比对 `X-YS-Code`。不存在"挑战先绑码"这条路径。

**挑战不变量**

| 项 | 值 |
|---|---|
| 有效期 | 120 秒 |
| 使用次数 | 1 次（成功即作废；失败也作废，防爆破） |
| 用途绑定 | 签发时绑定 `purpose`，提交时用途不符 → `AUTH_CHALLENGE_INVALID` |
| **不绑 code** | 挑战**不携带也不绑定**任何码：`REGISTER` 时该码尚未注册，没有"已存在的码"可绑。码与身份的绑定由 §1.3 的 `SIG_INPUT` 里被签名的 `CODE(4)` 完成 |
| 未使用清理 | 10 分钟后自动失效 |
| `nonce` | 32 字节 CSPRNG，base64url 下发给客户端 |

### 1.3 `SIG_INPUT` 规范（字节级，与 Rune 共用）

```
SIGN_PREFIX = "YSAUTH1"        // 7 字节 ASCII: 59 41 55 54 48 31
SIG_INPUT   = SIGN_PREFIX ‖ PURPOSE(1 字节) ‖ NONCE(32 字节) ‖ <该用途的字段串>
```

字段串里的整数一律 `u16be/u32be/u64be`，字符串一律 UTF-8 原始字节 + 显式长度前缀（若有变长字段）。

> **`ZA` / userID 口径（与包签名完全相同，别抄两套）**：`ID = "1234567812345678"`（16 字节 ASCII）、`ENTL = 0x0080`，`ZA` 按 `CRYPTO-PACK.md` §10.2 构造；`SIG_INPUT` 是 `ZA` 之后的**消息 M**，两者不互相包含。挑战域前缀 `YSAUTH1` 与包签名域前缀 `YSSIG1` 是两套拼接，**M 不同但 SM2 与 ZA 完全一致**。

**`SIG_INPUT` 长度上限（由字段上限推导，不是拍脑袋）**

```
SIG_INPUT_LEN = 7（"YSAUTH1"） + 1（PURPOSE） + 32（NONCE） + len(字段串)
```

| PURPOSE | 字段串构成 | 字段串上限 |
|---|---|---:|
| `0x01 REGISTER` | `CODE(4) ‖ PUBKEY(65)` | **69** |
| `0x02 NICKNAME_UPDATE` | `CODE(4) ‖ u16be(2) ‖ NICKNAME(≤32)` | 38 |
| `0x03 TRANSFER_CREATE` | `4+4+8+4+4+4+32` | 60 |
| `0x04 TRANSFER_REVOKE` | `CODE(4) ‖ TRANSFER_ID(32)` | 36 |
| `0x05 INBOX_LIST` | `CODE(4)` | 4 |
| `0x06 WS_HELLO` | `CODE(4)` | 4 |
| `0x07 TRANSFER_ACK` | `CODE(4) ‖ TRANSFER_ID(32)` | 36 |
| `0x08 UPLOAD_TOKEN_ISSUE` | `CODE(4) ‖ TRANSFER_ID(32)` | 36 |

**结论（写死）**：

- **`SIG_INPUT_MAX = 40 + 69 = 109 字节`**（`REGISTER` 最长）。`nickname ≤ 32 字节`（§1.1）、`transfer_id` 固定 32 字符、`CODE` 固定 4 字符——因此**任何合法请求拼接后的长度必然 ≤ 109**，不存在"字段各自合法、拼起来超限"的组合。
- 服务端 MUST 对 `SIG_INPUT` **按 PURPOSE 解析并逐字段校验**（字段越界报各自错误名，如 `NICKNAME_INVALID` / `CODE_FORMAT_INVALID`）；**MUST NOT** 用一个笼统的字节上限代替字段校验。
- **防御性硬上限 `SIG_INPUT_HARD_LIMIT = 512` 字节**（实现侧常量）：超长输入 MUST 在解析前被拒，防 DoS；触发时返回 §10.1 表中那条专属 400 码（当前仅库层可触发）。**该门在实际请求路径上不可达**——昵称先被字段级校验拒（`≤32` 字节，返回 `400 NICKNAME_INVALID`）、其余字段定长，所以任何请求都到不了 513 字节。
- **两层限额分工（写死）**：**109 是合法性边界**（越界走字段级错误，如 `NICKNAME_INVALID` / `CODE_FORMAT_INVALID`）；**512 是防御性 DoS 门**（对应 §10.1 那条 400 码，当前 HTTP 不可达、仅库层可触发）。服务端 MUST NOT 用字节上限代替字段校验；客户端 MUST 按字段上限本地校验、**不应依赖**该码。
- **客户端义务**：发请求前 MUST 在本地按字段上限校验（昵称 ≤32 字节、码 4 位、`transfer_id` 32 字符），**不要依赖服务端兜底**；否则用户会看到"签名无效"这类误导性错误。
- 未来若新增 PURPOSE 或放宽某字段上限而使 `SIG_INPUT_MAX` 超过 109，必须同步更新本表与常数（走 ADR），并保证 `SIG_INPUT_HARD_LIMIT ≥ SIG_INPUT_MAX`。

| PURPOSE | 名称 | 字段串（按序拼接） | 字段串上限 | `SIG_INPUT` 总长（实测） |
|---:|---|---|---:|---:|
| `0x01` | `REGISTER` | `CODE(4 ASCII) ‖ PUBKEY(65)` | 69 | **109** |
| `0x02` | `NICKNAME_UPDATE` | `CODE(4 ASCII) ‖ u16be(NICK_LEN) ‖ NICKNAME(UTF-8)` | 38 | **78** |
| `0x03` | `TRANSFER_CREATE` | `SENDER_CODE(4) ‖ RECIPIENT_CODE(4) ‖ u64be(PLAINTEXT_SIZE) ‖ u32be(CHUNK_SIZE) ‖ u32be(CHUNK_COUNT) ‖ u32be(PRELUDE_LEN) ‖ PRELUDE_SM3(32)` | 60 | **100** |
| `0x04` | `TRANSFER_REVOKE` | `SENDER_CODE(4) ‖ TRANSFER_ID(32 ASCII 小写 hex)` | 36 | **76** |
| `0x05` | `INBOX_LIST` | `CODE(4 ASCII)` | 4 | **44** |
| `0x06` | `WS_HELLO` | `CODE(4 ASCII)` | 4 | **44** |
| `0x07` | `TRANSFER_ACK` | `RECEIVER_CODE(4) ‖ TRANSFER_ID(32)` | 36 | **76** |
| `0x08` | `UPLOAD_TOKEN_ISSUE` | `SENDER_CODE(4) ‖ TRANSFER_ID(32)` | 36 | **76** |
| `0x09` | `ABUSE_REPORT` | `REPORTER_CODE(4 ASCII) ‖ TRANSFER_ID(32 ASCII 小写 hex)` | 36 | **76** |

共 **9 个** `PURPOSE`（`0x01`–`0x09`）；上表总长 = `7 + 1 + 32 + 字段串` = 40 + 字段串，与实测一致，最长仍是 `REGISTER` 的 **109**。

**`0x08 UPLOAD_TOKEN_ISSUE` 的逐字节定义**（重签发端点 §1.7.5 用）：

```
SIG_INPUT = "YSAUTH1"          (7 字节 ASCII)
          ‖ 0x08                (1 字节 PURPOSE)
          ‖ NONCE               (32 字节，挑战下发)
          ‖ SENDER_CODE         (4 字节 ASCII，归一化后的发送方码)
          ‖ TRANSFER_ID         (32 字节 ASCII，小写 hex)
                                 共 76 字节
```

- 两个字段都是**定长**，因此**不加长度前缀**（与 `0x02 NICKNAME_UPDATE` 变长字段的处理不同）。
- **`KID` 不参与 `SIG_INPUT`**：`KID` 是服务端状态，客户端在签名时无法可靠得知；它只在服务端派生与校验凭据时使用（§1.7.2）。把 `KID` 拼进签名输入会让"轮换版本后旧签名无法复现"，且不增加任何安全性。
- `SENDER_CODE` 必须与请求头 `X-YS-Code` 逐字节相同（归一化后，§1.6）。

**每个 PURPOSE 的字段串第一位都是 `CODE(4)`**（`REGISTER` 用待注册的码，`TRANSFER_ACK` 用接收方码），且它必须与请求头 `X-YS-Code` 逐字节相同。所以"你持有这个码对应的私钥"由**签名覆盖 code** 证明，不依赖挑战绑码。

示例（`TRANSFER_CREATE`）：

```
"YSAUTH1" ‖ 03
‖ "AWQW" ‖ "WTJF"
‖ 0000000000000005            // plaintext_size = 5
‖ 00100000                    // chunk_size = 1048576
‖ 00000001                    // chunk_count = 1
‖ 000001e5                    // prelude_len = 485
‖ 8625ec587744caa7bdf47f65120dc5ce3bb41d9ddc72c1fc0a21224a1a814179   // = SM3(prelude)，32 字节
（NONCE 插在 PURPOSE 之后）
```

### 1.4 鉴权头

| 头 | 说明 |
|---|---|
| `X-YS-Code` | 4 字符码（已归一化） |
| `X-YS-Challenge-Id` | 32 hex |
| `X-YS-Signature` | base64url(DER)，70..72 字节 |

缺任何一个 → `401 AUTH_MISSING`。

### 1.5 两类"能力凭证"（不用签名的读路径）

| 凭证 | 语义 | 有效期 |
|---|---|---|
| `transfer_id` | 128 bit 不可猜的**能力凭证**：持有它即可读取该传输的密文。它只会经由已鉴权通道（WS `TRANSFER_NOTICE` / `GET /v1/inbox`）送到接收方 | 传输生命周期内 |
| `upload_token` | 发送方上传侧凭证（`POST /transfers` 下发），可读写自己这条传输的上传状态 | **= 传输 `expires_at`**（TTL ≤ 24 h，部署可配更短）；随传输终结失效，可重签发（§1.7.5） |
| `download_id` | 接收方下载租约凭证（`GET /prelude` 下发），只用于取块与 `ack` | **30 分钟**（§7.3） |

用户码**不是**凭证、不授予任何操作权限。三者的完整生命周期、失效语义与应急吊销见 §1.7。

**`upload_token` 的构造（写死）**：`upload_token = base64url( HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1" ‖ TRANSFER_ID_ASCII ‖ u32be(KID)) )`，32 字节、无填充。

- 库内只存 `SM3(upload_token)`，无明文 token 可被拖库窃取；`Idempotency-Key` 重放时用同一 `transfer_id` 与同一密钥重算即可返回**逐字节相同**的 token。
- 校验时**不重算**：只比库内 `SM3(token)` 与记录里的 `KID`（§1.7.2）；`TOKEN_SECRET` 只在**签发**时参与派生。
- `TOKEN_SECRET` 只来自部署密钥，不入库、不写日志。
- **`KID` 进派生输入**：递增 `KID` 后重签发的凭据与旧凭据逐字节不同，旧凭据不会因重签发而复活（§1.7.3）。`KID` 只作派生输入与记录元数据，**不出现在任何请求/响应字段里**，wire 格式不变。
- **吊销只由 `KID` 承担**：递增 `KID` → 旧凭据 `AUTH_TOKEN_STALE`；只换 `TOKEN_SECRET`（`KID` 不变）**不吊销**任何既有凭据，只影响此后新签发凭据的派生值（§1.7.3）。

服务端只存 `SM3(upload_token)`，不存明文 token。`transfer_id` 泄漏的后果：他人可消耗你的下载次数并拿到密文（拿不到明文，因为 DK 被 `SM2` 封给接收方）——这是被显式接受的风险，写入威胁模型。

### 1.6 码的归一化与规范形式

码只有一种规范形态：**4 个 Crockford 符号**。归一化是"映射到规范形态"的幂等函数，规则与端侧完全一致（`CRYPTO-PACK.md` §3.4）：

1. 去 `-` 与空白 → 转大写 → `O→0`、`I→1`、`L→1`；
2. 结果必须**正好 4 个符号**，且每个都在字母表内（`U` 一律拒绝）；
3. 只允许上述映射：**禁止**任何猜测性纠错（不做编辑距离、不做邻近键替换、**不把 5 位截成 4 位**）。

服务端 MAY 执行这套归一化，但下列约束是硬的：

| 约束 | 说明 |
|---|---|
| 幂等 | `normalize(normalize(x)) == normalize(x)`，实现必须可重复 |
| 唯一落点 | 归一化 MUST 在**任何**判定之前完成：撞码判定、限速计数、失败锁定、`SIG_INPUT` 里的 `CODE(4)` 比对、审计记录，全部只用归一化结果 |
| 4 位硬门 | 归一化后不是正好 4 位 → `400 CODE_FORMAT_INVALID`。v1 **不接受** 5 位 `CODE-CHECK` 形式：校验字符 v1 不启用（§15），服务端无法区分"校验符"与"用户多打一位" |
| 不改变码空间 | 归一化只归并**同一个码的不同写法**（大小写、易混字符、分组符），不会把两个不同的规范码映射到一起；码空间仍是 2^20 个规范值 |

**安全结论（写死）**：容错归一化**不扩大撞码面**，但会归并同一码的多种书写——因此限速与失败锁定必须按**归一化后的码**计数，否则可用大小写变体绕过锁定。防"手滑打到另一个合法码"的责任在发送端：发送前 MUST 展示对方昵称供确认（`check_symbol()` 只是本地提示，见 `CRYPTO-PACK.md` §3.4）。

### 1.7 能力凭证的生命周期与版本吊销（KID）

#### 1.7.1 三种凭证

| 凭证 | 授予什么 | 绑定 | 寿命 | 谁持有 |
|---|---|---|---|---|
| `transfer_id` | 读该传输的元数据与密文（**能力凭证**，持有即可读） | 单一传输 | 传输生命周期 | 接收方（经已鉴权通道获得） |
| `upload_token` | 写操作：`PUT prelude`、`PUT chunks/{i}`、`GET status`、`POST complete` | 单一传输 + 签发时的 KID | **6 小时**（且 ≤ 传输 `expires_at`） | 发送方 |
| `download_id` | 下载租约：`GET chunks/{i}`、`POST ack` | 单一传输的**一次**租约 + 签发时的 KID | 30 分钟 | 接收方 |

`transfer_id` 与 token **互不替代**：前者能读密文，后者能写。用户码不是凭证（§1.1）。

#### 1.7.2 存储与校验口径

- 服务端**只存凭据的哈希**（`upload_token` 存 `SM3`），不存明文。
- `upload_token` 由令牌派生密钥 `TOKEN_SECRET` 与**凭据版本 `KID`** 确定性派生（§1.5）；`KID` 是**服务端元数据**：不出现在任何请求/响应字段、不改变 wire 格式（仍是 32 字节 base64url）。
- **校验顺序写死（四类）**：① 比 `KID`（记录里的签发 `KID` vs 当前 `KID`）——不等即 `AUTH_TOKEN_STALE`；② 比 `SM3(token)` 与库内记录——不等即 `AUTH_TOKEN_INVALID`；③ 比凭据自身有效期（上传 **6 小时** / 租约 **30 分钟**）——超期即 `AUTH_TOKEN_EXPIRED`；④ 最后才看传输状态（`409`/`410`）。
- **不重算**：校验不比 `TOKEN_SECRET`（它只是派生盐），因此**轮换 secret 不影响既有凭据**；吊销只由 `KID` 承担。

#### 1.7.3 版本吊销（`KID`，版本只能前进）

**`KID` 的取值规则（写死）**

- 凭据版本号 `KID`：**正整数**（十进制）。部署配置项为 `YANSHU_TOKEN_EPOCH`；**`YANSHU_TOKEN_KID` 是它的旧别名，两者等价**（设其一即可，同时设置时以 `YANSHU_TOKEN_EPOCH` 为准）。
- **未配置时使用默认 `KID = 1`**（仅对**全新库**成立；库里已有记录时以记录值为准，见下）。首次部署给默认值不构成风险——唯一危险的是"调回旧值让旧凭据复活"。
- **版本只能前进**：轮换时新值 MUST **严格大于**当前值；**同一版本重启允许相等**（否则每次重启都会被自己挡住）。
- 服务端 MUST 持久化"已生效的最大 `KID`"（记为 `current`），启动时按下表校验：

| 配置值 `provided` | 启动行为 |
|---|---|
| 未配置且库内无记录（全新库） | 正常启动，`KID` 取默认 `1` |
| 未配置且库内已有记录 | 正常启动，以**记录值**为准（不覆盖、不重置） |
| `provided < current` | **拒绝启动**（`exit 1`），错误信息须同时打印两个值，例如 `YANSHU_TOKEN_EPOCH=1 is lower than the recorded epoch 3: epoch must strictly increase` |
| `provided == current` | 正常启动（同一版本重启） |
| `provided > current` | 正常启动，生效并把 `current` 更新为新值（新签发的凭据用新 `KID`） |

  理由：把 `KID` 调回旧值会让**已被吊销的旧凭据瞬间复活**——这是本机制最危险的误操作，必须在启动时挡住，不能靠人记得。
- **唯一会拒绝启动的情形是"调小"**（`provided < current`）；未配置不构成拒绝理由（见上表前两行）。

**吊销效果（`KID` 是唯一吊销开关）**

- 签发凭据时把当时的 `KID` 写进记录；校验时**先比 `KID`**：记录 `KID` ≠ 当前 `KID` → 一律 `AUTH_TOKEN_STALE`（立即生效，不等过期）。
- **递增 `KID` 即刻生效**：不需要重启进程、不需要删库——更新"当前 `KID`"后新请求立刻按新版本校验（重启或热载都可，但都不是必要条件）。
- 新签发/重签发的凭据用当前 `KID` 派生，**与任何旧凭据逐字节不同**——旧凭据不会因为重签发而复活。
- `/v1/config` 暴露只读 `token_epoch`（**对外字段名保留 `token_epoch`，语义等价本节 `KID`**），便于观测版本切换。
- 这是**全局操作**：影响全站所有在传任务（发送中的上传会中断，需要重签发或重建传输），属**应急手段**，不作日常轮换。

**运维「一次性吊销」标准步骤（可直接照抄）**

1. 二选一把当前版本加一：① **直接推进库内版本状态**（等价 `UPDATE token_kid_state SET kid = kid + 1`）——**立即生效，不需要重启、不需要删库**；或 ② 把部署配置项 `YANSHU_TOKEN_EPOCH`（= 本节 `KID`）改成**比当前更大的整数**并重启。需要更强隔离时可**同时**更换 `TOKEN_SECRET`（可选，不影响吊销本身）。
2. 生效后**所有既有凭据立即失效**：记录 `KID` ≠ 当前 `KID` → `401 AUTH_TOKEN_STALE`（若同时换了 secret，仍是版本失效码，因为先比 `KID`）。
4. 客户端处置：**重新挑战 → 签名 → 取新凭据**（上传走 §1.7.5，下载重新 `GET /prelude`），**不要重算签名**；已传块不重传。
5. 记一条运维日志：`KID` 旧值 → 新值、时间、原因（应急吊销）；**不要**把 `TOKEN_SECRET` 写进日志。

**两种运维动作的语义必须分开写清**（不要混为一谈）：

| 运维操作 | 旧凭据结果 | 语义 |
|---|---|---|
| **只换 `TOKEN_SECRET`**（`KID` 不变） | **仍然有效**（`SM3(token)` 与记录一致、`KID` 一致） | `TOKEN_SECRET` 只是派生盐：轮换它**不吊销**任何凭据，只影响此后新签发凭据的派生值 |
| **递增 `KID`**（`TOKEN_SECRET` 可不变） | `401 AUTH_TOKEN_STALE` | 版本已轮换——"我签发过，但版本作废了" |
| 两者都做 | `401 AUTH_TOKEN_STALE` | 先比 `KID`，版本失效优先 |

**吊销只认 `KID`**：希望"换 secret 即全站失效"的部署必须**同时递增 `KID`**；只换 secret 不构成吊销。

#### 1.7.4 失效条件与错误名（凭据类与签名类严格分开）

| 情形 | HTTP | `code` | 客户端处置 |
|---|---:|---|---|
| 缺凭证头 | 401 | `AUTH_MISSING` | 补头 |
| 凭据不存在 / 格式错 / 与任何已签发凭据不匹配 | 401 | `AUTH_TOKEN_INVALID` | 重新申领（上传见 §1.7.5；下载重新 `GET /prelude`）；**不要**重试同一凭据 |
| 凭据记录的 `KID` 落后于当前版本（版本已轮换） | 401 | `AUTH_TOKEN_STALE` | 重新挑战 → 签名 → 取新凭据（§1.7.5）；**不要重算签名**；文案"凭据已过期版本，请重新获取" |
| 凭据超过自身有效期：**上传 6 小时** / **下载租约 30 分钟** | 401 | `AUTH_TOKEN_EXPIRED` | 上传走 §1.7.5 重签发（已传块不重传）；下载重新 `GET /prelude` 取新租约 |
| 传输进入终态 | 410 | `TRANSFER_REVOKED` / `TRANSFER_EXPIRED` / `TRANSFER_CONSUMED` | 停止并清理本地 |

**判定顺序写死（四类）**：**先判资源终结态**（`REVOKED`/`EXPIRED`/`CONSUMED` → `410`，见 §5.2），资源未终结时才走凭据校验——`KID` 不符 → `AUTH_TOKEN_STALE`；值不对/不存在/格式错 → `AUTH_TOKEN_INVALID`；超期 → `AUTH_TOKEN_EXPIRED`；最后才是 `409` 状态冲突。即**终结态（410）先于凭据（401），凭据内部先 `KID`、再值、再有效期**。

**为什么终结态排在凭据之前（写死）**：传输终结（TTL 到期 / 撤回 / 取走）**不可恢复**，重签发凭据也救不回来。若先回 `401`，客户端会按 §1.7.5 走一遍"重新挑战 → 签名 → 取新凭据"，拿到新凭据后仍然是 `410`——白跑一轮，还会让用户以为"再试一次就好"。因此：

- 传输已终结 → 一律 `410 TRANSFER_REVOKED` / `TRANSFER_EXPIRED` / `TRANSFER_CONSUMED`（按实际终态取对应码），**不返回**任何 `401 AUTH_TOKEN_*`，即使凭据同时不存在 / 已被轮换 / 已超期；
- 传输未终结 → 上表优先级**原样生效**；`AUTH_TOKEN_STALE` 的「一律」只在资源未终结时成立，不得用来顶替 `410`；
- 客户端按状态码分叉：`410 TRANSFER_*` → **停止重试、清理本地半成品，不要重取凭据**；`401 AUTH_TOKEN_*` → 才走重签 / 重取租约（§1.7.5）。两者处置互斥，把 `410` 当"凭据问题"重试会一直撞同一堵墙。

**三码的触发位置（便于构造用例）**：`STALE` 在**第 ① 步**（比 `KID`）触发，需要一次版本轮换；`INVALID` 在**第 ② 步**（比 `SM3(token)`）触发，构造方式为错 token / 格式错 / 别的传输的 token；`EXPIRED` 在**第 ③ 步**（比有效期）触发，需把上传 6 h 或租约 30 min 调短、或构造过期记录。"在线路上正常流转的凭据**不会**触发 `INVALID`/`EXPIRED`，所以这两个码只能用针对性用例验证。

**两类错误不得互相顶替**（写死）：

- 凭据类**三个**：`AUTH_TOKEN_STALE`（`KID` 已轮换）、`AUTH_TOKEN_INVALID`（不存在 / 格式错 / 值不匹配）、`AUTH_TOKEN_EXPIRED`（超 6 h / 30 min 有效期）；
- 签名类：`AUTH_SIGNATURE_INVALID`（**仅**签名本身不被接受：伪造 DER、消息被改、公钥不符）、`AUTH_CODE_MISMATCH`（码与签名不一致）。

**终值（定稿）**：凭据类**三个** —— `AUTH_TOKEN_STALE`（`KID` 已轮换）、`AUTH_TOKEN_INVALID`（值不匹配·格式错·不存在）、`AUTH_TOKEN_EXPIRED`（超 6 h / 30 min）；签名类**一个** —— `AUTH_SIGNATURE_INVALID`（**仅**签名本身不被接受）。

> 凭据类错误名**只有** `AUTH_TOKEN_STALE` / `AUTH_TOKEN_INVALID` / `AUTH_TOKEN_EXPIRED` 三个，签名类只有一个 `AUTH_SIGNATURE_INVALID`；不存在其它凭据错误名。

**客户端处置按名字分叉**：前两个都走"重新挑战 → 签名 → 取新凭据"（**不要重算签名**，那是签名问题的解法）；只有拿到 `AUTH_SIGNATURE_INVALID` 才去查 `SIG_INPUT` 拼接、私钥与公钥是否配对。

**`AUTH_TOKEN_EXPIRED`（401）与 `TRANSFER_EXPIRED`（410）的边界（写死）**：前者是**凭据自身**超期（上传 6 h / 租约 30 min），可重签发或重取租约恢复；后者是**传输**终结（TTL 到期），不可恢复。语义不同、状态码不同，**不得混用**。

凭据失效 **MUST NOT** 返回签名类错误：否则客户端会被引去"重算签名 / 怀疑私钥"，而真正原因是"该换凭据了"。同理 `AUTH_TOKEN_STALE` 也 **MUST NOT** 被 `AUTH_TOKEN_INVALID` 顶替——两者客户端处置相同，但排查含义完全不同（一个是版本、一个是来源）。

#### 1.7.5 重签发（可选端点）

`POST /v1/transfers/{id}/token`，无请求体。**v1 定义并实现**（不是可选特性、不是未来版本），用于"吊销后不重传大文件"；部署方 MAY 通过配置关闭（关闭后返回 `501 FEATURE_DISABLED`，代价是吊销后只能重建传输并重传）。

**① 鉴权：只认发送方签名**

- 必须带 `X-YS-Code`（发送方）+ `X-YS-Challenge-Id` + `X-YS-Signature`，`PURPOSE = 0x08 UPLOAD_TOKEN_ISSUE`（§1.3），验签通过才签发。
- **MUST NOT** 接受仅凭 `transfer_id`、旧 `upload_token`、用户码或 `Idempotency-Key` 换取——否则等同"凭据永不过期"。
- 签名有效但不是该传输的发送方 → `403 NOT_TRANSFER_PARTY`。

**② 幂等与限次**

- **幂等键是 `(transfer_id, KID)`**：同一键下重复调用返回**逐字节相同**的凭据与相同 `expires_at`（`200`），不刷新、不累加。
- 派生输入含 `KID` 与 `TOKEN_SECRET`：若期间只换过 `TOKEN_SECRET`（`KID` 未变），重签发会得到**新值**，旧值已 `AUTH_TOKEN_INVALID`——这是预期行为，不属于幂等破坏。
- 限速：按传输 10 次/分钟、按码 30 次/分钟（§11.1），超限 `429`。

**③ 失效联动：旧凭据不得复活**

新凭据用当前 `KID` 派生，与旧凭据**逐字节不同**；旧凭据的记录 `KID` 永久落后 → 永久 `AUTH_TOKEN_STALE`。重签发不是"续期"，MUST NOT 让任何旧凭据重新可用。

**④ 已传块不重传（该端点的核心价值）**

拿到新凭据后，先 `GET /status` 取 `missing`，只补缺失块；已 `201/204` 的 `prelude` 与块**不重传**。重新上传已完成块属实现缺陷（浪费带宽，且可能触发 `409 CHUNK_CONFLICT`）。

**⑤ 响应**

| 响应 | 含义 |
|---|---|
| `200 { "upload_token": "...", "expires_at": "..." }` | 新凭据用当前 `(TOKEN_SECRET, KID)` 派生，有效期 = 传输 `expires_at` |
| `403 NOT_TRANSFER_PARTY` | 签名有效但调用方不是发送方 |
| `404 TRANSFER_NOT_FOUND` | 传输不存在 |
| `410` + 对应终结码 | 传输已终态 |
| `501 FEATURE_DISABLED` | 部署方关闭了该可选端点 |

#### 1.7.6 可复跑用例（验收集固定剧本）

1. 建传输记 `tokenA`，`PUT /prelude` → 期望 `201`；
2. 递增 `KID`（可同时换 `TOKEN_SECRET`）并生效；
3. 用 `tokenA` 再打 `PUT /prelude` → **期望 `401 AUTH_TOKEN_STALE`**；
4. `POST /v1/transfers/{id}/token`（`PURPOSE 0x08`）换 `tokenB` → `200`，且 `tokenB ≠ tokenA`；
5. 用 `tokenB` 打 `PUT /prelude` → 期望 `201`/`204`（**不得要求重传已完成块**）；
6. 同一 `(TOKEN_SECRET, KID)` 下重复第 4 步 → `200` 且返回**与 `tokenB` 逐字节相同**（幂等）；
7. 补一条**只换 `TOKEN_SECRET`、不动 `KID`** 的场景：旧凭据 → **期望仍然有效**（`200`/`201`/`204`，与第 3 步的版本失效形成对照）；再补一条**超期**场景：把上传凭据的签发时间推到 6 h 前（或把租约调短）→ 期望 `401 AUTH_TOKEN_EXPIRED`。

只验证"重启后仍可用/不可用"不构成通过：必须验证"版本递增即全站失效 + 重签发恢复 + 幂等 + 两种吊销语义可分"。

#### 1.7.7 本节不定义的东西

表名/列名、`KID` 的存储方式、热载还是重启生效、是否保留上一代密钥——都属实现自由。契约只约束**行为**与**可观测结果**（错误名、HTTP 状态、可复跑用例）。

---

## 2. 服务端可见的元数据白名单（零知识边界）

### 2.1 允许服务端知道与持久化的字段（**穷举**）

| 域 | 字段 |
|---|---|
| 码 | `code`、`public_key`、`nickname`、`registered_at`、`updated_at` |
| 传输 | `transfer_id`、`sender_code`、`recipient_code`、`plaintext_size`、`chunk_size`、`chunk_count`、`prelude_len`、`prelude_sm3`、`total_ciphertext_bytes`、`created_at`、`expires_at`、`state`、`terminal_reason`、`terminal_at`、`download_count`、`max_downloads`、`uploader_ip`（派生列，仅用于按 IP 配额与反滥用）、`ciphertext_purged_at`（派生列，密文删除水位，仅用于让兜底清理逐批推进；无内容语义）、`updated_at` |
| 块 | `transfer_id`、`index`、`length`、`ciphertext_sm3`（幂等比对用）、`stored_at` |
| 挑战 | `challenge_id`、`purpose`、`nonce`（协议数据，过期即删）、`expires_at`、`used` |
| 派生状态（服务端内部，无业务内容） | `prelude_received`、`received_chunks`（位图或行集）、`upload_token_sm3`、`upload_token_kid`（凭据版本号，轮换即吊销旧凭据，见 §1.7.3）、`uploaded_bytes`、下载租约与取件记录（`download_id`、`lease_expires_at`、`acked_at`）、幂等键映射（`idempotency_key → transfer_id`，≤600 秒） |
| 统计计数器（`stats_counters`） | `day`（UTC 日界）、`consumed`、`consumed_bytes`、`created`——**按天聚合的计数**，无个例信息（不含码、`transfer_id`、昵称、大小分布），口径见 §4.6 |
| 举报 | `transfer_id`、`reporter_code`、`reason`、`note`（举报人自填，≤200 字节，服务端可见）、`created_at`、`distinct_reports`（计数） |
| 审计 | `ip`、`method`、`route_template`（**路由模板，如 `/v1/transfers/{id}/chunks/{index}`，不含实际路径参数**）、`status`、`bytes`、`ts`、`request_id` |

白名单的两条硬规矩：

1. **新增列/字段前必须先更新本节**；Gate 的列白名单断言以本节为唯一依据（多一列即失败）。
2. 任何列 MUST NOT 含文件内容、文件名、MIME、明文、密钥、`DK`、清单明文；错误响应与日志同理。审计只记**路由模板**而非实际路径，是为了不让 `transfer_id`（能力凭证）落进日志；需要按单条传输追溯时用 `request_id` + 元数据表，不写路径参数。

### 2.2 服务端**永不**知道、永不落盘的字段

文件名、扩展名、MIME、明文内容、明文摘要、`DK`、任何私钥、清单明文、块明文、本地路径、文件预览、缩略图。

### 2.3 强制性约束（可测）

1. **API 里根本不存在** `filename` / `mime` / `path` 这类字段。任何请求体里出现它们 → `400 FIELD_NOT_ALLOWED`。
2. 二进制端点只接受 `application/octet-stream`；`multipart/form-data`、`text/plain` 等一律 `415 CONTENT_TYPE_UNSUPPORTED`（multipart 是历史上最经典的"顺手带文件名"通道）。
3. 服务端 **MUST NOT** 解析 `prelude` / 块切片的内容（不读头、不解清单），只做长度与 `SM3` 比对。
4. 请求日志与错误日志 **MUST NOT** 记录请求体前 N 字节、`Query String` 原文（只记白名单参数名）、`Authorization` 类头、SDP 内容。
5. 删除是物理删除：`ack` / `revoke` / TTL 清理后，密文分块与 `prelude` 必须被删除；元数据留 tombstone 并**永久保留**（终结 +30 天后脱敏三个字段，见 §5.2）。表内**不存在**文件名 / MIME / 明文 / 密钥 / 密文，所以"永久保留"不涉及任何内容留存。
6. 只记大小、时间、IP、次数（审计白名单，见 §2.1）。

---

## 3. 接口总表

| # | 方法 | 路径 | 鉴权 | 用途 |
|---:|---|---|---|---|
| 1 | GET | `/v1/config` | 无 | 客户端启动配置（块大小、STUN 列表、限值、版本） |
| 2 | POST | `/v1/challenges` | 无（限速） | 申请签名挑战 |
| 3 | POST | `/v1/codes` | 签名 `REGISTER` | 注册码 + 公钥 + 昵称 |
| 4 | GET | `/v1/codes/{code}` | 无（限速 + 锁定） | 查公钥与昵称 |
| 5 | PATCH | `/v1/codes/{code}` | 签名 `NICKNAME_UPDATE` | 改昵称 |
| 6 | POST | `/v1/transfers` | 签名 `TRANSFER_CREATE` | 创建传输 |
| 7 | PUT | `/v1/transfers/{id}/prelude` | `upload_token` | 上传 prelude |
| 8 | PUT | `/v1/transfers/{id}/chunks/{index}` | `upload_token` | 上传一个块切片 |
| 9 | HEAD | `/v1/transfers/{id}/chunks/{index}` | `transfer_id` | 探测块是否存在 |
| 10 | GET | `/v1/transfers/{id}/status` | `upload_token` | 上传进度 / 续传查询 |
| 11 | POST | `/v1/transfers/{id}/complete` | `upload_token` | 标记上传完成 → `READY` |
| 12 | GET | `/v1/inbox` | 签名 `INBOX_LIST` | 待收列表 |
| 13 | GET | `/v1/transfers/{id}` | `transfer_id` | 传输元数据（含状态） |
| 14 | GET | `/v1/transfers/{id}/prelude` | `transfer_id` | 下载 prelude（开启下载租约） |
| 15 | GET | `/v1/transfers/{id}/chunks/{index}` | `transfer_id` + `download_id` | 下载一个块切片 |
| 16 | POST | `/v1/transfers/{id}/ack` | 签名 `TRANSFER_ACK` | 取件完成确认 → 删密文 |
| 17 | POST | `/v1/transfers/{id}/revoke` | 签名 `TRANSFER_REVOKE` | 发送方主动撤回 |
| 18 | POST | `/v1/transfers/{id}/token` | 签名 `UPLOAD_TOKEN_ISSUE` | 重签发 `upload_token`。**v1 定义并实现**；部署方可配置关闭（关闭返回 `501 FEATURE_DISABLED`，代价是吊销后需重建传输并重传）。细则见 §1.7.5 |
| 19 | WS | `/v1/ws` | 首帧签名 `WS_HELLO` | 在线状态、收件通知、直传信令。**v1 已实现**：连接后 10 秒内必须发 `HELLO`（`WS_HELLO` 签名）进入已认证态；握手、帧类型与限速见 §9 |
| 20 | GET | `/v1/stats` | 无 | 全站聚合计数（今日/累计的取走数与字节数、新建数）。**公开无鉴权**，响应禁止缓存（§4.6） |
| 20 | POST | `/v1/transfers/{id}/report` | 签名 `ABUSE_REPORT` | 举报一条传输。**v1 定义并实现**：只记录、不改变传输状态，下架由运维执行（§11.5） |

---

## 4. 码相关接口

### 4.1 `GET /v1/config`（无鉴权）

**响应 200**

```json
{
  "api_version": "v1",
  "crypto_pack_version": "YSPK/1.0",
  "chunk_size": 1048576,
  "max_plaintext_size": 4294967296,
  "max_ttl_seconds": 86400,
  "token_epoch": 1,
  "stun_urls": ["stun:stun.yan-shu.example:3478"],
  "ws_url": "wss://yan-shu.example/v1/ws",
  "limits": {
    "code_lookup_per_min": 30,
    "challenge_per_min": 20,
    "transfer_create_per_hour": 10,
    "chunk_put_per_min": 600
  }
}
```

**不返回**任何密钥、任何内部地址、任何 turn 配置（本项目**没有** TURN，见 §9.5）。

**`token_epoch`**：只读整数，与 §1.7 的凭据版本 `KID` **同义**（对外沿用 `token_epoch` 这个字段名）；递增即吊销全部既有凭据。只用于观测与排查，客户端 MUST NOT 依赖它做鉴权判断。

**`stun_urls` / `ws_url` 的契约约束**：由部署注入，契约不给默认值。`stun_urls` MUST 至少 1 条且 MUST NOT 含 `turn:` / `turns:`；`ws_url` 允许为 `null`（表示该部署不提供信令），此时客户端 MUST 按 §9.6 降级；`config` 里 MUST NOT 出现密钥、TURN 凭据或内部地址。

### 4.2 `POST /v1/challenges`

**请求**

```json
{ "purpose": "TRANSFER_CREATE" }
```

`purpose` ∈ `REGISTER | NICKNAME_UPDATE | TRANSFER_CREATE | TRANSFER_REVOKE | INBOX_LIST | WS_HELLO | TRANSFER_ACK`。

**请求体只有 `purpose`，没有 `code` 字段**（见 §1.2 的唯一口径）：码不在挑战里，而是在 `SIG_INPUT` 里被签名。`REGISTER` 因此天然可用——码还没注册也能签。

**响应 200**

```json
{
  "challenge_id": "3b1f0c9a7d2e4856b0f1a2c3d4e5f607",
  "nonce": "5Hk3n0Qq8mZ2xW7pC1vB4tY6uI9oP0aS3dF5gH7jK1l",
  "purpose": "TRANSFER_CREATE",
  "expires_at": "2026-11-02T14:02:00Z"
}
```

**失败**：`429 RATE_LIMITED`（按 IP）、`400 BAD_REQUEST`（未知 purpose）。

### 4.3 `POST /v1/codes` —— 注册（撞码语义在这里）

**头**：`X-YS-Code`、`X-YS-Challenge-Id`、`X-YS-Signature`（`purpose = REGISTER`；签名输入字段串 = `CODE(4 ASCII) ‖ PUBKEY(65)`，逐字节定义见 §1.3）

**请求**

```json
{
  "code": "AWQW",
  "public_key": "BL_Z33MpD1DsFr0YTjHAQ7bXD8_SRfdtEO8mtmydGbEW9CWv6h5-hJsvVz5WKrq2XPR8BFwyouzC8j-GUZoewl0",
  "nickname": "阿雁"
}
```

**响应 201**

```json
{
  "code": "AWQW",
  "public_key": "BL_Z33MpD1DsFr0YTjHAQ7bXD8_SRfdtEO8mtmydGbEW9CWv6h5-hJsvVz5WKrq2XPR8BFwyouzC8j-GUZoewl0",
  "nickname": "阿雁",
  "registered_at": "2026-11-02T14:00:00Z"
}
```

**撞码语义（写死，客户端必须照做）**

| 响应 | 含义 | 客户端 MUST 做的事 |
|---|---|---|
| `409 CODE_TAKEN` | 该 4 位码已被别的公钥占用 | **丢弃当前密钥对**，重新生成 SM2 密钥对，重新派生码，重新走本接口；最多 8 次；8 次仍冲突则提示"稍后重试"并停止（**不得**自动加长码、**不得**换别人的码） |
| `409 PUBKEY_TAKEN` | 同一公钥已注册在另一个码下（本地状态异常） | 清本地身份、重新生成密钥对并注册；或使用既有码（实现可提示"恢复既有身份"） |
| `200`（重复注册） | 同码 + 同公钥（重装/换设备前的重复提交） | 幂等：返回与首次相同的 body（`registered_at` 不变），**不覆盖昵称**——改昵称只能走 §4.5 的签名挑战 |

**码格式**：`code` 一律按 §1.6 归一化；归一化后不是正好 4 个合法符号 → `400 CODE_FORMAT_INVALID`；v1 **不接受** 5 位 `CODE-CHECK` 形式。

服务端**不得**在 `409` 响应里返回占用者的昵称或任何信息（否则等于开了一个"码占用枚举"接口）。

> 撞码不是安全事件：4 位 = 1,048,576 组合，约 1200 人量级才开始撞；撞了换密钥对重试即可。

### 4.4 `GET /v1/codes/{code}` —— 查公钥与昵称

**响应 200**

```json
{
  "code": "AWQW",
  "public_key": "BL_Z33MpD1DsFr0YTjHAQ7bXD8_SRfdtEO8mtmydGbEW9CWv6h5-hJsvVz5WKrq2XPR8BFwyouzC8j-GUZoewl0",
  "nickname": "阿雁",
  "registered_at": "2026-11-02T14:00:00Z"
}
```

**只返回这 4 个字段**。明确**不返回**：私钥存在性、在线状态（在线只走 WS presence）、传输数量、最近活跃、IP、设备、注册次数。未知码与"已注销"统一返回 `404 CODE_NOT_FOUND`，不区分原因。

**失败**：`404 CODE_NOT_FOUND`、`429 RATE_LIMITED`、`423 CODE_LOCKED`（失败次数锁定，见 §11.3）。

### 4.5 `PATCH /v1/codes/{code}` —— 改昵称（签名挑战）

**头**：`X-YS-*`（`purpose = NICKNAME_UPDATE`；签名输入字段串 = `CODE(4 ASCII) ‖ u16be(NICK_LEN) ‖ NICKNAME(UTF-8)`，长度前缀不可省，逐字节定义见 §1.3）

**请求**：`{ "nickname": "阿雁·改" }` → **响应 200**：`{ "code": "AWQW", "nickname": "阿雁·改", "updated_at": "2026-11-02T15:00:00Z" }`

**失败**：`401 AUTH_SIGNATURE_INVALID`（签名与挑战里的 code 或昵称不匹配时同此码）、`401 AUTH_CHALLENGE_INVALID`、`400 NICKNAME_INVALID`。

### 4.6 `GET /v1/stats` —— 全站聚合计数（无鉴权）

**请求**：无参数、无鉴权头。

**响应 200**（字段名固定，实现按此写）：

```json
{
  "today":   { "consumed": 123, "consumed_bytes": 456789, "created": 150 },
  "total":   { "consumed": 45678, "consumed_bytes": 9876543210, "created": 50000 },
  "generated_at": "2026-11-04T07:10:00Z"
}
```

**口径（写死）**：

| 字段 | 含义 |
|---|---|
| `consumed` | 已被取走的传输数，即 `state = CONSUMED` 的记录数 |
| `consumed_bytes` | 这些被取走传输的**明文**总大小（`plaintext_size` 求和；不是密文、不含 `prelude` 与 tag） |
| `created` | 新建传输数（`POST /transfers` 成功次数）。**单独字段，不与 `consumed` 相加**——两者是不同口径，不能合成"总计" |
| `today` | 服务器 **UTC 日界**（当日 `00:00:00Z` 起）的同一口径 |
| `total` | 自部署以来（全历史）的同一口径 |
| `generated_at` | 生成本次数值的时间（UTC，RFC 3339） |

**落桶时间戳（写死，与上表的 UTC 日界配套）**：日界是 UTC 已经写死，但"哪一天"按**哪个时间戳**落桶还必须说清，否则跨零点会错桶、对账会假报警：

- `consumed` / `consumed_bytes` 按 **`terminal_at`** 落桶（取走发生在哪一天，而不是建包在哪一天）；
- `created` 按 **`created_at`** 落桶；
- 区间是**半开** `[当日 00:00:00Z, 次日 00:00:00Z)`——同一时刻只落一个桶，不重不漏；对账 MUST 用同一组时间戳与同一区间（`adr/0002-stats-and-audit-retention.md` §2.3）。

（UTC 折算与"回填 / 运行时同口径"的要求见本节上文「日界实现约束」，此处不重复。）

**缓存**：响应 MUST 带 `Cache-Control: no-store`、`CDN-Cache-Control: no-store`、`Surrogate-Control: no-store`（避免中间层缓存把数字冻住）。服务端可内部缓存**≤ 60 秒**，因此**数值可能有 ≤60s 延迟**，不保证与同一时刻的 `GET /transfers/{id}` 逐笔吻合。

**隐私**：只返回**聚合数字**，不含任何个例信息（无码、无 `transfer_id`、无昵称、无大小分布）。展示层可做量级化（如"约 45 万次"），服务端返回的是**精确值**。

**参数**：不接受任何查询参数；出现未知参数 → `400 BAD_REQUEST`（§0.1 全局约定）。

**日界实现约束**：`today` MUST 按 UTC 计算，且 MUST NOT 依赖数据库会话时区（`::date` 强转会吃会话 `TimeZone`）。实现须显式 UTC 化（`(ts AT TIME ZONE 'UTC')::date`，或连接级固定 `TimeZone=UTC`）；**回填与运行时累加必须同一口径**，否则同一天的数字会跨零点错桶（回填按 `terminal_at::date`、运行时按进程 UTC 日，两者在非 UTC 会话下不一致）。

**审计**：该端点**匿名且会被首页轮询**，MUST NOT 每请求写一条审计行（实测：20 次匿名请求 → 20 行 `audit_events`；而 `audit_events` 当前无保留期，等于把首页流量线性写进库）。审计口径见 `adr/0002-stats-and-audit-retention.md`。

**对账**：计数器是**派生数据**，以 `transfers` 实际行为准；MUST 有每日对账（`count(*)`/`sum(plaintext_size)` 与计数器比对，偏差 > 0.1% 报警）。没有对账时"漏加/重放"不会被发现。

**失败**：`503 SERVICE_UNAVAILABLE`（统计不可用，如后端查询超时）。**不返回** `401`——该端点无鉴权，也不因缺头而拒绝。

---

---

## 5. 传输生命周期与状态机

### 5.1 状态

```
        POST /transfers            all chunks + prelude 齐
(空) ─────────────────► UPLOADING ─────────────────────► READY
                                  POST /complete            │
                                                            │ 首次 GET /prelude
                                                            ▼
                                                         LEASED
                                                            │ POST /ack
                                                            ▼
                                                        CONSUMED（密文删除）

任一非终结态 ──POST /revoke──► REVOKED（密文删除）
任一非终结态 ──TTL 到期──────► EXPIRED（密文删除）
ack 后 download_count 达 max_downloads ──► CONSUMED（密文删除）
```

`LEASED` 的租约默认 30 分钟。租约到期未 `ack`：回到 `READY`（不扣次数），已下载的密文不追回（客户端本地已有）。

**下载计数口径（唯一，全文以此为准）**：`download_count` 只在 `POST /ack` **成功**时 +1；`LEASED` 期间不变，租约过期回 `READY` 也不变。只有当 `download_count == max_downloads` 时才转 `CONSUMED`（并删密文）。因此 `LEASED` 的合法组合恒为 `0 ≤ download_count < max_downloads`（`max_downloads = 1` 时即 `download_count = 0`）。

### 5.2 状态到 API 表现的映射（**写死**）

| `state` | `GET /transfers/{id}` | `GET /prelude`、`GET /chunks/{i}` | 说明 |
|---|---|---|---|
| `UPLOADING` | 200，`state: "UPLOADING"` | `409 TRANSFER_NOT_READY` | 发送方还在传 |
| `READY` | 200 | 200 | 可下载 |
| `LEASED` | 200，含 `lease_expires_at`；`download_count` 不变 | 200（需同一 `download_id`） | 下载中（不扣次数） |
| `REVOKED` | 200（tombstone） | **`410 TRANSFER_REVOKED`** | 主动撤回 |
| `EXPIRED` | 200（tombstone） | **`410 TRANSFER_EXPIRED`** | TTL 到期 |
| `CONSUMED` | 200（tombstone） | **`410 TRANSFER_CONSUMED`** | 取件完成/次数用尽 |
| 不存在 | `404 TRANSFER_NOT_FOUND` | 同上 | id 本身无效 |

**TTL 判定在读写路径上即时生效（写死）**：判定时刻是**每次请求的服务器时间**，`expires_at <= now` 即视为 `EXPIRED`，不依赖后台清理任务的扫描周期（清理任务只是兜底重试物理删除）。因此：

- 到期后的**第一次** `GET /transfers/{id}` 就返回 `EXPIRED` tombstone（`terminal_reason: "EXPIRED"`、`terminal_at` = 该次请求时间，`expires_at` 保留**原始**到期时刻、不被改写）。
- 到期后 `GET /prelude` / `GET /chunks/{i}` 一律 `410 TRANSFER_EXPIRED`；上传侧的 `GET status`、`PUT prelude`、`PUT chunks/{i}`、`POST complete` 同样是 `410 TRANSFER_EXPIRED`（**不是** `401 AUTH_TOKEN_EXPIRED`：传输终结不可恢复，重签发凭据也救不回来，二者不得混用，见 §1.7.4）。
- `GET /inbox` **不返回**已到 `expires_at` 的条目（即使后台还没扫到该行）。
- 到期后的 `POST /ack` → `410 TRANSFER_EXPIRED` 且**不计数**（`download_count` 不变）；到期后的 `POST /revoke` → `409 TRANSFER_STATE_CONFLICT`（与 §6.7 一致）。

tombstone 只保留 §2.1 的元数据字段（**不含任何密文**）；响应里带 `terminal_reason` ∈ `REVOKED | EXPIRED | CONSUMED`。

**保留与脱敏（写死）**——与上段「TTL 即时判定」是**两件不同的事**，互不覆盖：上段定「**到期与否**」（由请求时刻判定，即时生效），本段定「**终结后留多久**」（行不删、只脱敏）。到期不因保留期长而延迟，保留也不因到期而缩短。

- **终结记录永久保留**（不再有 7 天清理期）。因此对已终结的 `transfer_id` 查询**恒为 `200` + tombstone**，不会因为时间推移变成 `404`。
- **终结后 30 天，三个字段置 `NULL` 脱敏**：`uploader_ip`、`prelude_sm3`、`upload_token_sm3`；其余字段（`created_at`、`expires_at`、`terminal_at`、`plaintext_size`、`chunk_count`、`state`、`terminal_reason`、`download_count`）**永久保留**，用于聚合计数与审计。
- **保留 ≠ 可取件**：`REVOKED`/`EXPIRED`/`CONSUMED` 三种终结态下，`GET /prelude` 与 `GET /chunks/{i}` 一律 `410`（见上表），与保留期无关。
- **脱敏不改变任何响应字段集**：tombstone 响应本来就不含 `prelude_sm3`（§7.2 已写死字段集），`uploader_ip`/`upload_token_sm3` 从未对外返回；因此 30 天脱敏对客户端**不可观测**，客户端 MUST NOT 依赖这三列的任何取值。
- **脱敏不影响限流**：按 IP 的存储配额只核算**尚未终结**（`UPLOADING`/`READY`/`LEASED`）的传输——终结态密文已物理删除，不计入占用。因此 `uploader_ip` 在终结满 30 天被置 NULL，对限流与配额核算**无影响**。

### 5.3 三种终结态的语义差异（客户端处置）

| 终结态 | 触发者 | 客户端话术 | 客户端动作 |
|---|---|---|---|
| `REVOKED` | 发送方点"撤回" | "对方已撤回" | 停止重试，清理本地半成品 |
| `EXPIRED` | 服务端 TTL | "已过期（未在 N 小时内取走）" | 同上，提示发送方重发 |
| `CONSUMED` | 接收方 `ack` 或次数用尽 | "已被取走" | 同上 |

三者**不允许**互相转换。对**同一终态**重复调用幂等（`revoke` on `REVOKED`、`ack` on `CONSUMED` → 200）；跨终态调用（如在 `EXPIRED` 上传 `ack`）→ `409 TRANSFER_STATE_CONFLICT`。

---

## 6. 发送方接口

### 6.1 `POST /v1/transfers`

**头**：`X-YS-Code`（发送方）、`X-YS-Challenge-Id`、`X-YS-Signature`（`TRANSFER_CREATE`）、`Idempotency-Key`（建议，见 §6.2）

**请求**

```json
{
  "recipient_code": "WTJF",
  "plaintext_size": 5,
  "chunk_size": 1048576,
  "chunk_count": 1,
  "prelude_len": 485,
  "prelude_sm3": "hiXsWHdEyqe99H9lEg3Fzju0HZ3ccsH8CiEiShqBQXk",
  "ttl_seconds": 86400,
  "max_downloads": 1
}
```

| 字段 | 必填 | 约束 |
|---|---|---|
| `recipient_code` | 是 | 4 字符，必须已注册（否则 `404 CODE_NOT_FOUND`） |
| `plaintext_size` | 是 | 0..4294967296 |
| `chunk_size` | 是 | 16..1048576；服务端不强制等于 1048576（格式允许，见 CRYPTO-PACK §6.1） |
| `chunk_count` | 是 | 必须等于 `ceil(plaintext_size / chunk_size)`，否则 `400 CHUNK_COUNT_MISMATCH` |
| `prelude_len` | 是 | 1..4194304 |
| `prelude_sm3` | 是 | 32 字节；服务端只用于完整性核对与幂等 |
| `ttl_seconds` | 否 | 默认 86400，服务端夹到 `[3600, 86400]` |
| `max_downloads` | 否 | 默认 1，服务端夹到 `[1, 3]` |

**响应 201**

```json
{
  "transfer_id": "9f2c1a7b4e5d4308b6c7d8e9f0a1b2c3",
  "state": "UPLOADING",
  "upload_token": "Yk3m0Qq8mZ2xW7pC1vB4tY6uI9oP0aS3dF5gH7jK1lM",
  "chunk_size": 1048576,
  "chunk_count": 1,
  "prelude_len": 485,
  "download_count": 0,
  "max_downloads": 1,
  "created_at": "2026-11-02T14:00:00Z",
  "expires_at": "2026-11-03T14:00:00Z"
}
```

### 6.2 幂等（`POST /transfers`）

带 `Idempotency-Key`（base64url 16..32 字节）时，服务端 MUST 在 **600 秒**内把同 key 的重复请求折叠为同一 `transfer_id` 与同一 `upload_token`（HTTP 200 而非 201，body 相同）。key 相同但请求体不同 → `409 TRANSFER_STATE_CONFLICT`。

### 6.3 `PUT /v1/transfers/{id}/prelude`

| 项 | 值 |
|---|---|
| 头 | `X-YS-Upload-Token: <token>`、`Content-Type: application/octet-stream` |
| 体 | prelude 原始字节（`HEADER ‖ SENDER_PUB ‖ WRAPPED_KEY ‖ MANIFEST_SEC ‖ SIG_SEC`，见 CRYPTO-PACK §4.3） |
| `Content-Length` | MUST 等于创建时的 `prelude_len`，否则 `400 LENGTH_MISMATCH` |
| 服务端校验 | 只算 `SM3(body)` 与 `prelude_sm3` 比对；不符 → `400 PRELUDE_DIGEST_MISMATCH`；**不解析内容** |

**响应**：首次 `201`

```json
{ "prelude_len": 485, "prelude_sm3": "hiXsWHdEyqe99H9lEg3Fzju0HZ3ccsH8CiEiShqBQXk" }
```

幂等重复（内容完全相同）→ `204 No Content`；内容不同 → `409 PRELUDE_CONFLICT`（服务端 MUST NOT 覆盖：prelude 被发送方签名绑定，覆盖等于换包）。

### 6.4 `PUT /v1/transfers/{id}/chunks/{index}`

| 项 | 值 |
|---|---|
| 路径参数 | `index`：`0 .. chunk_count-1`，越界 → `400 CHUNK_INDEX_OUT_OF_RANGE` |
| 头 | `X-YS-Upload-Token`、`Content-Type: application/octet-stream` |
| 体 | 块切片 = `CHUNK_CT ‖ TAG`，**不含 16 字节块头**（块头由接收方重建，见 CRYPTO-PACK §6.3） |
| 长度 | MUST 等于 `PT_LEN(index)+16`；末块按 `plaintext_size - chunk_size*(chunk_count-1)` 计算；不符 → `400 LENGTH_MISMATCH` |
| 幂等 | 同 index 已有**同长度且同 `SM3`** → `204`；不同 → `409 CHUNK_CONFLICT`（不允许覆盖） |

**响应 201**

```json
{ "index": 0, "length": 21, "received_chunks": 1, "chunk_count": 1 }
```

服务端**不解析**块内容；只存 `(transfer_id, index, length, ciphertext_sm3, blob)`。

### 6.5 `GET /v1/transfers/{id}/status` —— 断点续传进度

**头**：`X-YS-Upload-Token`

**响应 200**

```json
{
  "transfer_id": "9f2c1a7b4e5d4308b6c7d8e9f0a1b2c3",
  "state": "UPLOADING",
  "chunk_count": 3,
  "chunk_size": 32,
  "prelude_received": true,
  "received_chunks": 2,
  "bitmap": "wA",
  "missing": [ { "start": 2, "count": 1 } ],
  "uploaded_bytes": 96,
  "updated_at": "2026-11-02T14:01:10Z"
}
```

- `bitmap`：每块 1 bit，**第 i 块的 bit 位于第 `i/8` 字节的 `bit (7 - i%8)`（MSB 优先）**，长度 `ceil(chunk_count/8)` 字节，base64url 无填充。示例 `"wA"` = `11000000` → 块 0、1 已收到。
- `missing`：连续缺失区间，按 `start` 升序。
- 这个接口同时是"切换传输路径后已传块不重传"的依据：切直传前先拉一次，只发 `missing`。

### 6.6 `POST /v1/transfers/{id}/complete`

**头**：`X-YS-Upload-Token`，无请求体。

| 响应 | 含义 |
|---|---|
| `200 { "state": "READY", "expires_at": "..." }` | prelude 与全部块齐备 → 通知接收方（WS `TRANSFER_NOTICE`） |
| `409 CHUNKS_MISSING` + `error.details.missing`（槽位定义见 §0.2） | 还有块没传 |
| `409 PRELUDE_MISSING` | prelude 没传 |
| `409 TRANSFER_STATE_CONFLICT` | 已 `READY` 之后重复调用以外的非法转换 |

### 6.7 `POST /v1/transfers/{id}/revoke`

**头**：`X-YS-Code`（发送方）、挑战签名（`TRANSFER_REVOKE`）。

**响应 200**：`{ "state": "REVOKED", "terminal_reason": "REVOKED", "terminal_at": "2026-11-02T14:10:00Z" }`

- 对 `REVOKED` 幂等返回 200；对 `EXPIRED` / `CONSUMED` → `409 TRANSFER_STATE_CONFLICT`。
- 撤回后服务端 MUST 立刻删除 `prelude` 与所有块（不是标记删除）。
- 只有 `sender_code` 能撤回（签名里的 code 必须等于该传输的发送方）。

---

## 7. 接收方接口

### 7.1 `GET /v1/inbox`

**头**：`X-YS-Code`（接收方）、挑战签名（`INBOX_LIST`）。查询参数：`state`（默认 `ready`）、`limit`（默认 20，最大 50）、`cursor`。

| `state` | 返回哪些状态 |
|---|---|
| `ready`（默认） | `READY` + `LEASED`（收件人现在就能取） |
| `all` | 另含 `UPLOADING`（发送方还在传，仅供进度展示）；**永不返回** `REVOKED` / `EXPIRED` / `CONSUMED` |

**响应 200**

```json
{
  "items": [
    {
      "transfer_id": "9f2c1a7b4e5d4308b6c7d8e9f0a1b2c3",
      "sender_code": "AWQW",
      "sender_nickname": "阿雁",
      "recipient_code": "WTJF",
      "plaintext_size": 5,
      "chunk_size": 1048576,
      "chunk_count": 1,
      "prelude_len": 485,
      "created_at": "2026-11-02T14:00:00Z",
      "expires_at": "2026-11-03T14:00:00Z",
      "state": "READY"
    }
  ],
  "next_cursor": null
}
```

列表里**没有**文件名/MIME —— 它们只在 prelude 的加密清单里。因此弹窗只能显示"来自 `AWQW`（阿雁）、5 字节、1 块"；**文件名与类型必须先取 prelude 并解密才看得到**。

鉴权是必须的：否则任何人枚举码就能看到"谁给谁发了多大的东西"。

### 7.2 `GET /v1/transfers/{id}`

持有 `transfer_id` 即可（能力凭证）。返回 §2.1 白名单字段 + `state`。

**响应 200**

```json
{
  "transfer_id": "9f2c1a7b4e5d4308b6c7d8e9f0a1b2c3",
  "sender_code": "AWQW",
  "sender_nickname": "阿雁",
  "recipient_code": "WTJF",
  "plaintext_size": 5,
  "chunk_size": 1048576,
  "chunk_count": 1,
  "prelude_len": 485,
  "prelude_sm3": "hiXsWHdEyqe99H9lEg3Fzju0HZ3ccsH8CiEiShqBQXk",
  "total_ciphertext_bytes": 522,
  "download_count": 0,
  "max_downloads": 1,
  "created_at": "2026-11-02T14:00:00Z",
  "expires_at": "2026-11-03T14:00:00Z",
  "state": "LEASED",
  "lease_expires_at": "2026-11-02T14:30:00Z"
}
```

终态（tombstone）仍返回 `200`，字段集**固定**为：`transfer_id`、`sender_code`、`sender_nickname`、`recipient_code`、`plaintext_size`、`chunk_size`、`chunk_count`、`prelude_len`、`total_ciphertext_bytes`、`download_count`、`max_downloads`、`created_at`、`expires_at`、`state`、`terminal_reason`、`terminal_at`；**不再返回** `prelude_sm3` 与 `lease_expires_at`（密文已删、租约已终止）。

### 7.3 `GET /v1/transfers/{id}/prelude` —— 开启下载租约

| 项 | 值 |
|---|---|
| 响应 200 | 原始字节，`Content-Length = prelude_len`，`Accept-Ranges: bytes` |
| 响应头 | `X-YS-Download-Id: <32 hex>`、`X-YS-Lease-Expires-At: <RFC3339>`、`X-YS-State: LEASED` |
| 副作用 | 状态 `READY → LEASED`（幂等：已有有效租约则沿用同一 `download_id` 并刷新到期时间） |
| Range | 支持单区间（§8） |

### 7.4 `GET /v1/transfers/{id}/chunks/{index}`

| 项 | 值 |
|---|---|
| 头 | `X-YS-Download-Id: <先前拿到的>`；缺失 → `409 DOWNLOAD_NOT_STARTED`；租约过期（30 min）→ `401 AUTH_TOKEN_EXPIRED`；`KID` 轮换后 → `401 AUTH_TOKEN_STALE`（§1.7.4，重新 `GET /prelude` 取新租约） |
| 响应 200 | 块切片原始字节（`PT_LEN+16` 字节），`Accept-Ranges: bytes` |
| Range | 支持单区间（§8） |
| 乱序 | 任意顺序请求，服务端不做顺序约束（顺序由端侧 AAD 保证） |
| 响应头（非契约扩展） | 实现可附加 `X-YS-Ciphertext-Sm3`（base64url，对 `CHUNK_CT ‖ TAG` 求 SM3）供调试；**客户端 MUST NOT 依赖**它做完整性判断（完整性由 AEAD tag + 清单摘要保证，见 `CRYPTO-PACK.md` §7.5） |

### 7.5 `POST /v1/transfers/{id}/ack` —— 取件完成

**头**：`X-YS-Code`（接收方）、挑战签名（`TRANSFER_ACK`；签名输入字段串 = `RECEIVER_CODE(4) ‖ TRANSFER_ID(32 ASCII)`，见 §1.3）、`X-YS-Download-Id`。

**响应 200**（本次 `ack` 后达到 `max_downloads`）：`{ "state": "CONSUMED", "terminal_reason": "CONSUMED", "terminal_at": "...", "download_count": 1 }`

- 计数口径见 §5.1：`ack` 是**唯一**扣数时机（`LEASED` 期间不扣）。
- `ack` 成功 → `download_count += 1`。若 `download_count < max_downloads`：状态回 `READY`，响应 `{ "state": "READY", "download_count": N, "remaining_downloads": max_downloads - N }`，密文**不删**；达到 `max_downloads` 才转 `CONSUMED` 并在响应前完成物理删除。
- 幂等键是 `X-YS-Download-Id`：**同一 `download_id` 的重复 `ack` 只计一次**并返回 200；只有拿到新租约（新 `download_id`）后再 `ack` 才会再 +1。

### 7.6 `HEAD /v1/transfers/{id}/chunks/{index}`

用于"我这边到底缺哪块"的探测：存在 → `200`（带 `Content-Length`）；不存在 → `404 CHUNK_NOT_FOUND`；终态 → `410`。

> 接收端的**续传进度存在本地**（IndexedDB），服务端不保存"接收方进度"——多存一份状态就多一个可探测面。跨设备/清缓存后重来，按 §7.3 重新拿租约、按 `HEAD` 探块补齐即可。

---

## 8. Range、幂等与续传（汇总）

### 8.1 Range 支持

| 端点 | 支持 | 规则 |
|---|---|---|
| `GET /prelude` | 是 | 单区间 `Range: bytes=a-b`（闭区间，相对 prelude 起点） |
| `GET /chunks/{index}` | 是 | 单区间，相对该块切片起点 |
| JSON 端点 | 否 | 返回 `Accept-Ranges: none` |

- 命中 → `206 Partial Content` + `Content-Range: bytes a-b/total`。
- 越界 → `416 RANGE_NOT_SATISFIABLE` + `Content-Range: bytes */total`。
- 多区间（`bytes=0-1,3-4`）→ `400 RANGE_UNSUPPORTED`（不做 multipart/byteranges，省一类解析面）。
- 推荐用法：**整块重传**（块只有 1 MiB），Range 仅用于弱网大块重试。

### 8.2 幂等性矩阵

| 操作 | 幂等 | 冲突时 |
|---|---|---|
| `PUT prelude` | 是（同 `SM3` → 204） | `409 PRELUDE_CONFLICT` |
| `PUT chunks/{i}` | 是（同长度同 `SM3` → 204） | `409 CHUNK_CONFLICT` |
| `POST /transfers` | 是（靠 `Idempotency-Key`，600s） | `409 TRANSFER_STATE_CONFLICT` |
| `POST /complete` | 是（重复 → 200） | — |
| `POST /ack` | 是（重复 → 200） | — |
| `POST /revoke` | 是（重复 → 200） | 终态非 REVOKED → `409` |
| `POST /report` | 是（同人同包重复 → `202` + 同一 `report_id`，不重复计数） | — |

### 8.3 切换传输路径（中转 ↔ 直传）时的续传

1. 拉 `GET /status`（发送方）或本地记录（接收方）得到已完成的块集。
2. 只补齐缺失块，块序号空间完全一致，**已传块不重传**。
3. 直传走 `RTCDataChannel`，帧格式 `YS-DC/1`：

```
u32be index ‖ u32be length ‖ length 字节（CHUNK_CT ‖ TAG）
```

4. 直传中断 → 剩余块自动回到 HTTP 中转，**不重传已完成块**，UI 只提示一句"已切回中转"。

---

## 9. 直传信令（WebSocket）

### 9.1 连接与鉴权

1. `wss://<host>/v1/ws` 建立连接。
2. 客户端 MUST 在 **10 秒**内发送首帧 `HELLO`（含 `WS_HELLO` 签名）；否则服务端关闭，close code `4408`；`HELLO` 验签失败则关闭 `4401`。
3. 服务端回 `HELLO_OK`，连接进入已认证态；未认证前发任何其它帧 → 关闭 `4401`。
4. 限速与帧上限见 §9.4（每连接 40 帧/秒、突发 80；单帧 ≤ 64 KiB）。

### 9.2 消息信封

```json
{ "type": "RTC_OFFER", "seq": 42, "ts": "2026-11-02T14:00:00Z", "payload": { } }
```

- `type`：大写下划线常量（见 §9.3）。
- `seq`：服务端下发的 `seq` 在单连接内单调递增（从 1 开始）；客户端可省略。
- 未知 `type`：接收方 MUST 忽略（不报错、不断连），这是信令扩展的唯一兼容手段。

### 9.3 消息类型

| 方向 | `type` | `payload` | 说明 |
|---|---|---|---|
| C→S | `HELLO` | `{code, challenge_id, signature, client:{platform, version}}` | 首帧，`WS_HELLO` 签名 |
| S→C | `HELLO_OK` | `{code, server_time, heartbeat_ms: 25000}` | 认证成功 |
| S→C | `ERROR` | `{code, message, fatal}` | `fatal: true` 时随后关闭 |
| C→S | `PING` | `{}` | 每 25 s 一次 |
| S→C | `PONG` | `{}` | — |
| C→S | `PRESENCE_SUBSCRIBE` | `{codes: ["WTJF", ...]}` | 并发订阅 ≤ **8** 个码；**新增订阅** ≤ **2 码/秒**（见下方限速） |
| S→C | `PRESENCE_SNAPSHOT` | `{entries:[{code, online}]}` | 订阅回执 |
| S→C | `PRESENCE_CHANGED` | `{code, online}` | 上线/掉线推送 |
| S→C | `TRANSFER_NOTICE` | `{transfer_id, sender_code, sender_nickname, plaintext_size, chunk_count, expires_at}` | 有新传输可收 |
| S→C | `TRANSFER_STATE` | `{transfer_id, state, terminal_reason?}` | 状态变化（撤回/过期/被取走）。**v1 未实现**（见 §15） |
| C→S | `INBOX_SYNC` | `{}` | 主动拉一次。**v1 未实现**（见 §15） |
| S→C | `INBOX_SNAPSHOT` | `{items:[...]}` | 结构同 §7.1。**v1 未实现**（见 §15） |
| C→S | `RTC_OFFER` | `{transfer_id, to_code, sdp}` | 发起直传 |
| S→C | `RTC_OFFER` | `{transfer_id, from_code, sdp}` | 转发 |
| C→S | `RTC_ANSWER` | `{transfer_id, to_code, sdp}` | 应答 |
| S→C | `RTC_ANSWER` | `{transfer_id, from_code, sdp}` | 转发 |
| C→S | `RTC_ICE` | `{transfer_id, to_code, candidate:{candidate, sdp_mid, sdp_mline_index}}` | 候选 |
| S→C | `RTC_ICE` | `{transfer_id, from_code, candidate:{...}}` | 转发 |
| C→S | `RTC_BYE` | `{transfer_id, to_code, reason: "done" / "failed" / "cancelled"}` | 结束 |
| S→C | `PEER_UNREACHABLE` | `{transfer_id, code}` | 对方不在线/信令投递失败 |

> 表里标 **v1 未实现** 的帧类型属排期项（§15 是唯一排期清单），服务端当前既不发送也不接受；客户端 MUST 按 §9.2 的"未知 `type` 忽略"处理，不要依赖它存在。

> 在线表与 `TRANSFER_NOTICE` 已实现：建包成功时若收件人在线，服务端推送 `TRANSFER_NOTICE`；离线则不发，收件方靠 §7.1 的 `inbox` 拉取。

**`PRESENCE_SUBSCRIBE` 的两条硬限（写死）**：

- **并发订阅上限 8 个码**（单连接）。订阅集超过 8 个码 → 整帧拒绝，回 `ERROR{code:"RATE_LIMITED", fatal:false}`。
- **新增订阅速率 ≤ 2 码/秒**（单连接，令牌桶，突发按 1 秒额度）。计数口径是**新增**：重复订阅已在集合内的码**不计数**（幂等重发不会触发限速）；一次请求里带多个码，按"本次真正新增的码数"扣额度。
- 两种超限都**只拒该帧**：`fatal:false`、**连接保持**、**已有订阅不清空**（不会因为一次越限丢掉此前的在线状态）。
- 为什么不放宽：4 位 Crockford 码空间只有 `32^4 = 1,048,576` 个码，若不限订阅，单连接按 40 帧/秒 × 32 码就能到 ≈1280 码/秒，**约 13 分钟即可把整个码空间扫一遍**、拿到全站在线状态（谁注册了、谁此刻在线）。订阅限速与并发上限就是为堵这个枚举面；**MUST NOT** 为了"方便批量订阅"把它调回去。

- **单帧上限 32 个码（与"并发 ≤8"不是同一件事，别混）**：一帧里带超过 **32** 个码时，按出现顺序**保留前 32 个、尾部静默忽略**（不报错、不断连）。`32` 是**单帧解析上限**，`8` 是**连接内订阅集合上限**，两者独立。
- **并发上限是整帧拒绝，不做部分接受**：若"已有订阅数 + 本次新增数" > 8，**整帧被拒**（`ERROR{RATE_LIMITED, fatal:false}`），不会"先收满 8 个、再丢掉剩下的"——避免客户端拿到"部分成功"的歧义状态。
- **帧内非法码**：长度 ≠ 4 的码**只丢该码**（帧内其余码照常处理、不报错、不断连）；帧内重复出现的码去重后只算一次；长度合法但未注册的码视为离线（`online:false`），不报错。
- **订阅集不持久**：订阅集随连接关闭即清空，**不提供持久订阅**（没有"重连后自动恢复订阅"的语义）。为什么：若允许持久订阅，订阅 8 个码后就能长期、跨会话观测这些码的上下线节奏——等于把"在线状态"做成了长期监控（谁几点在线、是否活跃），这已经超出"本次传输需要知道对端在不在"的用途。需要时重新 `PRESENCE_SUBSCRIBE` 即可，成本只是一帧。


### 9.4 信令转发规则

- 服务端校验：连接已认证的会话码必须等于该 `transfer_id` 的 `sender_code`，`to_code` 必须等于 `recipient_code`（或反之：接收方回 `ANSWER`/`ICE` 时身份对调）。不符 → `ERROR{code:"SIGNAL_PEER_MISMATCH"}`，该次直传尝试作废（对应 §10.1 的同名常量）。
- 服务端**只做字符串转发**：不解析 SDP、不记录 SDP/候选（SDP 含内网地址与 IP，属敏感元数据）。
- 对端不在线 → `PEER_UNREACHABLE`，客户端 MUST **静默**继续走中转（不弹错误）。
- 信令帧总大小上限 64 KiB，超出 → `ERROR{code:"SIGNAL_TOO_LARGE"}`。
- 限速：每连接令牌桶 **40 帧/秒、突发 80**；超限 → `ERROR{code:"RATE_LIMITED", fatal:true}` 并关闭连接（客户端退避后重连，MUST NOT 原地重试）。
- 帧的 `transfer_id` 缺失或非法 → `ERROR{code:"SIGNAL_PEER_MISMATCH", fatal:false}`，**保持连接**（继续读帧、不关闭、无关闭码）；`payload` 不是合法 JSON 时服务端直接忽略该帧，同样不断连。

### 9.5 不做 TURN：明确写死

- 本项目**不部署 TURN、不签发 TURN 凭据、不提供 relay 候选**，也**不做 UDP 中继**（服务端只转发信令，不转发媒体/数据）。
- 客户端 ICE 配置 **MUST** 只包含 `/v1/config` 下发的 `stun_urls`；**MUST NOT** 接受任何 `typ relay` 候选（收到即丢弃）。
- 打洞失败判定：ICE gathering 5 秒内没有 `srflx` 候选，或 `iceConnectionState` 进入 `failed` → 直接放弃直传，**不重试、不提示**。
- 直传是**用户点一下才切换**（产品决策）；客户端与服务器都 **MUST NOT** 自动切到直传。

### 9.6 WS 不可用时的降级（v1 必须支持）

v1 **已实现**信令与在线表（§9.1–§9.5）。但"WS 不可用"仍是**必须支持的降级路径**——部署方可以不下发 `ws_url`，链路也可能被代理/CDN 掐断：

| 情形 | 服务端 | 客户端 MUST |
|---|---|---|
| `config.ws_url` 为 `null`（该部署不提供信令） | 不下发 WS 地址 | 从一开始就不建连，直接走中转 |
| 连接被拒 / 握手非 `101` / 升级被代理阻断 | — | 视为**直传能力不可用**：本次会话不再尝试 WS（退避重试至多 1 次）、全部走中转、**不向用户报错** |
| 建连后 **10 秒**内未收到 `HELLO_OK`（服务端 `4408`），或收到 `4401` | 首帧超时关 `4408`；验签失败关 `4401`（§9.1） | 关闭连接，按上一条处理；**不重试同一凭据**（挑战已作废，需重新取挑战再签） |

**收件通知的降级**：没有 WS 时，接收方靠轮询 `GET /v1/inbox`（`INBOX_LIST` 签名）得知新传输。**服务端不实现任何轮询节奏**（只提供 `GET /v1/inbox` 的 cursor/limit 分页）；节奏是**客户端 MUST**：间隔 ≥ 30 秒、指数退避至 ≤ 5 分钟（避免触发 §11.1 的限速），`next_cursor` 变化即视为有更新。

**不变量**：WS 不可用时，上传、下载、续传、取件、撤回**全部功能不受影响**——直传只是加速路径（§9.5）。

---

## 10. 错误码表（唯一权威）

> 客户端必须按 `code` 分支；`message` 仅供开发者阅读。

### 10.1 4xx

| `code` | HTTP | 含义 | 客户端应如何处置 |
|---|---:|---|---|
| `BAD_REQUEST` | 400 | 请求格式/参数非法 | 修 bug；不要重试 |
| `FIELD_NOT_ALLOWED` | 400 | 出现白名单外字段（如 `filename`） | 修 bug；这是"服务端不落明文"的边界告警 |
| `CODE_FORMAT_INVALID` | 400 | 码不是 4 位合法 Crockford | 本地归一化后重试一次；仍失败则提示用户重输 |
| `NICKNAME_INVALID` | 400 | 昵称空/超长/含控制字符 | 就地提示改昵称 |
| `CHUNK_SIZE_INVALID` | 400 | `chunk_size` 越界 | 修 bug |
| `CHUNK_COUNT_MISMATCH` | 400 | `chunk_count != ceil(plaintext_size/chunk_size)` | 修 bug |
| `CHUNK_INDEX_OUT_OF_RANGE` | 400 | 块序号越界 | 修 bug |
| `LENGTH_MISMATCH` | 400 | `Content-Length` 与声明不符 | 重新计算切片长度后重试 |
| `PRELUDE_DIGEST_MISMATCH` | 400 | `SM3(body) != prelude_sm3` | 重算 prelude 并重建传输（prelude 已被签名绑定，不能改） |
| `RANGE_UNSUPPORTED` | 400 | 多区间或非法 Range | 改成单区间或整块重传 |
| `SIZE_LIMIT_EXCEEDED` | 400 | **声明值**超上限：`plaintext_size > 4 GiB`、`chunk_count > 1048576`、`prelude_len > 4 MiB` | 提示用户拆分文件 |
| `SIG_INPUT_TOO_LONG` | 400 | **防御性上限（>512 字节）触发；当前 HTTP 路径不可达**（字段级校验先行：昵称 ≤32 等），**仅库层可触发** | 客户端按字段上限本地校验，不要依赖该码 |
| `AUTH_MISSING` | 401 | 缺 `X-YS-*` 鉴权头 | 补签名后重试 |
| `AUTH_SIGNATURE_INVALID` | 401 | **仅**签名本身不被接受（伪造 DER、消息被改、公钥不符） | 检查 `SIG_INPUT` 拼接顺序与私钥/公钥配对，用同一挑战重算签名；**不要**无限重试（挑战已作废，需重新申请） |
| `AUTH_CHALLENGE_INVALID` | 401 | 挑战过期/已用/用途不符 | 重新 `POST /challenges` 后重试一次 |
| `AUTH_CODE_MISMATCH` | 401 | `X-YS-Code` 与 `SIG_INPUT` 里被签名的 `CODE(4)` 不一致 | 修 bug；用同一码重算签名 |
| `AUTH_TOKEN_INVALID` | 401 | 凭据不存在 / 格式错 / 与任何已签发凭据不匹配（§1.7.4） | 重新申领（上传 §1.7.5、下载重取租约）；不要重试同一凭据 |
| `AUTH_TOKEN_STALE` | 401 | 凭据记录的 `KID` 落后于当前版本（版本已轮换，§1.7.3） | 重新挑战 → 签名 → 取新凭据（上传 §1.7.5、下载重取租约）；**不要重算签名**；文案"凭据已过期版本，请重新获取" |
| `AUTH_TOKEN_EXPIRED` | 401 | 凭据超过自身有效期：上传 **6 小时**、下载租约 **30 分钟**（§1.7.4）；与 `410 TRANSFER_EXPIRED`（传输终结）不同 | 上传重签发（已传块不重传）、下载重取租约 |
| `SIGNAL_PEER_MISMATCH` | 403 | 信令双方与传输不匹配 | 停止该直传尝试，走中转 |
| `NOT_TRANSFER_PARTY` | 403 | 已认证（签名有效）但**不是该传输的当事人**：非接收方调 `ack`、非发送方调 `revoke` | 停止操作、不要重试；提示"这不是你的传输" |
| `CODE_NOT_FOUND` | 404 | 码未注册 | 提示"码不对或对方已换浏览器" |
| `TRANSFER_NOT_FOUND` | 404 | `transfer_id` 本身无效（不存在/格式错）。**终结记录永久保留**，不再因保留期变 `404` | 从本地列表移除 |
| `CHUNK_NOT_FOUND` | 404 | 该块不存在 | 按 §7.6 重新探块；必要时让发送方重传该块 |
| `CODE_TAKEN` | 409 | 码被占用 | **换密钥对、重算码、重试注册（≤8 次）** |
| `PUBKEY_TAKEN` | 409 | 公钥已在别的码下注册 | 清本地身份重来，或复用既有码 |
| `PRELUDE_CONFLICT` | 409 | 已存在不同的 prelude | 停止；不要覆盖（签名已绑定） |
| `CHUNK_CONFLICT` | 409 | 同块序号已有不同内容 | 停止该块重传；核对是否两条传输混了 id |
| `CHUNKS_MISSING` | 409 | `complete` 时仍有缺块 | 用 `error.details.missing`（§0.2）补传 |
| `PRELUDE_MISSING` | 409 | `complete` 时没有 prelude | 先传 prelude |
| `TRANSFER_NOT_READY` | 409 | 传输还没就绪 | 轮询/等 `TRANSFER_STATE` |
| `DOWNLOAD_NOT_STARTED` | 409 | 缺有效 `download_id` | 先 `GET /prelude` 拿租约 |
| `TRANSFER_STATE_CONFLICT` | 409 | 状态不允许该操作 | 刷新状态，别硬来 |
| `TRANSFER_REVOKED` | 410 | 已撤回 | 清理本地，停止重试 |
| `TRANSFER_EXPIRED` | 410 | 已过期 | 同上，提示重发 |
| `TRANSFER_CONSUMED` | 410 | 已被取走/次数用尽 | 同上 |
| `PAYLOAD_TOO_LARGE` | 413 | **单个请求体**超过服务端接收上限（如块切片大于声明长度、prelude 超 `prelude_len`） | 减小切片后重传该块 |
| `CONTENT_TYPE_UNSUPPORTED` | 415 | 非 `application/octet-stream` | 改用二进制体（不要 multipart） |
| `RANGE_NOT_SATISFIABLE` | 416 | Range 越界 | 从头重传该块 |
| `CODE_LOCKED` | 423 | 查码失败次数过多被锁 | 等待锁定期（见 `Retry-After`），不要继续试 |
| `RATE_LIMITED` | 429 | 触发限速 | 按 `Retry-After` 退避 |

### 10.2 5xx

| `code` | HTTP | 含义 | 客户端处置 |
|---|---:|---|---|
| `INTERNAL` | 500 | 服务端内部错误 | 5s→20s→60s 退避重试，最多 3 次 |
| `FEATURE_DISABLED` | 501 | 该部署关闭了某个可选端点（当前仅 `POST /transfers/{id}/token`，§1.7.5⑤） | 不要重试；提示"该部署已关闭凭证重签发，请重新发送"，允许重建传输 |
| `SERVICE_UNAVAILABLE` | 503 | 维护/过载 | 同上，指数退避 |
| `INSUFFICIENT_STORAGE` | 507 | 配额类：服务端整体存储不足，或该 IP 未取走密文总量超配额（见 §11.4） | 提示"稍后重试"；**不是**速率错误，不要按 `Retry-After` 循环重试 |

### 10.3 与端侧错误码的分界

`CRYPTO_*`（见 `CRYPTO-PACK.md` §13：`CRYPTO_CHUNK_AUTH_FAILED`、`CRYPTO_SIGNATURE_INVALID` 等）是**端侧**错误码，**永不上行**。服务端看不到也不会返回它们；客户端把它们映射成用户文案，不上报服务端（避免把"解密失败"这类信息变成服务端可观测信号）。

### 10.4 WS 错误码与关闭码

WS 层 `ERROR` 帧里的 `code` 复用 §10.1/§10.2 的同一套常量（如 `SIGNAL_PEER_MISMATCH`、`RATE_LIMITED`）；**仅 WS 出现**的只有两个：`SIGNAL_TOO_LARGE`（帧 > 64 KiB）与 `PEER_UNREACHABLE`（对端不在线）。

| close code | 含义 |
|---:|---|
| `1000` | 正常关闭 |
| `4401` | 未认证 / `HELLO` 验签失败 / 认证前发其它帧 |
| `4408` | 首帧超时（10 s 内未发 `HELLO`） |
| `4429` | WS 连接数超限 |
| `1013` | 服务端过载，请稍后重连（客户端退避 ≥ 5 s） |

---

## 11. 限速与反滥用

### 11.1 维度与默认额度（服务端可配，契约给出默认值）

| 维度 | 端点 | 默认额度 | 超限响应 |
|---|---|---|---|
| 按 IP | `GET /codes/{code}` | 30 次/分钟 | `429 RATE_LIMITED`（`scope: "ip"`） |
| 按 IP | `POST /challenges` | 20 次/分钟 | `429` |
| 按 IP | `GET /transfers/{id}` 及内容端点 | 120 次/分钟 | `429` |
| 按码 | `POST /transfers` | 10 次/小时 | `429`（`scope: "code"`） |
| 按码 | `PATCH /codes/{code}` | 5 次/小时 | `429` |
| 按传输 | `PUT /chunks/{i}` | 600 次/分钟 | `429`（`scope: "transfer"`） |
| 按传输 | `GET /prelude` + `GET /chunks/{i}` | 600 次/分钟 | `429` |
| 按传输 / 按码 | `POST /transfers/{id}/token` | 10 次/分钟 / 30 次/分钟 | `429`（`scope: "transfer"` / `"code"`，§1.7.5②） |
| 按 IP | 新建 WS 连接 | 10 次/分钟 | 连接被拒（HTTP 429 或 close `4429`） |
| 按码 | `POST /transfers/{id}/report` | 5 次/小时 | `429`（`scope: "code"`） |
| 按 IP | `POST /transfers/{id}/report` | 20 次/小时 | `429`（`scope: "ip"`） |

### 11.2 `429` 响应语义

```
HTTP/1.1 429 Too Many Requests
Retry-After: 12
X-YS-RateLimit-Limit: 30
X-YS-RateLimit-Remaining: 0
X-YS-RateLimit-Reset: 12
Content-Type: application/json
```

```json
{ "error": { "code": "RATE_LIMITED", "message": "too many requests", "scope": "ip", "retry_after": 12, "request_id": "req_7f3a1c9e" } }
```

- `Retry-After` 单位秒，MUST 存在；客户端 MUST 遵守（不得在窗口内重试）。
- `scope` ∈ `ip | code | transfer | ws`。
- 团队统一退避：`5s → 20s → 60s`，最多 3 次；`429` 时以 `Retry-After` 为准（取二者较大值）。

### 11.3 失败锁定（防枚举）

| 规则 | 值 |
|---|---|
| 触发 | 同一 IP 对**同一码**连续 `CODE_NOT_FOUND` 5 次 |
| 响应 | `423 CODE_LOCKED` + `Retry-After` |
| 锁定时长 | 首次 1 分钟，逐次翻倍（2/4/8…），上限 60 分钟 |
| 解锁 | 到期自动；或该码历史上成功查询过一次（降低误伤） |
| 记录 | 只记 `(ip, code, count, until)`，不记查询者其它信息 |

同理对 `AUTH_SIGNATURE_INVALID` 连续失败做按码计数（10 次/小时 → `429`，`scope: "code"`），防签名爆破。

### 11.4 其它反滥用不变量

- 单码并发未终结传输上限 20；超出 → `429`（`scope: "code"`）。
- 单 IP 未取走密文总量上限（默认 8 GiB）→ 统一 `507 INSUFFICIENT_STORAGE`（配额类，不是速率类；`429` 只用于 §11.1 的时间窗限速）。
- 举报与下架：v1 提供**举报记录**接口（`POST /v1/transfers/{id}/report`，§11.5），**举报不改变传输状态**；下架由运维在服务端执行（`state → REVOKED` + 删密文 + 保留墓碑），对外表现与用户撤回一致。人工审核、申诉、自动内容识别不在 v1（排期见 §15）。

### 11.5 举报与下架（v1 最小定义）

**端点**：`POST /v1/transfers/{id}/report`

**鉴权**：走 §1.2 的挑战/签名，新增用途 **`0x09 ABUSE_REPORT`**（§1.3）：
`SIG_INPUT = "YSAUTH1"(7) ‖ 0x09(1) ‖ NONCE(32) ‖ REPORTER_CODE(4 ASCII) ‖ TRANSFER_ID(32 ASCII 小写 hex)` = **76 字节**，两字段定长、不加长度前缀。
*为什么不复用现有用途*：举报既不是撤回（`0x04`，仅发送方）也不是取件确认（`0x07`，仅接收方），复用会让"同一 nonce 换用途"无法被检测——§1.3 要求 `purpose` 必须参与签名，用途即权限。

**请求体**：

```json
{ "reason": "ABUSE", "note": "冒充登录页" }
```

- `reason`：必填，枚举 `ABUSE` / `CSAM` / `MALWARE` / `OTHER`（大小写敏感）；其它值 → `400 BAD_REQUEST`。
- `note`：可选，UTF-8，**≤ 200 字节**；含控制字符 → `400 BAD_REQUEST`。`note` 服务端可见并原样入库，**MUST NOT** 放文件名、明文内容、身份信息。
- 未知字段 → `400 FIELD_NOT_ALLOWED`（§0.3 全局约定）。

**响应 `202`**：

```json
{ "report_id": "r_7f3a1c9e", "state": "RECORDED", "distinct_reports": 3 }
```

- `state` 在 v1 **只有** `RECORDED` 一个值（不返回 `TAKEDOWN`）。
- `distinct_reports`：该传输被多少个不同码举报过（同一码重复举报不累加）。

**幂等**：同一 `reporter_code` + 同一 `transfer_id` 只记一条；重复举报 → `202` + **同一个** `report_id`，`distinct_reports` 不变（§8.2）。

**下架语义（写死）**：**举报不改变传输状态**。服务端收到举报只做三件事：写一条举报记录、维护 `distinct_reports` 计数、记审计（只记 `route_template`，**不记** `note` 正文）。
**不做**：不改 `state`、不删密文、不通知上传者、不解析传输内容、不做人工审核。

**谁有权下架**：v1 **不提供**管理 HTTP 端点。下架由运维在服务端执行，走与用户撤回**完全相同**的终结路径——`state → REVOKED`、删除该传输的密文目录、保留墓碑行；此后任何取件/状态查询一律 `410 TRANSFER_REVOKED`（§5.2）。
*理由*：`transfer_id` 是随链接/二维码扩散的能力凭证，"任何持 id 的已认证用户举报即下架"等于给所有人一条删他人文件的路径（恶意删档 + DoS）；CSAM 这类需要即时处置的场景在 v1 走运维介入，用延迟换"不可被滥用"。运维操作本身不进契约的 HTTP 面，避免多一套管理员鉴权与凭据。

**错误与限速**：

| 情形 | 响应 |
|---|---|
| 传输不存在 / `transfer_id` 格式错 | `404 TRANSFER_NOT_FOUND` |
| 传输已终结（`REVOKED` / `EXPIRED` / `CONSUMED`） | `410` + 对应 `TRANSFER_*`（§5.2） |
| 举报自己发出的传输 | `202` 照常记录（不做特殊处理，避免泄露"请求者是不是发送方"） |
| `reason` 非法 / `note` 超长或含控制字符 / 未知字段 | `400 BAD_REQUEST` / `400 FIELD_NOT_ALLOWED` |
| 同一码 > 5 次/小时、同一 IP > 20 次/小时 | `429 RATE_LIMITED`（`scope: "code"` / `"ip"`，§11.1） |

**不新增错误码**：全部复用 §10.1 现有码，两侧 parity 仍是 14 码。新增码必须实现侧同步落地，否则 parity 会判"契约有、实现无"。

---

## 12. 安全与日志纪律（API 层可核查项）

1. 服务端 **不落明文**：唯一二进制通道是 `prelude` 与块切片，服务端不解析、不记录内容片段。
2. 日志字段白名单 = §2.1 的审计字段（含 `route_template`：只记路由模板，不记实际路径参数，避免 `transfer_id` 这类能力凭证落进日志）；`Query String` 只允许记录白名单参数名（`state/limit/cursor`），不记值之外的原文。
3. 错误响应 **不泄露**：不区分"码不存在"与"码已注销"；不返回占用者信息；不返回服务端路径/栈。
4. 密文删除是**物理删除**：`ack`、`revoke`、TTL 三条路径都必须删 `prelude` 与所有块；tombstone 只留元数据（**永久保留**，终结 +30 天后 `uploader_ip`/`prelude_sm3`/`upload_token_sm3` 置 `NULL`，§5.2）。
5. 传输加密依赖外层 HTTPS（不做国密 TLS），应用层再叠 SM4 密文；两者互不替代。
6. CORS：只允许站点自身源；不开放 `*`；不开放 `credentials`。
7. 前端零第三方脚本 + 严格 CSP（属 Web 交付，此处只作为跨端约束记录）。
8. **审计保留期与免审计端点**：`audit_events` MUST 有保留期（建议 90 天，随 sweeper 清理）；匿名只读端点（`/v1/stats`、`/v1/config`）**MUST NOT** 每请求写审计行——只保留进程访问日志。审计只覆盖**有身份或有副作用**的请求（见 `adr/0002-stats-and-audit-retention.md` §2.4）。

---

## 13. 与 `CRYPTO-PACK.md` 的对应关系

| API 概念 | CRYPTO-PACK 概念 |
|---|---|
| `prelude` 请求/响应体 | `HEADER ‖ SENDER_PUB ‖ WRAPPED_KEY ‖ MANIFEST_SEC ‖ SIG_SEC`（§4.3） |
| 块切片请求/响应体 | `CHUNK_CT ‖ TAG`（**不含** 16 字节块头，§6.3） |
| `index` 路径参数 | 块记录的 `CHUNK_INDEX`（§6.2） |
| `prelude_sm3` | `SM3(prelude)`，服务端唯一允许的"内容级"计算 |
| `plaintext_size` / `chunk_size` / `chunk_count` | `HEADER` 里的同名语义字段（服务端**不解析**头，只信客户端声明并做交叉校验） |
| `crypto_pack_version`（`/v1/config`） | `YSPK/1.0`（§2.1） |
| `transfer_id` | 与包内任何字段无关，纯服务端寻址 |
| 签名挑战 `SIG_INPUT` | 与包内签名（`SIG_INPUT` in §10.2）**是两件事**，前缀不同（`YSAUTH1` vs `YSSIG1`），互不复用 |

---

## 14. 不变量清单（评审与 Gate 用）

1. API 报文里不存在文件名、MIME、明文、密钥、私钥字段；出现即 `400 FIELD_NOT_ALLOWED`。
2. 任何二进制端点都只接受 `application/octet-stream`。
3. 服务端不解析 prelude / 块内容，只算 `SM3` 与长度。
4. 下载计数只在 `ack` 成功时 +1（`LEASED` 期间与租约过期都不扣）；`ack` 达上限、`revoke`、TTL 三条路径都物理删除密文。
5. 三种终结态在内容端点一律 `410`，且三个 `code` 互不混用。
6. `transfer_id` 是能力凭证；`upload_token` 只存 `SM3`。
7. 无 TURN：客户端 ICE 配置只有 STUN，`typ relay` 候选一律丢弃。
8. 直传切换只能由用户点击触发；失败回落**静默**、只提示一句、不重传已完成块。
9. 撞码只走"重新生成密钥对"这一条路，不自动加长码。
10. 所有 `429` 都带 `Retry-After`，所有错误都带稳定 `code`；存储/配额类错误用 `507`，不用 `429`。
11. 挑战只绑 `purpose`，不绑 code；码身份由 `SIG_INPUT` 里的 `CODE(4)` + 验签绑定（`REGISTER` 也走这条）。
12. v1 无公开举报入口，只有内部 `REVOKED` 终结态（排期见 §15）。
13. 码的归一化在任何判定之前完成，且限速/锁定按归一化后的码计数（§1.6）。
14. WS 不可用是 v1 的正常路径：上传/下载/续传/取件/撤回功能不受影响，只静默降级（§9.6）。
15. 审计只记路由模板，不记实际路径参数；`upload_token` 库内只存 `SM3`。
16. 吊销只认 `KID`（严格单调递增；**只有调小会拒绝启动**，未配置取默认 `1`/沿用记录值）：递增即旧凭据 `401 AUTH_TOKEN_STALE` 且无需重启；只换 `TOKEN_SECRET` 不吊销；凭据类三码 `STALE`/`INVALID`/`EXPIRED`，传输级终结走 410（§1.7）。

---

## 15. 未实现 / 排期（v1 不做）

本节是**唯一**的 v1 未实现清单：其它章节只写 v1 的实际行为，不再另列排期。本节列出的能力在 §3 的接口表里**没有任何端点**，也不预留路径。

| 项 | v1 口径 | 排期 |
|---|---|---|
| **1GB 级流式分块 API** | v1 只有既有的分块上传/下载：`PUT /chunks/{index}`（§6.4）、`GET /chunks/{index}`（§7.4）、`prelude` 一次性进出（§6.3 / §7.3）。服务端按块存、按块发，端侧逐块解密落盘，但**接口层不做流式端点**。上限口径看两处：单包 = `plaintext_size ≤ 4 GiB`，单块 = `chunk_size ≤ 1 MiB`，块数 = `chunk_count ≤ 1048576`（字段约束见 §6.1，包级限值见 `CRYPTO-PACK.md` §14） | 下一轮：边传边解（请求/响应体流式，无整包落内存或落盘）。只加端点与传输方式，**不改块格式与 AAD** |
| 举报的处理流程 | v1 只提供**举报记录**接口（§11.5，`202 RECORDED`）与运维下架；**不含**人工审核队列、申诉通道、自动内容识别（哈希库/模型扫描）。下架动作与用户撤回同一终结路径（§5.2） | 审核与申诉排期 v2 |
| 用户码校验字符 | 码固定 **4 位**，v1 不启用校验字符；实现可本地计算 `check_symbol()` 作输入框前置防误输提示，不上行、不改变码长度（`CRYPTO-PACK.md` §3.4） | 需要时升 5 位展示，属契约变更，需 ADR |
| WS 帧 `INBOX_SYNC` / `INBOX_SNAPSHOT` / `TRANSFER_STATE`（§9.3） | 信令与在线表已实现（§9.1–§9.5），但这三种帧**未实现**：服务端不发送、也不接受。收件方靠 §7.1 `inbox` 拉取；传输状态变化靠轮询 `GET /transfers/{id}/status` | 下一轮；帧格式已在 §9.3 定死，实现时**不需要**再改契约 |
| TURN / UDP 中继（§9.5） | **明确不做**：不部署 TURN、不签发凭据、不提供 relay 候选、不转发媒体或数据；直传只走 STUN 打洞，失败即回中转 | 无排期（产品与安全决策，见需求基线） |
