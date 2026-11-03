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

### 0.3 已锁死的边界（不重开论证）

- **无注册无登录**：身份 = 密钥对；写操作靠 **SM2 签名挑战**。
- **明确信任服务器**：不做公钥指纹核对。服务器可信，但对**文件名与明文内容**零知识。
- **不做 TURN**，只配 STUN；直传失败静默回落中转。
- 4 位 Crockford Base32 用户码；撞码时**客户端重新生成密钥对**。
- 私钥只在本机（IndexedDB），不上传、不备份、无导出接口。

---

## 1. 身份、码与鉴权

### 1.1 身份三件套

| 项 | 规格 |
|---|---|
| `code` | 4 字符，Crockford Base32 字母表 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`；由 `SM3(公钥)` 前 20 bit 派生（见 `CRYPTO-PACK.md` §3.4） |
| `public_key` | SM2 未压缩点，65 字节，base64url 无填充（编码后 87 字符） |
| `nickname` | UTF-8 NFC，1..32 字节，不允许控制字符与 `<>`，可含中英文；服务端只做长度与字符集校验，不做内容过滤以外的推断 |

### 1.2 签名挑战（所有写操作的门）

1. 客户端 `POST /v1/challenges` 拿一个一次性挑战。
2. 客户端按 §1.3 的公式拼 `SIG_INPUT`，用自己私钥 SM2 签名（SM3 + 默认 ZA，DER 编码）。
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

| PURPOSE | 名称 | 字段串（按序拼接） |
|---:|---|---|
| `0x01` | `REGISTER` | `CODE(4 ASCII) ‖ PUBKEY(65)` |
| `0x02` | `NICKNAME_UPDATE` | `CODE(4 ASCII) ‖ u16be(NICK_LEN) ‖ NICKNAME(UTF-8)` |
| `0x03` | `TRANSFER_CREATE` | `SENDER_CODE(4) ‖ RECIPIENT_CODE(4) ‖ u64be(PLAINTEXT_SIZE) ‖ u32be(CHUNK_SIZE) ‖ u32be(CHUNK_COUNT) ‖ u32be(PRELUDE_LEN) ‖ PRELUDE_SM3(32)` |
| `0x04` | `TRANSFER_REVOKE` | `SENDER_CODE(4) ‖ TRANSFER_ID(32 ASCII 小写 hex)` |
| `0x05` | `INBOX_LIST` | `CODE(4 ASCII)` |
| `0x06` | `WS_HELLO` | `CODE(4 ASCII)` |
| `0x07` | `TRANSFER_ACK` | `RECEIVER_CODE(4) ‖ TRANSFER_ID(32 ASCII)` |

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
| `upload_token` | 发送方上传侧凭证（`POST /transfers` 下发），可读写自己这条传输的上传状态 | 传输生命周期内 |

服务端只存 `SM3(upload_token)`，不存明文 token。`transfer_id` 泄漏的后果：他人可消耗你的下载次数并拿到密文（拿不到明文，因为 DK 被 `SM2` 封给接收方）——这是被显式接受的风险，写入威胁模型。

---

## 2. 服务端可见的元数据白名单（零知识边界）

### 2.1 允许服务端知道与持久化的字段（**穷举**）

| 域 | 字段 |
|---|---|
| 码 | `code`、`public_key`、`nickname`、`registered_at`、`updated_at` |
| 传输 | `transfer_id`、`sender_code`、`recipient_code`、`plaintext_size`、`chunk_size`、`chunk_count`、`prelude_len`、`prelude_sm3`、`total_ciphertext_bytes`、`created_at`、`expires_at`、`state`、`terminal_reason`、`terminal_at`、`download_count`、`max_downloads` |
| 块 | `transfer_id`、`index`、`length`、`ciphertext_sm3`（幂等比对用）、`stored_at` |
| 挑战 | `challenge_id`、`purpose`、`nonce`（协议数据，过期即删）、`expires_at`、`used` |
| 审计 | `ip`、`method`、`path`（**不含文件名**）、`status`、`bytes`、`ts`、`request_id` |

### 2.2 服务端**永不**知道、永不落盘的字段

文件名、扩展名、MIME、明文内容、明文摘要、`DK`、任何私钥、清单明文、块明文、本地路径、文件预览、缩略图。

### 2.3 强制性约束（可测）

1. **API 里根本不存在** `filename` / `mime` / `path` 这类字段。任何请求体里出现它们 → `400 FIELD_NOT_ALLOWED`。
2. 二进制端点只接受 `application/octet-stream`；`multipart/form-data`、`text/plain` 等一律 `415 CONTENT_TYPE_UNSUPPORTED`（multipart 是历史上最经典的"顺手带文件名"通道）。
3. 服务端 **MUST NOT** 解析 `prelude` / 块切片的内容（不读头、不解清单），只做长度与 `SM3` 比对。
4. 请求日志与错误日志 **MUST NOT** 记录请求体前 N 字节、`Query String` 原文（只记白名单参数名）、`Authorization` 类头、SDP 内容。
5. 删除是物理删除：`ack` / `revoke` / TTL 清理后，密文分块与 `prelude` 必须被删除；元数据可留 tombstone（见 §5.2）。
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
| 18 | WS | `/v1/ws` | 首帧签名 `WS_HELLO` | 在线状态、收件通知、直传信令 |

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

tombstone 只保留 §2.1 的元数据字段（**不含任何密文**），保留 7 天后物理删除；响应里带 `terminal_reason` ∈ `REVOKED | EXPIRED | CONSUMED`。

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
| `409 CHUNKS_MISSING` + `{ "missing": [...] }` | 还有块没传 |
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

终态时同一接口返回 200 + `state` / `terminal_reason` / `terminal_at`（tombstone），此时 `lease_expires_at`、`prelude_sm3` 不再返回（密文已删）。

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
| 头 | `X-YS-Download-Id: <先前拿到的>`；缺失/过期 → `409 DOWNLOAD_NOT_STARTED` |
| 响应 200 | 块切片原始字节（`PT_LEN+16` 字节），`Accept-Ranges: bytes` |
| Range | 支持单区间（§8） |
| 乱序 | 任意顺序请求，服务端不做顺序约束（顺序由端侧 AAD 保证） |

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
| C→S | `PRESENCE_SUBSCRIBE` | `{codes: ["WTJF", ...]}` | ≤ 32 个码 |
| S→C | `PRESENCE_SNAPSHOT` | `{entries:[{code, online}]}` | 订阅回执 |
| S→C | `PRESENCE_CHANGED` | `{code, online}` | 上线/掉线推送 |
| S→C | `TRANSFER_NOTICE` | `{transfer_id, sender_code, sender_nickname, plaintext_size, chunk_count, expires_at}` | 有新传输可收 |
| S→C | `TRANSFER_STATE` | `{transfer_id, state, terminal_reason?}` | 状态变化（撤回/过期/被取走） |
| C→S | `INBOX_SYNC` | `{}` | 主动拉一次 |
| S→C | `INBOX_SNAPSHOT` | `{items:[...]}` | 结构同 §7.1 |
| C→S | `RTC_OFFER` | `{transfer_id, to_code, sdp}` | 发起直传 |
| S→C | `RTC_OFFER` | `{transfer_id, from_code, sdp}` | 转发 |
| C→S | `RTC_ANSWER` | `{transfer_id, to_code, sdp}` | 应答 |
| S→C | `RTC_ANSWER` | `{transfer_id, from_code, sdp}` | 转发 |
| C→S | `RTC_ICE` | `{transfer_id, to_code, candidate:{candidate, sdp_mid, sdp_mline_index}}` | 候选 |
| S→C | `RTC_ICE` | `{transfer_id, from_code, candidate:{...}}` | 转发 |
| C→S | `RTC_BYE` | `{transfer_id, to_code, reason: "done" / "failed" / "cancelled"}` | 结束 |
| S→C | `PEER_UNREACHABLE` | `{transfer_id, code}` | 对方不在线/信令投递失败 |

### 9.4 信令转发规则

- 服务端校验：`X-YS-Code` 的会话码必须等于该 `transfer_id` 的 `sender_code`，`to_code` 必须等于 `recipient_code`（或反之：接收方回 `ANSWER/ICE` 时身份对调）。不符 → `403 SIGNAL_PEER_MISMATCH`。
- 服务端**只做字符串转发**：不解析 SDP、不记录 SDP/候选（SDP 含内网地址与 IP，属敏感元数据）。
- 对端不在线 → `PEER_UNREACHABLE`，客户端 MUST **静默**继续走中转（不弹错误）。
- 信令帧总大小上限 64 KiB，超出 → `ERROR{code:"SIGNAL_TOO_LARGE"}`。

### 9.5 不做 TURN：明确写死

- 本项目**不部署 TURN、不签发 TURN 凭据、不提供 relay 候选**。
- 客户端 ICE 配置 **MUST** 只包含 `/v1/config` 下发的 `stun_urls`；**MUST NOT** 接受任何 `typ relay` 候选（收到即丢弃）。
- 打洞失败判定：ICE gathering 5 秒内没有 `srflx` 候选，或 `iceConnectionState` 进入 `failed` → 直接放弃直传，**不重试、不提示**。
- 直传是**用户点一下才切换**（产品决策）；客户端与服务器都 **MUST NOT** 自动切到直传。

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
| `AUTH_MISSING` | 401 | 缺 `X-YS-*` 鉴权头 | 补签名后重试 |
| `AUTH_SIGNATURE_INVALID` | 401 | 验签失败或签名与字段不匹配 | 用同一挑战重算签名；**不要**无限重试（挑战已作废，需重新申请） |
| `AUTH_CHALLENGE_INVALID` | 401 | 挑战过期/已用/用途不符 | 重新 `POST /challenges` 后重试一次 |
| `AUTH_CODE_MISMATCH` | 401 | `X-YS-Code` 与 `SIG_INPUT` 里被签名的 `CODE(4)` 不一致 | 修 bug；用同一码重算签名 |
| `SIGNAL_PEER_MISMATCH` | 403 | 信令双方与传输不匹配 | 停止该直传尝试，走中转 |
| `CODE_NOT_FOUND` | 404 | 码未注册 | 提示"码不对或对方已换浏览器" |
| `TRANSFER_NOT_FOUND` | 404 | 传输不存在/已物理删除 | 从本地列表移除 |
| `CHUNK_NOT_FOUND` | 404 | 该块不存在 | 按 §7.6 重新探块；必要时让发送方重传该块 |
| `CODE_TAKEN` | 409 | 码被占用 | **换密钥对、重算码、重试注册（≤8 次）** |
| `PUBKEY_TAKEN` | 409 | 公钥已在别的码下注册 | 清本地身份重来，或复用既有码 |
| `PRELUDE_CONFLICT` | 409 | 已存在不同的 prelude | 停止；不要覆盖（签名已绑定） |
| `CHUNK_CONFLICT` | 409 | 同块序号已有不同内容 | 停止该块重传；核对是否两条传输混了 id |
| `CHUNKS_MISSING` | 409 | `complete` 时仍有缺块 | 用返回的 `missing` 补传 |
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
| `SERVICE_UNAVAILABLE` | 503 | 维护/过载 | 同上，指数退避 |
| `INSUFFICIENT_STORAGE` | 507 | 配额类：服务端整体存储不足，或该 IP 未取走密文总量超配额（见 §11.4） | 提示"稍后重试"；**不是**速率错误，不要按 `Retry-After` 循环重试 |

### 10.3 与端侧错误码的分界

`CRYPTO_*`（见 `CRYPTO-PACK.md` §13：`CRYPTO_CHUNK_AUTH_FAILED`、`CRYPTO_SIGNATURE_INVALID` 等）是**端侧**错误码，**永不上行**。服务端看不到也不会返回它们；客户端把它们映射成用户文案，不上报服务端（避免把"解密失败"这类信息变成服务端可观测信号）。

### 10.4 WS 错误码与关闭码

WS 层 `ERROR` 帧里的 `code` 复用 §10.1/§10.2 的同一套常量；WS 专属的只有 `SIGNAL_TOO_LARGE`（信令帧 > 64 KiB）。

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
| 按 IP | 新建 WS 连接 | 10 次/分钟 | 连接被拒（HTTP 429 或 close `4429`） |

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
- 举报下架：**v1 不提供公开举报入口**，只保留内部 `REVOKED` 终结态（运营手动撤回），语义与用户撤回完全一致；公开举报入口排期 v2（职责见需求基线 §6）。

---

## 12. 安全与日志纪律（API 层可核查项）

1. 服务端 **不落明文**：唯一二进制通道是 `prelude` 与块切片，服务端不解析、不记录内容片段。
2. 日志字段白名单 = §2.1 的审计字段；`Query String` 只允许记录白名单参数名（`state/limit/cursor`），不记值之外的原文。
3. 错误响应 **不泄露**：不区分"码不存在"与"码已注销"；不返回占用者信息；不返回服务端路径/栈。
4. 密文删除是**物理删除**：`ack`、`revoke`、TTL 三条路径都必须删 `prelude` 与所有块；tombstone 只留元数据（7 天）。
5. 传输加密依赖外层 HTTPS（不做国密 TLS），应用层再叠 SM4 密文；两者互不替代。
6. CORS：只允许站点自身源；不开放 `*`；不开放 `credentials`。
7. 前端零第三方脚本 + 严格 CSP（属 Web 交付，此处只作为跨端约束记录）。

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
12. v1 无公开举报入口，只有内部 `REVOKED` 终结态。
