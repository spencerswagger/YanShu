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
- **防御性硬上限 `SIG_INPUT_HARD_LIMIT = 512` 字节**：长度超过它时，服务端 MUST 在解析前直接拒绝（`400 SIG_INPUT_TOO_LONG`），这是防 DoS 的最廉价一道门（避免为超长输入分配/解析）。512 只作"安全门"，**不是**合法性边界——合法上限是 109。
- **客户端义务**：发请求前 MUST 在本地按字段上限校验（昵称 ≤32 字节、码 4 位、`transfer_id` 32 字符），**不要依赖服务端兜底**；否则用户会看到"签名无效"这类误导性错误。
- 未来若新增 PURPOSE 或放宽某字段上限而使 `SIG_INPUT_MAX` 超过 109，必须同步更新本表与常数（走 ADR），并保证 `SIG_INPUT_HARD_LIMIT ≥ SIG_INPUT_MAX`。

| PURPOSE | 名称 | 字段串（按序拼接） |
|---:|---|---|
| `0x01` | `REGISTER` | `CODE(4 ASCII) ‖ PUBKEY(65)` |
| `0x02` | `NICKNAME_UPDATE` | `CODE(4 ASCII) ‖ u16be(NICK_LEN) ‖ NICKNAME(UTF-8)` |
| `0x03` | `TRANSFER_CREATE` | `SENDER_CODE(4) ‖ RECIPIENT_CODE(4) ‖ u64be(PLAINTEXT_SIZE) ‖ u32be(CHUNK_SIZE) ‖ u32be(CHUNK_COUNT) ‖ u32be(PRELUDE_LEN) ‖ PRELUDE_SM3(32)` |
| `0x04` | `TRANSFER_REVOKE` | `SENDER_CODE(4) ‖ TRANSFER_ID(32 ASCII 小写 hex)` |
| `0x05` | `INBOX_LIST` | `CODE(4 ASCII)` |
| `0x06` | `WS_HELLO` | `CODE(4 ASCII)` |
| `0x07` | `TRANSFER_ACK` | `RECEIVER_CODE(4) ‖ TRANSFER_ID(32 ASCII)` |
| `0x08` | `UPLOAD_TOKEN_ISSUE` | `SENDER_CODE(4) ‖ TRANSFER_ID(32 ASCII)` |

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
- 校验时用**当前** `TOKEN_SECRET` 重算并常量时间比对（§1.7.2）。
- `TOKEN_SECRET` 只来自部署密钥，不入库、不写日志。
- **`KID` 进派生输入**：递增 `KID` 后重签发的凭据与旧凭据逐字节不同，旧凭据不会因重签发而复活（§1.7.3）。`KID` 只作派生输入与记录元数据，**不出现在任何请求/响应字段里**，wire 格式不变。
- **两种吊销语义**：只换 `TOKEN_SECRET`（`KID` 不变）→ 旧凭据 `AUTH_TOKEN_INVALID`；递增 `KID` → 旧凭据 `AUTH_TOKEN_STALE`（§1.7.3 / §1.7.4）。

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
| `upload_token` | 写操作：`PUT prelude`、`PUT chunks/{i}`、`GET status`、`POST complete` | 单一传输 + 签发时的 KID | = 传输 `expires_at`（TTL ≤ 24 h，可配更短） | 发送方 |
| `download_id` | 下载租约：`GET chunks/{i}`、`POST ack` | 单一传输的**一次**租约 + 签发时的 KID | 30 分钟 | 接收方 |

`transfer_id` 与 token **互不替代**：前者能读密文，后者能写。用户码不是凭证（§1.1）。

#### 1.7.2 存储与校验口径

- 服务端**只存凭据的哈希**（`upload_token` 存 `SM3`），不存明文。
- `upload_token` 由令牌派生密钥 `TOKEN_SECRET` 与**凭据版本 `KID`** 确定性派生（§1.5）；`KID` 是**服务端元数据**：不出现在任何请求/响应字段、不改变 wire 格式（仍是 32 字节 base64url）。
- **校验顺序写死**：① 先比 `KID`（该传输记录的签发 `KID` vs 当前 `KID`）——不等即 `AUTH_TOKEN_STALE`；② 再用当前 `TOKEN_SECRET` 重算凭据并做常量时间比对——不符即 `AUTH_TOKEN_INVALID`。
- 因此吊销不是"删数据"，而是"版本或密钥换了、对不上"——可秒级全站生效。

#### 1.7.3 版本吊销（`KID`，v1 必配）

**`KID` 的取值规则（写死）**

- 部署**必配**凭据版本号 `KID`：**正整数**（十进制）。
- **版本只能前进**：轮换时新值 MUST **严格大于**当前值；**同一版本重启允许相等**（否则每次重启都会被自己挡住）。
- 服务端 MUST 持久化"已生效的最大 `KID`"（记为 `current`），启动时按下表校验：

| 配置值 `provided` | 启动行为 |
|---|---|
| `provided < current` | **拒绝启动**（`exit 1`），错误信息打印 `current=N, provided=M` |
| `provided == current` | 正常启动（同一版本重启） |
| `provided > current` | 正常启动，生效并把 `current` 更新为新值（新签发的凭据用新 `KID`） |

  理由：把 `KID` 调回旧值会让**已被吊销的旧凭据瞬间复活**——这是本机制最危险的误操作，必须在启动时挡住，不能靠人记得。
- **未配置 `KID` 时同样 MUST 拒绝启动**（fail closed，`exit 1`，错误信息点名该配置项）。**MUST NOT** 退化为"没有版本号就放过旧凭据"。

**吊销效果**

- 签发凭据时记录当时的 `KID`；校验时**先比 `KID`**：记录 `KID` < 当前 `KID` → 一律 `AUTH_TOKEN_STALE`（立即生效，不等过期）。
- 新签发/重签发的凭据用当前 `KID` 派生，**与任何旧凭据逐字节不同**——旧凭据不会因为重签发而复活。
- 这是**全局操作**：影响全站所有在传任务（发送中的上传会中断，需要重签发或重建传输），属**应急手段**，不作日常轮换。

**运维「一次性吊销」标准步骤（可直接照抄）**

1. 把配置里的 `YANSHU_TOKEN_KID` 改成**比当前更大的整数**（如 `1 → 2`）；需要更强隔离时**同时**更换 `TOKEN_SECRET`（可选）。
2. 重启服务（或触发等价的配置重载）。
3. 生效后**所有既有凭据立即失效**：`KID` 落后的 → `401 AUTH_TOKEN_STALE`（若同时换了 secret，仍是版本失效码，因为先比 `KID`）。
4. 客户端处置：**重新挑战 → 签名 → 取新凭据**（上传走 §1.7.5，下载重新 `GET /prelude`），**不要重算签名**；已传块不重传。
5. 记一条运维日志：`KID` 旧值 → 新值、时间、原因（应急吊销）；**不要**把 `TOKEN_SECRET` 写进日志。

**两种吊销语义必须分开写清**（同一次"换密钥"动作，结果不同）：

| 运维操作 | 旧凭据结果 | 语义 |
|---|---|---|
| **只换 `TOKEN_SECRET`**（`KID` 不变） | `401 AUTH_TOKEN_INVALID` | 凭据重算不匹配——"这不是我签发的" |
| **递增 `KID`**（`TOKEN_SECRET` 可不变） | `401 AUTH_TOKEN_STALE` | 版本已轮换——"我签发过，但版本作废了" |
| 两者都做 | `401 AUTH_TOKEN_STALE`（先比 `KID`） | 版本失效优先 |

两种都能吊销；但**只有递增 `KID` 表示"版本失效"**，只换 secret 表示"凭据不匹配"。日志与排查必须按此区分。

#### 1.7.4 失效条件与错误名（凭据类与签名类严格分开）

| 情形 | HTTP | `code` | 客户端处置 |
|---|---:|---|---|
| 缺凭证头 | 401 | `AUTH_MISSING` | 补头 |
| 凭据不存在 / 格式错 / 与任何已签发凭据不匹配 | 401 | `AUTH_TOKEN_INVALID` | 重新申领（上传见 §1.7.5；下载重新 `GET /prelude`）；**不要**重试同一凭据 |
| 下载租约过期（30 min），或凭据被端侧丢弃后重放 | 401 | `AUTH_TOKEN_INVALID` | 重新 `GET /prelude` 取新租约 |
| 凭据记录的 `KID` 落后于当前版本（版本已轮换） | 401 | `AUTH_TOKEN_STALE` | 重新挑战 → 签名 → 取新凭据（§1.7.5）；**不要重算签名**；文案"凭据已过期版本，请重新获取" |
| 传输进入终态 | 410 | `TRANSFER_REVOKED` / `TRANSFER_EXPIRED` / `TRANSFER_CONSUMED` | 停止并清理本地 |

**判定顺序写死**：先凭据（401）、后状态（410）；凭据内部**先比 `KID`、再比凭据本身**。

**两类错误不得互相顶替**（写死）：

- 凭据类**只有两个**：`AUTH_TOKEN_INVALID`（不存在 / 格式错 / 值不匹配 / 租约过期）、`AUTH_TOKEN_STALE`（`KID` 已轮换）；
- 签名类：`AUTH_SIGNATURE_INVALID`（**仅**签名本身不被接受：伪造 DER、消息被改、公钥不符）、`AUTH_CODE_MISMATCH`（码与签名不一致）。

**终值（定稿）**：凭据类**两个** —— `AUTH_TOKEN_STALE`（版本已过期，`KID` 轮换）、`AUTH_TOKEN_INVALID`（值不匹配·格式错·不存在）；签名类**一个** —— `AUTH_SIGNATURE_INVALID`（**仅**签名本身不被接受）。凭据类不设第三个名字。

> 「显式吊销列表」这类独立语义本期**不定义**：本实现没有该机制，将来若引入再单独命名，避免与 `AUTH_TOKEN_STALE` 近义混用。

**客户端处置按名字分叉**：前两个都走"重新挑战 → 签名 → 取新凭据"（**不要重算签名**，那是签名问题的解法）；只有拿到 `AUTH_SIGNATURE_INVALID` 才去查 `SIG_INPUT` 拼接、私钥与公钥是否配对。

**v1 不设凭据级的"过期"错误码（该名仅作预留、v1 不实现，登记见 `docs/contract-rulings.md` K2）**：上传凭据的有效期就是传输的 `expires_at`，到期由传输终结表达（`410 TRANSFER_EXPIRED`）；下载租约到期视为凭据失效（`AUTH_TOKEN_INVALID`）。凭据类 **MUST NOT** 另设任何"凭据过期"类错误名；与 `TRANSFER_EXPIRED` 的边界是"传输终结走 410、凭据失效走 401 两码"，两者不混用。

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
7. 补一条**只换 `TOKEN_SECRET`、不动 `KID`** 的场景：旧凭据 → 期望 `401 AUTH_TOKEN_INVALID`（与第 3 步的版本失效码区分开）。

只验证"重启后仍可用/不可用"不构成通过：必须验证"版本递增即全站失效 + 重签发恢复 + 幂等 + 两种吊销语义可分"。

#### 1.7.7 本节不定义的东西

表名/列名、`KID` 的存储方式、热载还是重启生效、是否保留上一代密钥——都属实现自由。契约只约束**行为**与**可观测结果**（错误名、HTTP 状态、可复跑用例）。

---

## 2. 服务端可见的元数据白名单（零知识边界）

### 2.1 允许服务端知道与持久化的字段（**穷举**）

| 域 | 字段 |
|---|---|
| 码 | `code`、`public_key`、`nickname`、`registered_at`、`updated_at` |
| 传输 | `transfer_id`、`sender_code`、`recipient_code`、`plaintext_size`、`chunk_size`、`chunk_count`、`prelude_len`、`prelude_sm3`、`total_ciphertext_bytes`、`created_at`、`expires_at`、`state`、`terminal_reason`、`terminal_at`、`download_count`、`max_downloads`、`uploader_ip`（派生列，仅用于按 IP 配额与反滥用）、`updated_at` |
| 块 | `transfer_id`、`index`、`length`、`ciphertext_sm3`（幂等比对用）、`stored_at` |
| 挑战 | `challenge_id`、`purpose`、`nonce`（协议数据，过期即删）、`expires_at`、`used` |
| 派生状态（服务端内部，无业务内容） | `prelude_received`、`received_chunks`（位图或行集）、`upload_token_sm3`、`uploaded_bytes`、下载租约与取件记录（`download_id`、`lease_expires_at`、`acked_at`）、幂等键映射（`idempotency_key → transfer_id`，≤600 秒） |
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
| 18 | POST | `/v1/transfers/{id}/token` | 签名 `UPLOAD_TOKEN_ISSUE` | 重签发 `upload_token`。**v1 定义并实现**；部署方可配置关闭（关闭返回 `501 FEATURE_DISABLED`，代价是吊销后需重建传输并重传）。细则见 §1.7.5 |
| 19 | WS | `/v1/ws` | 首帧签名 `WS_HELLO` | 在线状态、收件通知、直传信令。**v1 未实现**：返回 `503 SERVICE_UNAVAILABLE`，客户端按 §9.6 降级（排期见 §15） |

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
| 头 | `X-YS-Download-Id: <先前拿到的>`；缺失 → `409 DOWNLOAD_NOT_STARTED`；租约过期 → `401 AUTH_TOKEN_INVALID`；`KID` 轮换后 → `401 AUTH_TOKEN_STALE`（§1.7.4，重新 `GET /prelude` 取新租约） |
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

### 9.6 WS 不可用时的降级（v1 必须支持）

v1 的信令与在线表**未实现**（排期见 §15），所以"WS 不可用"是 v1 的正常路径，不是异常路径：

| 情形 | 服务端 | 客户端 MUST |
|---|---|---|
| `GET /v1/ws` 不可用（503 / 连接被拒 / 握手非 `101`） | 返回 `503 SERVICE_UNAVAILABLE`（错误码同 §10.2） | 视为**直传能力不可用**：本次会话不再尝试 WS（退避重试至多 1 次）、全部走中转、**不向用户报错** |
| `config.ws_url` 为 `null` | 同上 | 从一开始就不建连，直接走中转 |
| 建连后 5 秒内未收到 `HELLO_OK` | — | 关闭连接，按第一条处理 |

**收件通知的降级**：没有 WS 时，接收方靠轮询 `GET /v1/inbox`（`INBOX_LIST` 签名）得知新传输。轮询间隔 **MUST ≥ 30 秒**，并指数退避到 ≤ 5 分钟（避免触发 §11.1 的限速）；`next_cursor` 变化即视为有更新。

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
| `AUTH_MISSING` | 401 | 缺 `X-YS-*` 鉴权头 | 补签名后重试 |
| `SIG_INPUT_TOO_LONG` | 400 | `SIG_INPUT` 超过防御性硬上限 512 字节（合法上限是 109，见 §1.3） | 客户端本地按字段上限校验后重算签名；不要靠服务端兜底 |
| `AUTH_SIGNATURE_INVALID` | 401 | **仅**签名本身不被接受（伪造 DER、消息被改、公钥不符） | 检查 `SIG_INPUT` 拼接顺序与私钥/公钥配对，用同一挑战重算签名；**不要**无限重试（挑战已作废，需重新申请） |
| `AUTH_CHALLENGE_INVALID` | 401 | 挑战过期/已用/用途不符 | 重新 `POST /challenges` 后重试一次 |
| `AUTH_CODE_MISMATCH` | 401 | `X-YS-Code` 与 `SIG_INPUT` 里被签名的 `CODE(4)` 不一致 | 修 bug；用同一码重算签名 |
| `AUTH_TOKEN_INVALID` | 401 | 凭据不存在 / 与任何已签发凭据不匹配（随机串、别的传输的 token；§1.7.4） | 重新申领（上传 §1.7.5、下载重取租约）；不要重试同一凭据 |
| `AUTH_TOKEN_STALE` | 401 | 凭据记录的 `KID` 落后于当前版本（版本已轮换，§1.7.3） | 重新挑战 → 签名 → 取新凭据（上传 §1.7.5、下载重取租约）；**不要重算签名**；文案"凭据已过期版本，请重新获取" |
| `SIGNAL_PEER_MISMATCH` | 403 | 信令双方与传输不匹配 | 停止该直传尝试，走中转 |
| `NOT_TRANSFER_PARTY` | 403 | 已认证（签名有效）但**不是该传输的当事人**：非接收方调 `ack`、非发送方调 `revoke` | 停止操作、不要重试；提示"这不是你的传输" |
| `CODE_NOT_FOUND` | 404 | 码未注册 | 提示"码不对或对方已换浏览器" |
| `TRANSFER_NOT_FOUND` | 404 | 传输不存在/已物理删除 | 从本地列表移除 |
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
| 按传输 / 按码 | `POST /transfers/{id}/token` | 10 次/分钟 / 30 次/分钟 | `429`（`scope: "transfer"` / `"code"`，§1.7.5②） |
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
- 举报下架：**v1 不提供公开举报入口**，只保留内部 `REVOKED` 终结态（运营手动撤回），语义与用户撤回完全一致。排期统一记在 §15，本节不重复列排期。

---

## 12. 安全与日志纪律（API 层可核查项）

1. 服务端 **不落明文**：唯一二进制通道是 `prelude` 与块切片，服务端不解析、不记录内容片段。
2. 日志字段白名单 = §2.1 的审计字段（含 `route_template`：只记路由模板，不记实际路径参数，避免 `transfer_id` 这类能力凭证落进日志）；`Query String` 只允许记录白名单参数名（`state/limit/cursor`），不记值之外的原文。
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
12. v1 无公开举报入口，只有内部 `REVOKED` 终结态（排期见 §15）。
13. 码的归一化在任何判定之前完成，且限速/锁定按归一化后的码计数（§1.6）。
14. WS 不可用是 v1 的正常路径：上传/下载/续传/取件/撤回功能不受影响，只静默降级（§9.6）。
15. 审计只记路由模板，不记实际路径参数；`upload_token` 库内只存 `SM3`。
16. 版本吊销 = 递增 `KID`（**严格单调递增**，调小/调回 MUST 拒绝启动）：旧凭据一律 `401 AUTH_TOKEN_STALE`；只换 `TOKEN_SECRET` 不换 `KID` 则是 `AUTH_TOKEN_INVALID`；未配置 `KID` 拒绝启动；凭据类只有 `INVALID`/`REVOKED` 两码，传输级过期走 410（§1.7）。

---

## 15. 未实现 / 排期（v1 不做）

本节是**唯一**的 v1 未实现清单：其它章节只写 v1 的实际行为，不再另列排期。本节列出的能力在 §3 的接口表里**没有任何端点**，也不预留路径。

| 项 | v1 口径 | 排期 |
|---|---|---|
| **1GB 级流式分块 API** | v1 只有既有的分块上传/下载：`PUT /chunks/{index}`（§6.4）、`GET /chunks/{index}`（§7.4）、`prelude` 一次性进出（§6.3 / §7.3）。服务端按块存、按块发，端侧逐块解密落盘，但**接口层不做流式端点**。上限口径看两处：单包 = `plaintext_size ≤ 4 GiB`，单块 = `chunk_size ≤ 1 MiB`，块数 = `chunk_count ≤ 1048576`（字段约束见 §6.1，包级限值见 `CRYPTO-PACK.md` §14） | 下一轮：边传边解（请求/响应体流式，无整包落内存或落盘）。只加端点与传输方式，**不改块格式与 AAD** |
| 公开举报入口 | 无公开入口；只保留内部 `REVOKED` 终结态（运营手动撤回），语义与用户撤回一致（§11.4） | v2（职责见需求基线 §6） |
| 用户码校验字符 | 码固定 **4 位**，v1 不启用校验字符；实现可本地计算 `check_symbol()` 作输入框前置防误输提示，不上行、不改变码长度（`CRYPTO-PACK.md` §3.4） | 需要时升 5 位展示，属契约变更，需 ADR |
| 直传信令与在线表（WebSocket，§9） | `GET /v1/ws` 返回 `503 SERVICE_UNAVAILABLE`；客户端按 §9.6 静默降级到中转，收件通知改为轮询 `inbox`（≥30 秒） | 下一轮实现；消息类型已在 §9 定死，实现时**不需要**再改契约 |
