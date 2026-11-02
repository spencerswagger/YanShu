# 雁书 · 服务端骨架「暂定契约」清单（待 API.md 对齐）

| 项 | 值 |
|---|---|
| 状态 | **DRAFT** — `docs/API.md` 尚未落盘，本清单是骨架期的暂定值 |
| 代码位置 | 全部集中在 `server/internal/spec/`（`api.go` / `types.go` / `errors.go` / `limits.go` / `ws.go`） |
| 对齐方式 | API.md 冻结后**只改 `internal/spec`**，业务代码不动（handlers 全部引用常量） |
| 用途 | 给 Ark 核对字段名/路径/错误码；差异项直接在本文件 §10 上勾 |
| 与 CRYPTO-PACK 的关系 | 传输切片口径已按 `CRYPTO-PACK.md` §12 实现：prelude 整段 + 块切片 `CT‖TAG`（不含 16 字节块头） |

> 一句话：**服务端从不解析 prelude 与块内容**，只当不透明字节存取；`spec` 里的名字是唯一可改点。

---

## 1. 全局约定

| 项 | 暂定值 | 备注 |
|---|---|---|
| 前缀 | `/api/v1` | 是否要 `/api` 待定 |
| JSON 字段风格 | `camelCase` | 与前端 JS 习惯一致 |
| 二进制字段 | `base64url`（无 `=` 填充，RFC 4648 §5） | 与 CRYPTO-PACK §3.2 一致 |
| 时间 | RFC 3339（UTC，带毫秒/纳秒按 Go 默认） | 待确认是否统一秒级 |
| 错误外壳 | `{"error":{"code","message","retryAfterMs","requestId"}}` | 所有非 2xx 统一 |
| 成功外壳 | 直接返回资源对象，**不套 `{data:...}`** | 待确认要不要套一层 |
| 未知字段 | 请求体出现未知字段 → `400 invalid_request` | 契约漂移当场报错 |
| 内容类型 | JSON `application/json`；密文 `application/octet-stream` | |

---

## 2. 端点清单

| # | 方法 | 路径 | 鉴权 | 作用 |
|---:|---|---|---|---|
| 1 | POST | `/api/v1/auth/challenges` | 无 | 下发一次性 nonce 与待签名消息 |
| 2 | POST | `/api/v1/auth/sessions` | 无（靠签名） | 用签名换会话令牌 |
| 3 | POST | `/api/v1/codes` | 无（靠签名挑战） | 注册用户码（码由公钥派生） |
| 4 | GET | `/api/v1/codes/{code}` | 无（严格限速） | 查公钥 + 昵称 |
| 5 | PATCH | `/api/v1/codes/{code}` | 会话 + 签名挑战 | 改昵称 |
| 6 | GET | `/api/v1/inbox` | 会话 | 收件列表 |
| 7 | POST | `/api/v1/packages` | 会话（发送方） | 创建传输包 |
| 8 | GET | `/api/v1/packages/{packageId}` | 会话（收发双方） | 包元信息 |
| 9 | PUT | `/api/v1/packages/{packageId}/prelude` | 会话（发送方） | 上传 prelude |
| 10 | GET | `/api/v1/packages/{packageId}/prelude` | 会话（收发双方） | 下载 prelude |
| 11 | PUT | `/api/v1/packages/{packageId}/chunks/{index}` | 会话（发送方） | 上传单块（幂等） |
| 12 | GET | `/api/v1/packages/{packageId}/chunks/{index}` | 会话（收发双方） | 下载单块 |
| 13 | POST | `/api/v1/packages/{packageId}/commit` | 会话（发送方） | 完成标记 / 锁定 |
| 14 | GET | `/api/v1/packages/{packageId}/progress` | 会话（收发双方） | 续传进度（位图） |
| 15 | POST | `/api/v1/packages/{packageId}/ack` | 会话（接收方） | 接收确认（扣次数、按策略删密文） |
| 16 | POST | `/api/v1/packages/{packageId}/revoke` | 会话（发送方） | 撤回（终结 + 真删） |
| 17 | GET | `/api/v1/ws` | 未实现 | 直传信令桩（501 `not_implemented`） |
| 18 | GET | `/healthz` | 无 | 健康检查 |

---

## 3. 请求 / 响应字段

### 3.1 挑战与会话

`ChallengeRequest`：`purpose`、`code`、`pubKey`、`nickname`
`ChallengeResponse`：`challengeId`、`purpose`、`nonce`、`message`、`messageEncoding`(`base64url`)、`expiresAt`
`SessionRequest`：`challengeId`、`code`、`signature`
`SessionResponse`：`sessionToken`、`code`、`expiresAt`

`purpose` 取值：`register` / `nickname` / `session`。

### 3.2 用户码

`RegisterCodeRequest`：`pubKey`、`nickname`、`challengeId`、`signature`、`code`（可选，仅一致性校验）
`CodeInfo`：`code`、`pubKey`、`nickname`、`status`、`registeredAt`、`updatedAt`、`expiresAt`
`UpdateNicknameRequest`：`nickname`、`challengeId`、`signature`

`status` 取值：`active` / `expired`。

### 3.3 包与块

`CreatePackageRequest`：`recipientCode`、`chunkCount`、`chunkSize`、`plaintextSize`、`preludeLen`、`maxDownloads`、`ttlSeconds`、`deleteOnAck`
`PackageInfo`：`packageId`、`senderCode`、`recipientCode`、`state`、`chunkCount`、`chunkSize`、`plaintextSize`、`preludeLen`、`maxDownloads`、`downloadsUsed`、`receivedChunks`、`createdAt`、`expiresAt`、`committedAt`、`terminalReason`
`PreludePutResponse`：`packageId`、`preludeLen`、`duplicate`
`ChunkPutResponse`：`packageId`、`index`、`ciphertextLen`、`receivedChunks`、`duplicate`
`ProgressResponse`：`packageId`、`state`、`preludeReceived`、`preludeLen`、`chunkCount`、`receivedChunks`、`receivedBitmap`、`receivedIndexes`、`missingIndexes`、`missingTruncated`、`downloadsRemaining`、`expiresAt`、`chunks[]`
`ChunkMeta`：`index`、`ciphertextLen`、`receivedAt`
`AckRequest`：`countsAsDownload`
`StateResponse`：`packageId`、`state`、`updatedAt`
`InboxResponse`：`packages[]`
`HealthResponse`：`status`、`apiVersion`、`contract`

> **注意**：`PackageInfo` 里**没有** `filename` / `mime` / `ext`，这不是漏写——文件名与 MIME 只存在于端侧加密清单里，从不上行。

### 3.4 状态机

```
uploading ──commit──> ready ──ack(次数用尽)──> exhausted（终结）
    │                   │
    │                   └──revoke──> revoked（终结）
    └──TTL 到期──> expired（终结）
任意终结态 ──清理任务──> purged（墓碑，密文已物理删除）
```

终结态判定函数 `spec.IsTerminalPackageState`；终结后所有块/prelude 请求一律 410。

---

## 4. 错误码（`spec/errors.go`）

| 错误码 | HTTP | 场景 |
|---|---:|---|
| `invalid_request` | 400 | 请求体/参数不合法、未知字段 |
| `invalid_code` | 400 | 码不是 4 位 Crockford Base32 |
| `code_not_found` | 404 | 码未注册 |
| `code_expired` | 410 | 码已过期（需换密钥对重注册） |
| `code_taken` | 409 | 码已被别人的公钥占用（撞码） |
| `code_mismatch` | 400 | 客户端自报的码与公钥派生结果不一致 |
| `pubkey_invalid` | 400 | 公钥不是 65 字节未压缩点 |
| `nickname_invalid` | 400 | 昵称空/超 64 字节/含控制字符 |
| `challenge_not_found` | 404 | 挑战不存在 |
| `challenge_expired` | 410 | 挑战过期 |
| `challenge_used` | 409 | 挑战已被用过（防重放） |
| `challenge_invalid` | 400 | 挑战与请求不匹配（用途/码/公钥/绑定上下文） |
| `signature_invalid` | 401 | 验签失败 |
| `unauthorized` | 401 | 缺会话令牌 |
| `session_expired` | 401 | 会话过期或码已过期 |
| `verifier_unavailable` | 503 | 服务端还没接 SM2 验签（骨架期默认 fail closed） |
| `forbidden` | 403 | 凭据对该资源无权 |
| `package_not_found` | 404 | 包不存在 |
| `package_expired` | 410 | 包 TTL 到期 |
| `package_revoked` | 410 | 发送方已撤回 |
| `package_exhausted` | 410 | 下载次数用尽 |
| `package_purged` | 410 | 密文已删除 |
| `package_locked` | 409 | 已 commit，包锁定 |
| `package_incomplete` | 409 | 缺 prelude 或块，或尚未 commit 就下载 |
| `package_conflict` | 409 | 状态冲突（并发 ack/revoke 等） |
| `chunk_conflict` | 409 | 同序号已存在不同字节 |
| `chunk_not_found` | 404 | 该块尚未收到 |
| `chunk_index_out_of_range` | 400 | 块序号越界 |
| `chunk_length_mismatch` | 400 | 块长度与清单推导值不符 |
| `prelude_conflict` | 409 | prelude 已上传且字节不同 |
| `prelude_length_mismatch` | 400 | prelude 实际长度与创建时声明不符 |
| `payload_too_large` | 413 | 超过单请求上限 |
| `quota_exceeded` | 429 | 发送方存储配额超限 |
| `rate_limited` | 429 | 触发限速 |
| `locked_out` | 423 | 失败次数过多被锁定 |
| `not_implemented` | 501 | 预留端点（当前是 WS 信令） |
| `internal_error` | 500 | 服务端内部错误（不暴露细节） |

> 与端侧错误码（`CRYPTO_*`，见 CRYPTO-PACK §13）**不共用命名空间**：一套走 HTTP，一套只在浏览器内部。

---

## 5. HTTP 头

| 头 | 方向 | 说明 |
|---|---|---|
| `Authorization: Bearer <sessionToken>` | 请求 | 会话令牌 |
| `X-Yanshu-Digest` | 响应（下载）/ 请求（预留） | SM3 摘要，小写 hex |
| `X-Yanshu-Digest-Alg` | 请求/响应 | 当前固定 `sm3` |
| `X-Request-Id` | 双向 | 排障用；服务端未收到时自生成 |
| `Retry-After` | 429 / 423 响应 | 重试间隔（秒） |

---

## 6. 挑战消息（签什么）

服务端下发 `message`（base64url），客户端**直接对这段字节签名**，不要自己拼：

```
YANSHU-CHALLENGE/1
purpose=<register|nickname|session>
code=<4 位码>
pubkey=<base64url(公钥)>
nonce=<base64url(32 字节随机)>
expiresAt=<RFC3339Nano UTC>
context=<base64url(改昵称时为新昵称 UTF-8，其余为空)>
```

- 末行不带换行；其余每行以 `\n` 结尾。
- 签名算法：SM2-SM3 + 默认 `ZA`（ID `1234567812345678`）+ DER 编码（CRYPTO-PACK §10.4）。
- `context` 绑定昵称，可防"换昵称重放同一签名"。

---

## 7. 鉴权边界（服务端写死的规则）

| 操作 | 允许 | 拒绝 |
|---|---|---|
| 查码 `GET /codes/{code}` | 任何人（限速 + 失败锁定） | 无 |
| 注册码 | 持有对应私钥（用挑战签名证明） | 公钥非法；码已占用 |
| 创建包 | 任意有效会话（发送方） | 收件码不存在/已过期；自己发自己 |
| 写 prelude / 块 / commit / revoke | 会话码 == 包 `senderCode`，且状态 `uploading` | 其他码；已锁定；终结态 |
| 读 prelude / 块 / progress | 会话码 == `senderCode` 或 `recipientCode` | 其他码（403） |
| 接收方读 | 仅当状态 `ready` | 未 commit（409 `package_incomplete`） |
| ack | 会话码 == `recipientCode`，状态 `ready` | 发送方；未 commit |
| 改昵称 | 会话码 == 路径码 + 昵称挑战签名 | 其他码 |

**为什么 4 位码不是访问凭据**：码只有 104 万组合，会被枚举；真正保密性来自端侧 SM4-GCM + SM2 封装。服务端用「会话 == 密钥对」做资源级隔离，码只当索引。

---

## 8. 大小与时间默认值（`spec/limits.go`、`spec/api.go`）

| 项 | 默认 | 来源 |
|---|---|---|
| 块大小 | `1 MiB`（创建时声明，读方按包内值） | CRYPTO-PACK §14 |
| 块数上限 | `1048576` | 同上 |
| 明文总大小 | `4 GiB` | 同上 |
| prelude 上限 | `8 MiB` | 本骨架暂定 |
| 单包密文上限 | `4 GiB`（可配） | 本骨架暂定 |
| 发送方存储配额 | `8 GiB`（可配） | 本骨架暂定 |
| 包 TTL | `24h`，可请求 `60s ~ 7d` | 需求基线「1~24 小时」的上沿放宽 |
| 码 TTL | `30d`（每次查询/注册续期） | 本骨架暂定 |
| 会话 TTL | `24h` | 本骨架暂定 |
| 挑战 TTL | `5min` | 本骨架暂定 |
| 默认下载次数 | `1`，上限 `100` | 一次性传输定位 |
| ack 后删密文 | `deleteOnAck=true` | 需求基线「收到即解密、服务器随即删」 |

限速（全部可配，见 `spec/limits.go`）：按 IP 查码 60/min（突发 20）、注册 10/min、会话 30/min、建包 20/min；按码查码 30/min；连续失败 5 次锁 15 分钟（锁定键为 `IP+码`，避免误锁别人的码）。

---

## 9. 与 CRYPTO-PACK 的对接点（已按它实现）

| 项 | 服务端行为 |
|---|---|
| prelude | 整段不透明字节，按创建时声明的 `preludeLen` 校验，另存 `SM3(prelude)` |
| 块切片 | 只收 `CHUNK_CT ‖ TAG`（不含 16 字节块头），长度 = `PT_LEN(i)+16` |
| 块头 | **服务端不解析、不存储**，由接收方按 §6.3 重建 |
| 文件名/MIME | 在 `MANIFEST_SEC` 密文里，服务端从未见过 |
| 包顺序 | 乱序上传允许，块序号是唯一坐标 |

---

## 10. 待 API.md 对齐项（共 26 处，逐条可勾）

> 每条给出「当前做法」与「建议」，Ark 定稿时二选一或直接改 `spec`。

| # | 项 | 当前做法 | 待确认点 |
|---:|---|---|---|
| Q1 | URL 前缀 | `/api/v1` | 是否要 `/api` 段、是否用 `/v1` |
| Q2 | 成功响应外壳 | 直接返回资源对象 | 是否统一 `{data:...}` |
| Q3 | 字段风格 | `camelCase` | 是否改 `snake_case` |
| Q4 | 错误外壳 | `{"error":{...}}` | 字段名与是否加 `details` |
| Q5 | 会话令牌位置 | `Authorization: Bearer` | 是否改自定义头 `X-YanShu-Session` |
| Q6 | 会话令牌有效期 | 24h | 是否要滑动续期 |
| Q7 | 挑战下发路径 | `/auth/challenges` | 是否并入 `/codes` 命名空间 |
| Q8 | 挑战消息格式 | 行式 `key=value`（§6） | 是否改 JSON 规范化串 |
| Q9 | `message` 传输形态 | base64url | 是否直接给原文（含非 ASCII 风险） |
| Q10 | 注册是否需要 `code` 字段 | 可选，仅一致性校验 | 是否删掉（服务端总能派生） |
| Q11 | 码归一化策略 | 容错归一化（大小写/`O I L`/`-`） | CRYPTO-PACK §3.4 写「服务端 MUST 只接受归一化后的 4 字符」——需二选一；已留 `YANSHU_CODE_STRICT=1` 开关 |
| Q12 | 5 位 `CODE-CHECK` 输入 | 去掉末位校验字符 | 服务端是否该直接拒绝 |
| Q13 | 「不存在」与「已过期」 | 404 / 410 区分 | 与 PROJECT-MAP「不区分不存在/不可查」有张力，请确认以哪个为准 |
| Q14 | 码 TTL | 30d 并随访问续期 | 是否要固定有效期 |
| Q15 | 建包字段集 | `recipientCode/chunkCount/chunkSize/plaintextSize/preludeLen` | 是否由服务端从 prelude 解析（不建议，违反"不解析"） |
| Q16 | 建包是否返回上传凭据 | 不返回（用会话） | 是否要一次性 `uploadToken` |
| Q17 | `maxDownloads` 默认与上限 | 1 / 100 | 产品上限 |
| Q18 | 扣次数时机 | `ack` 时扣 | 是否改为首次下载即扣 |
| Q19 | 撤回凭据 | 发送方会话（私钥证明） | 需求写"本机持有凭证"，是否要独立 `revokeToken` |
| Q20 | 续传进度形态 | `receivedBitmap`（base64url）+ `missingIndexes` | 是否改纯索引数组 / 是否加 ETag |
| Q21 | 位图 bit 序 | 第 i 块 = 第 i bit（LSB） | 是否改 MSB |
| Q22 | 下载是否支持 HTTP Range | 不支持（按块） | 是否需要单块内 Range |
| Q23 | 摘要头 | `X-Yanshu-Digest` + `-Alg: sm3` | 是否要改 `Content-Digest`（RFC 9530） |
| Q24 | 错误码命名 | `code_taken` / `package_locked` 等下划线 | 是否改大驼峰或 `E_` 前缀 |
| Q25 | 410 vs 404 | 终结态 410，不存在 404 | 是否统一 404 防枚举 |
| Q26 | WS 信令 | 只留消息类型 + 501 | 消息信封与鉴权方式待定 |

### 额外说明（非对齐项，供评审知悉）

- **SM2 验签未接入**：`auth.Verifier` 默认 `stub-deny`（一律拒绝，fail closed）。接入方式二选一：Rune 的 WASM 实现通过子进程/cgo 调用，或服务端自研（`sm2p256v1` + SM3 + DER 严格解析）。接入点集中在 `internal/auth/verifier.go`。
- **限速为进程内实现**：多实例部署时换 Redis 版，接口 `ratelimit.Limiter` 不变。
- **审计只记** `IP / 时间 / 大小 / 状态`，不记业务内容；访问日志只记路由模板，不记路径参数与令牌。
