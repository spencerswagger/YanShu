# 雁书 · 服务端契约对齐清单（已对齐 v1）

| 项 | 值 |
|---|---|
| 状态 | **已对齐**（原 26 处暂定字段全部对到契约） |
| 契约版本 | `docs/API.md` v1，commit **`376c5b5`**（分支 `feat/contracts-v1`） |
| 加密包约束 | `docs/CRYPTO-PACK.md` `YSPK/1.0` §2 / §4.2 / §4.3 / §12 / §13 |
| 代码落点 | `server/internal/spec/`（路径/字段/错误码/限值/WS 类型）、`server/internal/auth/`（`SIG_INPUT`） |
| 说明 | 本文件保留原文件名，内容改为「对齐结果 + 残留偏离 + 契约缺口」，便于评审对照 |

> 一句话：服务端只当**不透明字节**的搬运工；边界是 `prelude` 与 `CHUNK_CT‖TAG`，不解析任何包内加密字段。

---

## 1. 原 26 处暂定项的对齐结果

| # | 原暂定项 | 契约定稿 | 落点 |
|---:|---|---|---|
| Q1 | 前缀 `/api/v1` | **`/v1`**（§0.1） | `spec.Prefix` |
| Q2 | 直接返回资源对象 | 维持（契约无 `data` 包裹） | 各 handler |
| Q3 | `camelCase` | **`snake_case`**（§0.1） | `spec/types.go` 全部 tag |
| Q4 | 错误外壳 `{error:{code,message,...}}` | 增加 `scope` / `retry_after` / `request_id`（§0.2） | `spec.ErrorResponse` |
| Q5 | `Authorization: Bearer` | **`X-YS-Code` + `X-YS-Challenge-Id` + `X-YS-Signature`**（§1.4） | `spec.Header*`、`httpapi/authn.go` |
| Q6 | 会话令牌 24h | **无会话**；上传用 `X-YS-Upload-Token`，下载用 `X-YS-Download-Id`（§1.5） | `auth.TokenIssuer`、`transfer_downloads` |
| Q7 | `/auth/challenges` | **`POST /v1/challenges`**（§4.2） | `spec.PathChallenges` |
| Q8 | 行式挑战消息 | **`SIG_INPUT = "YSAUTH1" ‖ PURPOSE(1) ‖ NONCE(32) ‖ 字段串`**（§1.3） | `auth/signinput.go` |
| Q9 | `message` base64url | 服务端不再下发待签串；客户端按 §1.3 自拼 | 同上 |
| Q10 | 注册带 `code` | **必需**，且 `code == SM3(pubkey)[0:20bit]` 派生值与签名里的 `CODE(4)` 三方一致（§4.3） | `handleRegisterCode` |
| Q11 | 容错归一化码 | **裁决 D3：允许**，但须幂等、先于一切判定、限速/锁定按归一化后计数、禁止猜测性纠错 | `gm.NormalizeCode` |
| Q12 | 接受 5 位 `CODE-CHECK` | **拒绝**：5 位不截断，直接 `CODE_FORMAT_INVALID`（裁决 D3 ④） | `gm.NormalizeCode` |
| Q13 | 区分「不存在 / 已过期」 | **不区分**：统一 `404 CODE_NOT_FOUND`（§4.4） | `handleLookupCode` |
| Q14 | 码 30 天 TTL | **无过期**：只有 `registered_at` / `updated_at`（§2.1） | `codes` 表 |
| Q15 | 建包字段集 | `recipient_code / plaintext_size / chunk_size / chunk_count / prelude_len / prelude_sm3 / ttl_seconds / max_downloads`（§6.1） | `spec.CreateTransferRequest` |
| Q16 | 不返回上传凭据 | **返回 `upload_token`**（§6.1），服务端只存 `SM3`（§1.5） | `handleCreateTransfer` |
| Q17 | `maxDownloads` 1..100 | **1..3**（§6.1） | `spec.Min/MaxDownloads` |
| Q18 | ack 时扣次数 | **维持，且为唯一扣数时机**；`LEASED` 与租约过期都不扣（§5.1 / §7.5） | `store.AckDownload` |
| Q19 | 撤回用发送方会话 | **发送方签名 `TRANSFER_REVOKE`**（§6.7） | `store.RevokeTransfer` |
| Q20 | 位图 + missing 数组 | `bitmap`（base64url，**MSB 优先**）+ `missing: [{start,count}]`（§6.5） | `httpapi/validate.go` |
| Q21 | 位图 LSB | **MSB**：第 i 块在 `bit (7-i%8)`（§6.5） | `buildBitmap` |
| Q22 | 不支持 Range | **支持单区间** `206/416`，多区间 `400 RANGE_UNSUPPORTED`（§8.1） | `serveRange` |
| Q23 | `X-Yanshu-Digest` | **裁决 G9：不纳入 v1**，已从响应头移除；SM3 仅服务端内部做幂等比对 | `handleGetChunk` |
| Q24 | 错误码下划线小写 | **大写 + 下划线**（`CODE_TAKEN` 等，§10） | `spec/errors.go` |
| Q25 | 410 vs 404 | 终结态 **410**（三个码互不混用），不存在 **404**（§5.2 / §10） | `spec.TerminalErrorCode` |
| Q26 | WS 只留类型 | 契约已定义完整信令（§9）；本轮仍**未实现**，`/v1/ws` 回 503（见 §3 偏离 1） | `handleWS` |

---

## 2. 本次定稿四条的直接落点

| 定稿要求 | 实现位置 | 测试 |
|---|---|---|
| **计数口径**：只在 `ack` 成功时 `+1`；`LEASED`/租约过期不扣；`download_id` 作幂等键 | `store.AckDownload`（`transfer_downloads.acked_at` 唯一判据）；`handleAck` | `TestAckCountingAcrossLeases`、`TestTransferLifecycle` |
| **`SIG_INPUT` 覆盖 `CODE(4)`**；挑战只绑 `purpose`；`X-YS-Code` 与签名码逐字比对 → `AUTH_CODE_MISMATCH` | `auth/signinput.go` 七个 PURPOSE 构造器；`httpapi/verifySignature` | `TestAuthErrors`、`internal/auth/auth_test.go` |
| **错误码修正**：配额 `507 INSUFFICIENT_STORAGE`；`429` 只用于时间窗限速；`SIZE_LIMIT_EXCEEDED` ≠ `PAYLOAD_TOO_LARGE` | `spec/errors.go`；`handleCreateTransfer`（507）；`allow`（429）；`checkDeclaredLength`（413 vs 400） | `TestStorageQuota`、`TestSizeAndPayloadErrors`、`TestLookupRateLimited` |
| **v1 无公开举报入口**：只有内部 `REVOKED` 终结态 | 无举报路由；`store.RevokeTransfer` 即运营/用户共用撤回语义 | `TestRevoke` |

---

## 3. 裁决落实与残留待裁决

契约方已就 D1/D2/D3/G5/G9 给出裁决（`docs/contract-rulings.md`，13 项落点表）。
其中 5 条已在本分支落实；**其余 8 项对应的裁决文档尚未推到远端**（`docs/contract-clarify`
分支在本地未推，`feat/contracts-v1` 仍停在 `376c5b5`），因此这 8 项暂按现有实现保留，
拿到文档后逐条对，不静默留白。

### 3.1 已裁决并落实（5 项）

| # | 裁决 | 落实 |
|---|---|---|
| D1 | WS 补降级语义：`GET /v1/ws` 返回 503 即直传不可用，客户端静默走中转、改为轮询 inbox（≥30s，退避至 5min） | `handleWS` 立即返回 `503 SERVICE_UNAVAILABLE`（不挂起）；`spec.InboxPollMinIntervalSeconds=30` / `InboxPollMaxBackoffSeconds=300`；inbox 轮询无额外限速（仅受每次 `INBOX_LIST` 挑战的 IP 20/min 约束，30s 轮询 ≈ 2/min） |
| D2 | 审计只记 `route_template`，不写实际路径 | `middleware.go` 用 `r.Pattern`（含方法前缀，如 `GET /v1/transfers/{transferId}`）；`TestAuditPathIsRouteTemplate` 断言审计里不出现 `transfer_id` |
| D3 | 码容错归一化**允许**，四条硬约束：幂等 / 先于一切判定 / 限速与锁定按归一化后计数 / 禁止 5 位截断与猜测性纠错 | `gm.NormalizeCode` 只保留契约明列的「大写 + 去 `-`/空白 + `O→0`、`I/L→1` + 长度必须 4」，删掉 5 位截断；`TestNormalizeCodeIdempotent`、`TestFiveCharCodeRejected`、`TestLookupRateLimitAndLockout`（大小写混合命中同一锁） |
| G5 | 采纳 HMAC 派生并写进契约：`base64url(HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1" ‖ transfer_id))`，库内只存 `SM3` | `auth.TokenIssuer` 前缀改为 `yanshu/upload-token/v1`（无分隔符）；`TestUploadTokenMatchesContract` 独立复算；`TOKEN_SECRET` 只从 env 读、不落日志 |
| G9 | 密文摘要头**不纳入 v1**，客户端不得依赖 | 已从 `GET /v1/transfers/{id}/chunks/{index}` 响应里移除 `X-YS-Ciphertext-Sm3`；内部仍存 SM3 用于幂等 |

### 3.2 待裁决（7 项，等 `docs/contract-rulings.md`）

| # | 缺口 | 当前做法（未变） |
|---:|---|---|
| G1 | 「已认证但不是传输当事人」（非接收方 `ack`、非发送方 `revoke`）没有专用错误码 | `409 TRANSFER_STATE_CONFLICT` |
| G2 | `CHUNKS_MISSING` 要求带 `missing` 数组，但错误信封没有 `details` 槽位 | 放在错误体顶层 |
| G3 | `§2.1` 白名单未列服务端必需的派生状态（`prelude_received`、`received_chunks`、`updated_at`、`upload_token_sm3`、`uploader_ip`、租约表、幂等表） | 已落库并在迁移文件注明理由 |
| G4 | `§11.4` 按 IP 配额需要上传者 IP，但 `§2.1` 只在审计域列了 `ip` | `transfers.uploader_ip`（派生列） |
| G7 | 重复注册（同码同公钥）语义未定义 | 幂等 `200`，不覆盖昵称 |
| G8 | 终结后 `GET /v1/transfers/{id}` 的字段集未写清 | 保留白名单元数据，去掉 `prelude_sm3` 与 `lease_expires_at` |
| G10 | `GET /v1/config` 的 `stun_urls` / `ws_url` 默认值未定义 | 由 `YANSHU_STUN_URLS` / `YANSHU_WS_URL` 注入 |

（原 G6「码归一化」已由 D3 裁决关闭。）

## 4. 接口与鉴权实现对照

| 端点 | 鉴权 | 状态 |
|---|---|---|
| `GET /v1/config` | 无 | ✅ |
| `POST /v1/challenges` | 无（IP 20/min） | ✅ |
| `POST /v1/codes` | 签名 `REGISTER` | ✅ |
| `GET /v1/codes/{code}` | 无（IP 30/min + 失败锁定） | ✅ |
| `PATCH /v1/codes/{code}` | 签名 `NICKNAME_UPDATE`（码 5/h） | ✅ |
| `POST /v1/transfers` | 签名 `TRANSFER_CREATE`（码 10/h + 并发 20 + 507 配额） | ✅ |
| `PUT .../prelude` | `X-YS-Upload-Token` | ✅ |
| `PUT .../chunks/{index}` | `X-YS-Upload-Token` | ✅ |
| `HEAD .../chunks/{index}` | 无（`transfer_id` 能力凭证） | ✅ |
| `GET .../status` | `X-YS-Upload-Token` | ✅ |
| `POST .../complete` | `X-YS-Upload-Token` | ✅ |
| `GET /v1/inbox` | 签名 `INBOX_LIST` | ✅ |
| `GET /v1/transfers/{id}` | 无（`transfer_id` 能力凭证） | ✅ |
| `GET .../prelude` | 无（开/续租约） | ✅ |
| `GET .../chunks/{index}` | `X-YS-Download-Id`（有效租约） | ✅ |
| `POST .../ack` | 签名 `TRANSFER_ACK` + `X-YS-Download-Id` | ✅ |
| `POST .../revoke` | 签名 `TRANSFER_REVOKE` | ✅ |
| `GET /v1/ws` | — | ⛔ 503（D1） |

---

## 5. 存储红线（Gate 可复跑）

- 列名白名单断言：`internal/store/schema_test.go`（多一列即失败）。
- 文件名/明文探针：`internal/httpapi/api_test.go::TestNoFilenameOrPlaintextPersisted` 扫全库 text/bytea 列 + 磁盘文件名。
- 磁盘布局：`<BLOB_DIR>/<transfer_id[0:2]>/<transfer_id>/prelude` 与 `chunks/<8 位序号>`，另外什么都没有。
- 取存储根目录与 schema 的方法见 `server/README.md` 的「Gate 取数」小节。
