# 契约裁决记录 · 2026-11-03

对接过程中提出的 13 项契约问题（3 项有意偏离 + 10 项缺口）的裁决与落点。

- 契约版本：`docs/API.md` v1 / `docs/CRYPTO-PACK.md` `YSPK/1.0`（基线 commit `376c5b5`，分支 `feat/contracts-v1`）
- **影响面：全部 13 项均为澄清、错误码与元数据口径，不改包字段、不改样例字节**（V1 522 B / V2 743 B / 封装 129 B / 签名 70 B 均不变）。
- 唯一"会改变包字节"的候选（把包身份显式绑进 AAD）不在此列，单独见 `docs/adr/0001-aad-chunk-binding.md`，结论是 v1 不改、留待版本升级。

| # | 问题 | 裁决 | 落点 | 改字节 |
|---:|---|---|---|---|
| D1 | WebSocket（信令与在线表）未实现 | **补定义降级语义 + 排期**：v1 `GET /v1/ws` 返回 `503 SERVICE_UNAVAILABLE`；客户端视为直传不可用、静默走中转、收件通知改轮询 `inbox`（≥30 s，退避到 ≤5 min）；功能不受影响 | API §9.6、§4.1、§10.2、§15 | 否 |
| D2 | 审计 `path` 记路由模板而非实际路径 | **采纳（并写进白名单）**：审计字段改为 `route_template`，明确不记实际路径参数，避免 `transfer_id`（能力凭证）落日志；追溯改用 `request_id` + 元数据表 | API §2.1、§12 | 否 |
| D3 | 服务端对码做容错归一化 | **允许，但有硬约束**：规则必须与端侧逐字节一致、幂等、在一切判定之前完成；限速/锁定按归一化后的码计数；**禁止**猜测性纠错与 5 位截断。归一化不扩大撞码面（码空间仍是 2^20 个规范值），只归并同一码的不同写法 | API §1.6、§1.1、§4.3；CRYPTO-PACK §3.4 | 否 |
| G1 | 非当事人调 `ack` / `revoke` 无专用错误码 | **补定义**：新增 `403 NOT_TRANSFER_PARTY`（已认证但非当事人），不再复用 `409 TRANSFER_STATE_CONFLICT` | API §10.1 | 否 |
| G2 | `CHUNKS_MISSING` 的 `missing` 无槽位 | **补定义**：错误信封新增可选 `details` 对象，v1 **只允许**键 `missing`；新增键须走 ADR | API §0.2、§6.6、§10.1 | 否 |
| G3 | 白名单未含服务端必需的派生状态 | **补定义**：新增「派生状态（服务端内部，无业务内容）」一组：`prelude_received`、`received_chunks`、`upload_token_sm3`、`uploaded_bytes`、租约/取件记录、幂等键映射；并加两条硬规矩（新增列必须先改本节；任何列不得含用户内容） | API §2.1 | 否 |
| G4 | 按 IP 配额需要上传者 IP | **补定义**：`transfers.uploader_ip` 作为派生列列入白名单，仅用于配额与反滥用，不对外返回、不用于画像 | API §2.1 | 否 |
| G5 | 幂等重放要返回同一 `upload_token`，与"只存 `SM3`"冲突 | **认可并写死构造**：`upload_token = base64url(HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1" ‖ TRANSFER_ID_ASCII))`；库内只存 `SM3(upload_token)`；`TOKEN_SECRET` 只来自部署密钥、不入库不落日志；轮换令存量 token 失效（≤ TTL 24 h） | API §1.5 | 否 |
| G6 | 码归一化与 `CRYPTO-PACK §3.4` 的"服务端只接受归一化后 4 字符"表述冲突 | **补定义（同 D3）**：CRYPTO-PACK 改为"服务端 MAY 执行同一套归一化，结果必须正好 4 个合法符号"，判定口径指向 API §1.6 | CRYPTO-PACK §3.4 | 否 |
| G7 | 重复注册（同码同公钥）语义未定义 | **补定义**：`200` 幂等，返回与首次相同的 body（`registered_at` 不变），**不覆盖昵称**；改昵称只能走 `NICKNAME_UPDATE` | API §4.3 | 否 |
| G8 | 终态 `GET /transfers/{id}` 字段集不明确 | **补定义**：给出固定字段清单（16 项），并明确**不再返回** `prelude_sm3` 与 `lease_expires_at` | API §7.2 | 否 |
| G9 | 块/prelude 响应未定义密文摘要头 | **明确拒绝纳入 v1**：完整性已由 AEAD tag + 清单摘要保证；实现可保留 `X-YS-Ciphertext-Sm3` 作**非契约扩展**，客户端 MUST NOT 依赖 | API §7.4 | 否 |
| G10 | `/v1/config` 的 `stun_urls` / `ws_url` 未给默认值 | **补定义约束而不给默认值**：`stun_urls` ≥1 条且禁 `turn:`；`ws_url` 可为 `null`（走 §9.6）；`config` 不得含密钥/TURN 凭据/内部地址 | API §4.1 | 否 |

## 统计

- **补定义**：12 项（D1、D2、D3、G1–G8、G10）
- **明确拒绝**：1 项（G9）
- **排期下一轮**：1 项（D1 的 WS 实现；其降级语义已在 v1 补定义）
- **需要抬版本号**：0 项（唯一候选见 `docs/adr/0001-aad-chunk-binding.md`，结论为 v1 不改）

## 一致性校核

- 全部 `§` 交叉引用可解析；表格列数与代码围栏配对通过。
- `CRYPTO-PACK` 四组样例字节零变化（V1 522 B / V2 743 B / V3 129 B / V4 70 B），逐字节复核脚本 0 失败。
