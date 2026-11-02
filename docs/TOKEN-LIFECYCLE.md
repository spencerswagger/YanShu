# upload_token 的生命周期与失效方式（KID 版）

> 实现：`server/internal/auth/token.go`、`server/internal/store/token_kid.go`、
> `server/internal/httpapi/handlers_transfers.go`。契约：`API §1.7`。

## 1. 生成、存储、校验

```
upload_token = base64url(HMAC-SHA256(TOKEN_SECRET,
                "yanshu/upload-token/v1" ‖ transfer_id ‖ u32be(KID)))
```

- **KID 参与派生**（`u32be`，契约 §1.7）：递增 KID 后为同一 `transfer_id` 重新签发的 token
  与旧 token **逐字节不同**，旧凭据不可能"换个行就复活"（`TestStaleTokenCannotBeReincarnated`）。
- 库里只存 `SM3(upload_token)`（`transfers.upload_token_sm3`）与**签发时的 KID**
  （`transfers.upload_token_kid`）；校验 = 行内 KID == 当前 KID（版本闸）+ 当前密钥/KID 重算
  == 库内哈希（值闸）。
- 校验顺序（**先凭据后状态**）：
  1. 行内 KID != 当前 KID → `401 AUTH_TOKEN_REVOKED`；
  2. token 不等于当前密钥下的派生值（伪造/串传输/**secret 被轮换**）→ `401 AUTH_TOKEN_INVALID`；
  3. 之后才看传输状态：终结态一律 `410`（含传输 TTL 过期 `410 TRANSFER_EXPIRED`）。
- `AUTH_SIGNATURE_INVALID` **只**用于签名本身不被接受（伪造 DER、消息被改、公钥不符），
  与上面三个凭据类是两套。

## 2. KID：唯一吊销开关

当前 KID 存在 `token_kid_state`（单行 `id=true, kid=<n>`），运行期每次校验都读它。

```sql
-- 一键吊销全部 upload_token：不删库、不重启
UPDATE token_kid_state SET kid = kid + 1;
```

**严格单调递增**：`YANSHU_TOKEN_KID`（正整数，默认 1）只在启动时 bootstrap——
库里没有就写入、**等于**允许（重复启动幂等）、大于则更新、**小于直接拒绝启动**：

```
config: YANSHU_TOKEN_KID must increase (current=3, provided=2); refusing to start
```

调小会让被吊销的旧凭据复活，所以这是硬校验，不是告警。
`TOKEN_SECRET` 参与派生：轮换它会让既有 token 派生值对不上 → `AUTH_TOKEN_INVALID`；
KID 递增则是显式的"版本吊销"→ `AUTH_TOKEN_REVOKED`。两者都要求重启（secret/KID 都从启动配置读）。

## 3. 失效矩阵

| 事件 | 结果 |
|---|---|
| KID 递增 | 全部旧 token 立刻 `401 AUTH_TOKEN_REVOKED`（无需重启） |
| 只换 `TOKEN_SECRET` | 旧 token `401 AUTH_TOKEN_INVALID`（派生值变了；不是签名类） |
| token 值不对/串了传输 | `401 AUTH_TOKEN_INVALID` |
| 传输终结（撤回/过期/取完） | 上传接口 409/410（状态层） |

## 4. 客户端处置（按错误名分支）

| 错误名 | 含义 | 客户端动作 |
|---|---|---|
| `AUTH_TOKEN_REVOKED` | KID 已轮换，凭据作废 | 重新 `POST /v1/transfers` 建传输拿新 token；**不要**重算签名 |
| `AUTH_TOKEN_INVALID` | token 值不对/串了传输 | 检查本地 token 与 transfer_id 是否配对 |
| `AUTH_SIGNATURE_INVALID` | 签名本身不被接受 | 检查 `SIG_INPUT` 与私钥；**与 token 无关** |

## 5. 切换 sm2 与 schema

- schema 只用一套：**`yanshu_core`**；`yanshu_core_sm2` 只是本地隔离验证时的临时 schema，
  换验签模式**不需要重建 schema**。
- `/v1/config` 暴露只读 `token_epoch`（值就是当前 KID），便于客户端判断是否落后。
