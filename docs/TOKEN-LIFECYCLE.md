# upload_token 的生命周期与失效方式

> 契约依据：`docs/API.md` §1.5、`docs/contract-rulings.md` G5。实现：`server/internal/auth/token.go`。

## 1. 它是什么

`upload_token` 是**发送方上传侧的能力凭证**（`POST /v1/transfers` 下发），用于 `PUT prelude`、
`PUT chunks/{i}`、`GET status`、`POST complete`。它只写不读：拿到它也读不到别人的密文。

**生成**（契约写死的构造，无分隔符）：

```
upload_token = base64url( HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1" ‖ TRANSFER_ID_ASCII) )
```

**存的是什么**：只存 `SM3(upload_token)`（`transfers.upload_token_sm3`，32 字节 bytea）
与签发时的**密钥版本** `kid`（`transfers.upload_token_kid`）。不存原文；没有单独的 token 过期时间
——它的生命周期绑在传输行上。

**kid 的作用**：服务端只认当前 `YANSHU_TOKEN_KID`。轮换时把 `YANSHU_TOKEN_SECRET` 与
`YANSHU_TOKEN_KID` 一起换掉，所有旧行立刻失效，错误名为 **`401 AUTH_TOKEN_STALE`**
（与"token 不对"的 `AUTH_SIGNATURE_INVALID` 区分，客户端据此走"重建传输"的自愈路径）。
`TOKEN_KID` 缺失 → 启动报错（fail closed），不允许"没有版本信息就都放过"。

错误名只有两个：**`AUTH_TOKEN_STALE`**（kid 轮换导致的作废，401）与
**`AUTH_SIGNATURE_INVALID`**（token 值本身不对，401）。前者让客户端"重建传输"，后者说明
头部/令牌传错了。**没有** `AUTH_TOKEN_EXPIRED`：过期是传输级语义（`410 TRANSFER_EXPIRED`）。

**怎么校验**（`TokenIssuer.Validate`）：按**当前** `TOKEN_SECRET` 与路径里的 `transfer_id`
重算一遍，要求「提交的 token == 重算值」**且**「SM3(重算值) == 库里存的哈希」，两者都成立才放行。
所以 `TOKEN_SECRET` 参与的是**校验时的重算**，不是"只比对哈希"。

## 2. 什么时候失效

| 事件 | 效果 | 说明 |
|---|---|---|
| **轮换 `TOKEN_SECRET` + `TOKEN_KID`** | **全部 token 立即失效**，返回 `401 AUTH_TOKEN_STALE` | kid 对不上直接拒；客户端重建传输拿新 token |
| 只换 `TOKEN_SECRET` 不换 kid | 旧 token 也会失败（重算值不同），错误名是 `AUTH_SIGNATURE_INVALID` | 不建议；规范做法是两个一起换 |
| TTL 到期 | 传输转 `EXPIRED`，内容端点 `410 TRANSFER_EXPIRED` | 这是**传输**生命周期，不是 token 错误；没有 `AUTH_TOKEN_EXPIRED` 这个码 |
| 传输进入终结态（`CONSUMED`/`REVOKED`/`EXPIRED`） | 上传接口拒绝（`409 TRANSFER_STATE_CONFLICT`） | token 本身不再是有效上传凭据 |
| TTL 到期 | 先转 `EXPIRED`，终结元数据保留 7 天后物理删除 | 行删除后 token 自然失效（404/410） |
| 发送方撤回 | 立即终结 + 删密文 | 同上 |
| 删除用户码 | 不影响 token（token 不绑定码） | 但发送方已无法再签发新传输 |
| 改昵称 | 不影响 | 与上传凭证无关 |

> 结论：**轮换 `TOKEN_SECRET` 就是一次性吊销全部 `upload_token` 的手段**。
> 用它做应急：换掉 secret 并重启服务 → 所有在途上传令牌失效，攻击者手里的旧 token 立刻报废；
> 已取走的密文不受影响（那是另一条信任链）。

## 3. 与幂等重放的关系

`POST /v1/transfers` 带 `Idempotency-Key` 时，600 秒内重放要返回**同一个** `transfer_id` 与 `upload_token`。
服务端只存 `SM3(token)`，无法回放原文，因此 token 是按上面的公式**重新算**出来的——这也意味着：

- secret 没变 → 重算值 = 原值，重放 `200`；
- secret 轮换过 → 重算值 ≠ 原值，服务端不会把一个不可用的 token 发出去，返回 `409 TRANSFER_STATE_CONFLICT`，
  客户端重建传输即可（新传输拿新 token）。

## 3.5 运维：如何一次性吊销全部 upload_token（三步）

```sh
# 1) 同时改两个变量（只改一个也行，见下表）：
#    YANSHU_TOKEN_SECRET = 新的 ≥16 字节随机值
#    YANSHU_TOKEN_KID    = 新的版本号，单调递增（如 k1 -> k2 -> k3）
# 2) 重启服务（配置没有热加载）
# 3) 旧 token 立刻 401，客户端重建传输拿新 token（新 token 立即可用）
```

轮换矩阵（自动化测试 `TestTokenRotationMatrix`）：

| 只改什么 | 旧 token 结果 | 说明 |
|---|---|---|
| 只改 `TOKEN_SECRET` | `401 AUTH_TOKEN_INVALID` | 校验会按新密钥重算，旧 token 自然也失效 |
| 只改 `TOKEN_KID` | `401 AUTH_TOKEN_STALE` | 行内 kid 与当前不一致 |
| 两个都改（推荐） | `401 AUTH_TOKEN_STALE` | kid 先判，语义最清楚 |

`AUTH_TOKEN_STALE` = 版本被轮换，客户端应**重建传输**；`AUTH_TOKEN_INVALID` = token 值不对，
客户端应检查是不是串了传输；`AUTH_SIGNATURE_INVALID` 只用于签名不被接受。
**没有 `AUTH_TOKEN_EXPIRED`**：过期是传输级语义（`410 TRANSFER_EXPIRED`）。

> kid 的"单调递增"是运维约定（服务端只做等值比较，不解析序数）；如果要服务端强制递增，
> 需要契约先定义 kid 的格式与历史版本存储，v1 不做。

## 4. 切换 `sm2` 的操作清单（宿主）

1. **schema 只用一套**：`yanshu_core`。`yanshu_core_sm2` 只是我本地做隔离验证时用的临时 schema，
   不要求宿主存在；换验签模式**不需要重建 schema**（验签是无状态的，不动表）。
2. env：

   ```sh
   YANSHU_DATABASE_URL=<从 /.keys/pg.env 读，追加 &search_path=yanshu_core>
   YANSHU_BLOB_DIR=/var/lib/yanshu/blobs
   YANSHU_ADDR=127.0.0.1:8080
   YANSHU_LOG_DIR=/var/log/yanshu
   YANSHU_TOKEN_SECRET=<≥16B 的固定随机值，落 0600 文件>
   YANSHU_TOKEN_KID=<密钥版本，1..32 可打印字符，如 k2026-11；与 secret 同时轮换>
   YANSHU_VERIFIER=sm2
   YANSHU_KERNEL_WASM=<repo>/server/kernel/yanshu_sm.wasm   # 留空则自动探测 ./kernel/ 与 exe 同级
   ```

3. 迁移：`./bin/yanshu-server -migrate-only`（幂等）。
4. 切换后失效的东西：
   - **不需要真实签名的旧客户端**（`stub-allow` 时代的占位签名）会得到 `401 AUTH_SIGNATURE_INVALID`；
   - 如果同时换了 `TOKEN_SECRET`，所有在途 `upload_token` 失效（见 §2），客户端重建传输；
   - 码、昵称、已终结的元数据都不受影响。
5. 保持 `TOKEN_SECRET` 不变地切换 `sm2`：只换验签，不动 token，在途上传可继续。

## 5. 二进制

仓库不提交二进制。构建（需要 Go 1.27，一次即可）：

```sh
cd server
go build -o bin/yanshu-server ./cmd/yanshu-server
go build -o bin/deliver ./cmd/deliver
```

`bin/yanshu-server` 与 `server/kernel/yanshu_sm.wasm` 两个文件一起部署即可；内核随仓库提供，
**不需要 Rust 工具链**。
