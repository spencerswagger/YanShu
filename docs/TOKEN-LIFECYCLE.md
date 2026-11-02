# upload_token 的生命周期与失效方式（v1）

> 实现：`server/internal/auth/token.go`、`server/internal/httpapi/handlers_transfers.go`。

## 1. 生成、存储、校验

```
upload_token = base64url(HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1" ‖ transfer_id))
```

- 库里只存 `SM3(upload_token)`（`transfers.upload_token_sm3`），不存原文。
- 校验顺序（**先凭据后状态**）：
  1. `SM3(token)` 与库内哈希对不上 → `401 AUTH_TOKEN_INVALID`（伪造/串了传输）；
  2. 哈希对得上、但**当前密钥**派生不出同一个值 → `401 AUTH_TOKEN_REVOKED`（密钥轮换）；
  3. 签发超过 **6 小时** → `401 AUTH_TOKEN_EXPIRED`；
  4. 之后才看传输状态（409/410）。
- 签名类错误 `AUTH_SIGNATURE_INVALID` **只**用于签名本身不被接受（伪造 DER、消息被改、公钥不符），
  与上面三个凭据类是两套，互不覆盖。

## 2. 吊销

**v1 不引入 EPOCH**：吊销 = **轮换 `TOKEN_SECRET`**（派生结果变，旧 token 对不上 → `AUTH_TOKEN_REVOKED`）。

```sh
# 应急：换一个新 secret 并重启（影响全站所有在传任务）
YANSHU_TOKEN_SECRET=<新的 ≥16B 随机值>  ./bin/yanshu-server
```

代价与边界：这是**全局**动作（不是按用户/按传输）；重启期间不可用；客户端拿到
`AUTH_TOKEN_REVOKED` 后应**重建传输**，而不是重算签名。

## 3. 失效矩阵

| 事件 | 结果 |
|---|---|
| 轮换 `TOKEN_SECRET` | 全部旧 token **立刻** `401 AUTH_TOKEN_REVOKED`（应急吊销） |
| 超过 6 小时 | `401 AUTH_TOKEN_EXPIRED`（下载租约 30 分钟同属此类） |
| token 值不对/串了传输 | `401 AUTH_TOKEN_INVALID` |
| 传输终结（撤回/过期/取完） | 上传接口 409/410（状态层） |

## 3.4 为什么旧版本看到的是 201（commit 时间线）

| commit | token 校验方式 | 换 secret 后旧 token |
|---|---|---|
| `9065eb8` 及更早 | 只比 `SM3(token)` 与库内哈希 | **仍然有效（201）** |
| `08d40e7` | 按当前密钥**重算** + 比对 | 失效（401 `AUTH_TOKEN_INVALID`） |
| `fa479d9` | 加 kid（**已按最终裁决撤回**，见 `0004` 迁移） | 当时为 `AUTH_TOKEN_STALE`，已改名 `AUTH_TOKEN_REVOKED` |

所以"换 secret 后 201"是 `9065eb8` 的**预期行为**，不是同一份实现的矛盾。

## 3.5 运维：如何一次性吊销全部 upload_token（三步）

```sh
# 1) 同时改两个变量（只改一个也行，见下表）：
#    YANSHU_TOKEN_SECRET = 新的 ≥16 字节随机值
#    YANSHU_TOKEN_KID    = 新的版本号，单调递增（如 k1 -> k2 -> k3）
# 2) 重启服务（配置没有热加载）
# 3) 旧 token 立刻 401，客户端重建传输拿新 token（新 token 立即可用）
```

### 客户端自愈（按错误名分支）

| 错误名 | 含义 | 客户端动作 |
|---|---|---|
| `AUTH_TOKEN_REVOKED` | 派生密钥已轮换，凭据作废 | 重新 `POST /v1/transfers` 建传输拿新 token；**不要**重算签名 |
| `AUTH_TOKEN_INVALID` | token 值不对/串了传输 | 检查本地存的 token 与 transfer_id 是否配对；必要时重建传输 |
| `AUTH_TOKEN_EXPIRED` | 超过 6 小时（或租约 30 分钟） | 重建传输 / 重新拿租约 |
| `AUTH_SIGNATURE_INVALID` | 签名本身不被接受 | 检查 `SIG_INPUT` 与私钥；**与 token 无关** |

> 注意：按 API §1.7，`TOKEN_SECRET` 只是派生盐——**轮换它不会吊销任何 token**；
> 全局吊销的唯一开关是 EPOCH 递增（`UPDATE token_kid_state SET kid = kid + 1`）。
> v1 的吊销就是轮换 `TOKEN_SECRET`（全局、需重启）。EPOCH 机制已按最终裁决撤回
> （`0004_drop_token_epoch.sql` 删列删表）。
**没有 `AUTH_TOKEN_EXPIRED`**：过期是传输级语义（`410 TRANSFER_EXPIRED`）。

### 自动化对照脚本（给验收）

```sh
server/scripts/token-rotation-check.sh \
  --bin ./bin/yanshu-server --deliver ./bin/deliver \
  --yspk /tmp/sample.yspk --dsn '<DSN 含 search_path>' --blob /tmp/blobs
```

脚本自己起停服务四轮（基线 / 只换 secret / 只换 kid / 两个都换），每组都断言
"旧 token 拒 + 新 token 200"，输出 PASS/FAIL 并以退出码收口。

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
   YANSHU_TOKEN_KID=<密钥版本，正整数且严格递增：1 → 2 → 3；与 secret 同时轮换>
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
