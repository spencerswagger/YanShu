# upload_token 的生命周期与失效方式（EPOCH 版，API §1.7）

> 实现：`server/internal/auth/token.go`、`server/internal/store/token_epoch.go`。

## 1. 生成、存储、校验

```
upload_token = base64url(HMAC-SHA256(TOKEN_SECRET,
                "yanshu/upload-token/v2" ‖ u64be(EPOCH) ‖ transfer_id))
```

- 库里只存 `SM3(upload_token)`（`transfers.upload_token_sm3`）与**签发时的 EPOCH**
  （`transfers.upload_token_kid`，列名沿用旧命名，值就是 EPOCH 的十进制串）。
- 校验（`requireUploadToken`，顺序固定）：
  1. **EPOCH**：行内 EPOCH == 当前 EPOCH，否则 `401 AUTH_TOKEN_STALE`；
  2. **哈希**：`SM3(token)` == 库内值，否则 `401 AUTH_TOKEN_INVALID`；
  3. **过期**：签发超过 **6 小时** → `401 AUTH_TOKEN_EXPIRED`；
  4. 之后才看传输状态（**先凭据后状态**：401 优先于 410）。
- `TOKEN_SECRET` 只是派生盐：**轮换它不会让已签发 token 失效**（哈希没变）。

## 2. EPOCH：一键吊销

当前 EPOCH 存在 `token_kid_state`（单行 `id=true, kid=<epoch>`），运行期每次校验都读它。

```sql
-- 一键吊销全部 upload_token：不需要删库、不需要重启
UPDATE token_kid_state SET kid = kid + 1;
```

- 启动时 `YANSHU_TOKEN_EPOCH`（正整数，默认 1）作为 bootstrap：库里没有就写入；比库里大就更新；
  **比库里小直接拒绝启动**（防止调小让旧 token 复活）。
- `/v1/config` 暴露只读 `token_epoch`，客户端可据此判断自己是否落后。

## 3. 失效矩阵

| 事件 | 结果 |
|---|---|
| 只换 `TOKEN_SECRET` | **旧 token 仍然有效**（EPOCH 未变、哈希未变） |
| `EPOCH` 递增 | 全部旧 token 立刻 `401 AUTH_TOKEN_STALE` |
| 超过 6 小时 | `401 AUTH_TOKEN_EXPIRED` |
| token 值不对/串了传输 | `401 AUTH_TOKEN_INVALID` |
| 传输终结（撤回/过期/取完） | 上传接口 409/410（状态层） |

## 3.4 为什么旧版本看到的是 201（commit 时间线）

| commit | token 校验方式 | 换 secret 后旧 token |
|---|---|---|
| `9065eb8` 及更早 | 只比 `SM3(token)` 与库内哈希 | **仍然有效（201）** |
| `08d40e7` | 按当前密钥**重算** + 比对 | 失效（401 `AUTH_TOKEN_INVALID`） |
| `fa479d9` | 加 kid：行内 kid 必须等于当前 kid | 失效（401 `AUTH_TOKEN_STALE`） |

所以"换 secret 后 201"是 `9065eb8` 的**预期行为**，不是同一份实现的矛盾。

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

### 客户端自愈（按错误名分支）

| 错误名 | 含义 | 客户端动作 |
|---|---|---|
| `AUTH_TOKEN_STALE` | EPOCH 已递增，凭据作废 | 重新 `POST /v1/transfers` 建传输拿新 token；**不要**重算签名 |
| `AUTH_TOKEN_INVALID` | token 值不对/串了传输 | 检查本地存的 token 与 transfer_id 是否配对；必要时重建传输 |
| `AUTH_TOKEN_EXPIRED` | 超过 6 小时（或租约 30 分钟） | 重建传输 / 重新拿租约 |
| `AUTH_SIGNATURE_INVALID` | 签名本身不被接受 | 检查 `SIG_INPUT` 与私钥；**与 token 无关** |

> 注意：按 API §1.7，`TOKEN_SECRET` 只是派生盐——**轮换它不会吊销任何 token**；
> 全局吊销的唯一开关是 EPOCH 递增（`UPDATE token_kid_state SET kid = kid + 1`）。
> 若最终裁决改为"删掉 EPOCH、只靠换 secret 吊销"，则 `AUTH_TOKEN_STALE` 会改由 secret 轮换触发，
> 届时只需替换 `requireUploadToken` 的 EPOCH 判定，错误名与客户端分支不变。
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
