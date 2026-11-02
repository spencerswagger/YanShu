# 雁书 · 服务端（Core）

中转服务端：**只做码/公钥登记、密文块存取、TTL/次数/撤回策略、审计与限速**。
它不解析 prelude，不解析块，不实现加密——文件名与明文从头到尾不上行、不落库、不落盘。

契约：`docs/API.md` v1（commit `376c5b5`）+ `docs/CRYPTO-PACK.md` `YSPK/1.0`。
对齐结果、残留偏离与契约缺口见 `docs/DRAFT-FIELDS.md`。

## 目录

```
server/
├── cmd/yanshu-server/      # 入口：配置 → 迁移 → 路由 → 清理任务 → 优雅退出
├── internal/spec/          # ★ 对外契约唯一来源（路径/字段/错误码/限值/WS 类型）
├── internal/gm/            # 自研 SM3 + Crockford 码派生与归一化
├── internal/auth/          # SIG_INPUT（YSAUTH1）+ 验签接口/桩 + upload_token 签发
├── internal/store/         # PG 持久层 + migrations
├── internal/blob/          # 密文块磁盘存储（不透明字节，支持 Range）
├── internal/httpapi/       # HTTP 接口、鉴权边界、限速、Range
├── internal/ratelimit/     # 令牌桶 + 失败锁定（内存版）
├── internal/cleanup/       # TTL/终结态清道夫（真删 + 7 天墓碑）
└── internal/testutil/      # 集成测试夹具（独立 schema）
```

## 常驻实例启动清单（宿主按顺序执行）

前置：Go 1.27 构建产物、PostgreSQL 17。凭据**只从 `/.keys/pg.env` 读**，任何文件/PR/日志里都不写 DSN 与口令。

```sh
# 0) 构建（产物在 server/bin）
cd server
go build -o bin/yanshu-server ./cmd/yanshu-server
go build -o bin/deliver ./cmd/deliver

# 1) 载入凭据（不 echo；PG_DEV_DSN / PGPASSFILE 由该文件提供）
set -a; . /.keys/pg.env; set +a

# 2) 建 schema（一次性；名字可自定，下面统一用 yanshu_core）
psql "$PG_DEV_DSN" -c 'create schema if not exists yanshu_core'

# 3) 迁移（可单独跑；启动时也会自动跑一遍，内嵌 SQL + advisory lock）
YANSHU_DATABASE_URL="${PG_DEV_DSN}&search_path=yanshu_core" ./bin/yanshu-server -migrate-only

# 4) 起常驻服务
YANSHU_DATABASE_URL="${PG_DEV_DSN}&search_path=yanshu_core" \
YANSHU_BLOB_DIR=/var/lib/yanshu/blobs \
YANSHU_ADDR=127.0.0.1:8080 \
YANSHU_LOG_DIR=/var/log/yanshu \
YANSHU_VERIFIER=stub-allow \
YANSHU_TOKEN_SECRET="$(cat /var/lib/yanshu/token-secret)" \
./bin/yanshu-server

# 5) 探活
curl -fsS http://127.0.0.1:8080/healthz
```

日志位置可直接算出来，不依赖部署方怎么重定向：
`$YANSHU_LOG_DIR/yanshu-server-$(date -u +%F).log`（UTC 日期，跨天自动切新文件，保留 7 天）。
stdout 仍会打一份，容器里可另行重定向，但验收以 `YANSHU_LOG_DIR` 下的文件为准。

| 项 | 值 / 说明 |
|---|---|
| 监听 | 默认 `:8080`（所有网卡）；常驻本机建议显式 `YANSHU_ADDR=127.0.0.1:8080`，与默认不冲突 |
| 端口 | `8080`（`YANSHU_STUN_URLS`/`YANSHU_WS_URL` 与它无关，前者是客户端 ICE 配置） |
| 迁移 | `./bin/yanshu-server -migrate-only`（幂等；启动时也会自动执行） |
| 存储根 | `YANSHU_BLOB_DIR`，布局 `<root>/<transfer_id 前2位>/<transfer_id>/{prelude,chunks/<8位序号>}` |
| 日志 | 默认仅 stdout；`YANSHU_LOG_DIR=<dir>` 时**按日滚动**写 `<dir>/yanshu-server-YYYY-MM-DD.log`（UTC，0640，保留 `YANSHU_LOG_RETENTION_DAYS` 天，默认 7）；也可用 `YANSHU_LOG_FILE=<file>` 指定单文件（优先于 LOG_DIR） |
| 令牌密钥 | `YANSHU_TOKEN_SECRET` 建议落一个 0600 文件；为空则进程内随机，重启后旧 upload_token 失效 |
| 验签 | 验收/联调用 `stub-allow`；默认 `stub-deny`（fail closed）；接真实 SM2 用 `sm2` |

已验证：PostgreSQL 17 @ `127.0.0.1:5432`，库 `yanshu_dev` + 独立 schema，起服务、`-migrate-only`、
投递命令全程跑通（详见 PR #3 描述里的实测摘要）。

## 一条命令投递（验收/Gate 用）

`cmd/deliver` 是投递驱动：它只搬运**已加密的 `.yspk` 包**，不做加解密、不解析清单、不碰私钥。
按 `docs/CRYPTO-PACK.md` 切出 prelude 与块切片，按 `docs/API.md` 走完
注册 → 建传输 → 传 prelude/块 → complete → 凭码查询 → 取件 → ack。

```sh
cd server
go build -o bin/deliver ./cmd/deliver

# 只投递、保留密文（Gate 检索用）；--dsn 只用于打印脱敏 db_url 与 schema
set -a; . /.keys/pg.env; set +a
bin/deliver --base-url http://127.0.0.1:8080 \
  --yspk /tmp/sample.yspk \
  --no-ack \
  --blob-dir "$YANSHU_BLOB_DIR" \
  --dsn "${PG_DEV_DSN}&search_path=yanshu_core" \
  --log /var/log/yanshu/server.log \
  --json-out /tmp/delivery.json

# 全流程（含 ack，结束后密文被物理删除）
bin/deliver --base-url http://127.0.0.1:8080 --yspk /tmp/sample.yspk
```

| 参数 | 说明 |
|---|---|
| `--yspk` | **必填**，端侧产出的加密包路径 |
| `--base-url` | 服务端地址，默认 `http://127.0.0.1:8080` |
| `--recipient-code` | 收件人码；不给则临时生成一个并注册 |
| `--recipient-pubkey` | 收件人公钥 base64url（收件人未注册时用；会校验与码一致） |
| `--sender-code` | 可选，用于核对包内 `SENDER_PUB` 派生的码 |
| `--no-ack` | 取件后不 ack，保留密文给 Gate 检索；**不传就是全流程**：ack 会消耗一次下载次数，达到 `max_downloads` 后进入 `CONSUMED` 并**物理删除密文**，想留证据务必加这个开关 |
| `--blob-dir` | 服务端的 `YANSHU_BLOB_DIR`，用于打印/校验存储路径 |
| `--dsn` | 服务端 DSN，用于打印 `database` / `schema` |
| `--json-out` | 结果写 JSON |
| `--sm3-cmd` | 外部 SM3 命令（hex 进 hex 出），用于与端侧实现对齐 |

**输出契约**：`stdout` **只输出一份 JSON 对象**（单行，字段见下表），`stderr` 输出人读摘要
（`=== DELIVERY ===` 包裹的 `key=value`）。`--json-out <file>` 额外落一份缩进 JSON 到文件
（`--json-out -` 等同默认：只有 stdout）。

JSON 字段：

| 字段 | 含义 |
|---|---|
| `code` | 发送方用户码（由包内 `SENDER_PUB` 派生） |
| `recipient_code` | 接收方用户码 |
| `package_id` | 服务端的 `transfer_id`（32 位小写 hex） |
| `chunks` | 块数 |
| `chunk_size` | 块大小（字节） |
| `plaintext_size` | 明文总长（客户端声明） |
| `prelude_len` | prelude 字节数 |
| `ciphertext_bytes` | 本次上传的密文总量（prelude + 块切片） |
| `state` | 结束状态（`LEASED` / `CONSUMED` / `READY`） |
| `acked` | 是否已 ack |
| `blob_dir` | 服务端存储根（来自 `--blob-dir`） |
| `storage_path` | 本次传输的目录（`<blob_dir>/<id 前2位>/<id>`） |
| `db_url` | **脱敏** DSN（无口令，只留 user@host:port/db?params） |
| `schema` | 实际生效的数据库 schema（连 `--dsn` 查出来的） |
| `log_path` | 服务端日志路径（来自 `--log`）；传目录时自动展开为当日文件 `yanshu-server-YYYY-MM-DD.log` |

stdout（示例，一行 JSON）：

```json
{"ok":true,"base_url":"http://127.0.0.1:8080","code":"0KHJ","recipient_code":"57YV","package_id":"e36350a11e7a44642b1fefdba019c12c","chunks":1,"chunk_size":1024,"plaintext_size":48,"prelude_len":503,"ciphertext_bytes":567,"state":"LEASED","acked":false,"blob_dir":"/var/lib/yanshu/blobs","storage_path":"/var/lib/yanshu/blobs/e3/e36350a11e7a44642b1fefdba019c12c","db_url":"postgres://<user>@127.0.0.1:5432/<db>?search_path=yanshu_core&sslmode=disable","schema":"yanshu_core","log_path":"/var/log/yanshu/server.log"}
```

stderr（人读摘要，同样的值）：

```
=== DELIVERY ===
code=0KHJ
package_id=e36350a11e7a44642b1fefdba019c12c
blob_dir=/var/lib/yanshu/blobs
db_url=postgres://<user>@127.0.0.1:5432/<db>?search_path=yanshu_core&sslmode=disable
log_path=/var/log/yanshu/server.log
================
```

退出码：`0` 成功 / `1` 业务失败 / `2` 用法错误 / `3` 服务不可达 / `4` 服务端验签未就绪
（用 `YANSHU_VERIFIER=stub-allow` 启动即可）。

注意：
- 本工具用**占位签名**，只能配合 `stub-allow`；接真实 SM2 验签后需改真签名。
- 连续跑两次会生成两个不同的 `package_id`，互不冲突；`--no-ack` 的包会留到 TTL 清理。
- 默认（不加 `--no-ack`）会 ack：`download_count` +1，达到上限即 `CONSUMED` 并删除密文；只有
  `max_downloads > 1` 时才会停在 `READY` 等待下一次取件。

### 给自动化脚本的 `--deliver-cmd`

```sh
<repo>/server/bin/deliver --base-url http://127.0.0.1:8080 --yspk <PACK> --no-ack \
  --blob-dir <BLOB_DIR> --dsn "<DSN>" | jq -r '.package_id, .blob_dir, .db_url, .log_path'
```

判定：退出码 `0` 即投递成功；**stdout 是一行 JSON**，可直接 `json.loads` / `jq`。
`--json-out <file>` 只是额外落一份缩进 JSON，不改变 stdout 的形状；`--json-out -` 等同默认。

### 环境变量（实现侧权威清单）

| 变量 | 必需 | 默认 | 说明 / 合法取值 |
|---|---|---|---|
| `YANSHU_DATABASE_URL` | **是** | 无 | PG DSN；建议带 `?search_path=<schema>` 指定独立 schema。缺失 → 启动直接报错退出 |
| `YANSHU_BLOB_DIR` | 否 | `./data/blobs` | 密文块根目录，自动创建；同一实例不要与别的实例共用 |
| `YANSHU_TOKEN_SECRET` | **起服务时必需** | 无 | `upload_token` 的 HMAC 密钥，**≥16 字节**；缺失或过短 → 启动报错退出（不会用空值/随机值静默跑起来）；只从环境变量或 0600 密钥文件读 |
| `YANSHU_ADDR` | 否 | `:8080` | 监听地址；常驻本机写 `127.0.0.1:8080`。**只认这个 env，没有 `--addr` 参数** |
| `YANSHU_VERIFIER` | 否 | `stub-deny` | `sm2` / `stub-deny`（一律拒绝，fail closed）/ `stub-allow`（仅显式开启的测试态，启动打 WARN） |
| `YANSHU_KERNEL_WASM` | `sm2` 时必需 | 自动探测 `./kernel/yanshu_sm.wasm` | 端侧内核路径（wazero 加载，0 import） |
| `YANSHU_LOG_DIR` | 否 | 空（仅 stdout） | 按 UTC 日期滚动写 `yanshu-server-YYYY-MM-DD.log`（0640） |
| `YANSHU_LOG_RETENTION_DAYS` | 否 | `7` | 滚动日志保留天数，只清理本服务命名规则内的文件 |
| `YANSHU_LOG_FILE` | 否 | 空 | 单文件日志（不滚动），优先于 `YANSHU_LOG_DIR` |
| `YANSHU_TRUST_PROXY` | 否 | `false` | 为 `true` 时从 `X-Forwarded-For` 取客户端 IP；**只有前面确有可信反代时才开** |
| `YANSHU_STUN_URLS` | 否 | 公共 STUN | `/v1/config` 下发的 STUN 列表（逗号分隔）；本项目**没有 TURN** |
| `YANSHU_WS_URL` | 否 | 空 | `/v1/config` 下发的 `ws_url` |
| `YANSHU_STORAGE_QUOTA_BYTES` | 否 | `8GiB` | 单 IP 未取走密文总量上限（超出 → `507 INSUFFICIENT_STORAGE`） |
| `YANSHU_SWEEP_INTERVAL` | 否 | `30s` | 清理任务周期（Go duration） |
| `YANSHU_SHUTDOWN_TIMEOUT` | 否 | `10s` | 优雅退出超时（Go duration） |

**限速阈值目前没有 env 开关**：默认值在 `internal/spec/limits.go`（按 IP/按码/按传输各档），
要线上调需要改代码发版；这是 v1 的已知限制，不是漏写。

### 端口与监听

- 默认 `:8080`（所有网卡）。要只监听本机：`YANSHU_ADDR=127.0.0.1:8080`。
- **没有命令行参数覆盖**，端口/地址只认 `YANSHU_ADDR`。
- 健康检查：`GET /healthz`
  - DB 正常 → **200**，body `{"status":"ok","api_version":"v1","contract":"v1"}`
  - DB 不可用 → **503**，body `{"status":"degraded","api_version":"v1","contract":"v1"}`
  - 该端点不校验签名、不查业务表，只 `Ping` 数据库。

### 切到真实 SM2 验签（`YANSHU_VERIFIER=sm2`）

```sh
YANSHU_VERIFIER=sm2 \
YANSHU_KERNEL_WASM=./kernel/yanshu_sm.wasm \
... ./bin/yanshu-server
```

- 走 **路线 B**：纯 Go wasm 运行时（wazero）加载端侧内核 `yanshu_sm.wasm`，
  调 `ys_sm2_verify_der` 验签。服务端**不再维护第二套 SM2 实现**，减少分叉源。
- 内核随仓库提供：`server/kernel/yanshu_sm.wasm`（0 import、`ys_version()=0x00010000`，
  来源与 sha256 见 `server/kernel/README.md`）。
- `YANSHU_KERNEL_WASM` 留空时自动探测 `./kernel/yanshu_sm.wasm` 与可执行文件同级的
  `kernel/yanshu_sm.wasm`；**sm2 模式下找不到内核 → 启动直接报错**（不降级）。
- 公钥：内核 ABI 收 64 字节 `X‖Y`；服务端存的是 65 字节（`0x04‖X‖Y`），调用前剥掉前缀。
  签名：DER `SEQUENCE{r,s}`；userID 固定 `1234567812345678`，`e = SM3(ZA‖SIG_INPUT)`。
- 默认值：`YANSHU_VERIFIER` 缺省 `stub-deny`（一律拒绝，fail closed）；`stub-allow` 只能显式开启
  并打 WARN。三者都非法值 → 启动报错。
- **轮换操作**：同时改 `YANSHU_TOKEN_SECRET`（≥16B）与 `YANSHU_TOKEN_KID`（新版本号，单调递增）
  并重启；旧 token 立刻 `401 AUTH_TOKEN_STALE`，新传输的新 token 立即可用。
  只改 secret 也会失效（`401 AUTH_TOKEN_INVALID`，因为校验按新密钥重算）；详见
  `docs/TOKEN-LIFECYCLE.md` §3.5 的轮换矩阵与 `TestTokenRotationMatrix`。
- **切换清单与 token 失效机制**见 `docs/TOKEN-LIFECYCLE.md`：`upload_token` 由
  `HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1"‖transfer_id)` 派生、库里只存 `SM3` 与
  签发时的 `kid`；**同时轮换 `TOKEN_SECRET` 与 `TOKEN_KID` 会让全部旧 token 立刻
  `401 AUTH_TOKEN_STALE`**（这就是应急吊销手段；与"token 值不对"的
  `AUTH_SIGNATURE_INVALID` 分开）。`TOKEN_KID` 缺失时启动直接报错（fail closed）。
- **schema 只用一套**：`yanshu_core`。`yanshu_core_sm2` 只是本地隔离验证用的临时 schema；
  换验签模式不需要重建 schema。
- 切换影响：
  - 所有写操作必须带**真实签名**（`X-YS-Signature` = base64url(DER)，覆盖 `SIG_INPUT`）；
    占位签名会得到 `401 AUTH_SIGNATURE_INVALID`。
  - `X-YS-Code` 与签名覆盖的 `CODE(4)` 不一致 → `401 AUTH_CODE_MISMATCH`。
  - **没有会话**：雁书没有 session/token 登录态，切换不涉及"旧会话失效"。
  - `upload_token` 按「当前密钥重算 + SM3 比对」校验，**轮换 `TOKEN_SECRET` 会让存量 token 失效**
    （≤ TTL 24h）：旧 token → 401，客户端重建传输即可继续；同 `Idempotency-Key` 重放会返回 409。

### migrations（命令与幂等性）

```sh
# 需先有 schema（只建一次；不建就看 DSN 里 search_path / 默认 public）
psql "$PG_DSN_WITHOUT_SEARCH_PATH" -c 'create schema if not exists yanshu_core'

# 只迁移、不起服务
YANSHU_DATABASE_URL="$PG_DSN_WITH_SEARCH_PATH" ./bin/yanshu-server -migrate-only
```

- **幂等**：`schema_migrations` 表记录已应用的文件，重复执行只会跳过；并发执行有
  `pg_advisory_lock` 兜底。重复跑不会重建表、不会丢数据。
- 不需要单独跑迁移也能起服务：正常启动时会先自动执行一遍同样的迁移。
- `-migrate-only` **不需要** `YANSHU_TOKEN_SECRET`（它不监听端口）。

## 接口

完整清单（字段、错误码、鉴权、状态机）见 `docs/API.md`；速览：

- 配置：`GET /v1/config`
- 鉴权：`POST /v1/challenges`（只绑 purpose；码由客户端签进 `SIG_INPUT`）
- 码：`POST /v1/codes`、`GET|PATCH /v1/codes/{code}`
- 传输：`POST /v1/transfers`、`GET /v1/transfers/{id}`、`GET /v1/inbox`
- 上传：`PUT .../prelude`、`PUT .../chunks/{index}`、`GET .../status`、`POST .../complete`（均用 `X-YS-Upload-Token`）
- 下载：`GET .../prelude`（开租约）、`GET .../chunks/{index}`（需 `X-YS-Download-Id`）、`HEAD .../chunks/{index}`
- 终结：`POST .../ack`（唯一扣次数时机）、`POST .../revoke`
- 运维：`GET /healthz`

### 直传不可用时的降级（契约裁决 D1）

`GET /v1/ws` **立即**返回 `503 SERVICE_UNAVAILABLE`（不挂起、不让客户端等待）。
客户端据此判定直传不可用，静默走中转，并把收件通知改为轮询 `GET /v1/inbox`
（间隔 **≥ 30 秒**，失败退避至 **5 分钟**）。服务端不额外限制 inbox；每次轮询仍需
一次 `INBOX_LIST` 挑战签名（受 IP 20/min 约束，30 秒一次约 2/min，不会误伤）。

## 库表（表结构变更必须在 PR 描述写一行）

`codes`、`auth_challenges`、`transfers`、`transfer_chunks`、`transfer_downloads`、
`idempotency_keys`、`audit_events`（+ `schema_migrations`）。

白名单断言在 `internal/store/schema_test.go`：**多一列即失败**。改表结构时同步改断言，
并在 PR 描述里写明新增/删除的表与列，否则白名单会静默失效（比漏检更危险）。

## 状态机与计数口径

```
UPLOADING --complete--> READY --GET prelude--> LEASED --ack--> READY / CONSUMED
任一非终结态 --revoke--> REVOKED     任一非终结态 --TTL--> EXPIRED
```

`download_count` **只在 ack 成功时 +1**；`LEASED` 期间与租约过期都不扣。
`X-YS-Download-Id` 是 ack 的幂等键：同一 id 重复 ack 只计一次。
三种终结态在内容端点一律 `410`；元数据端点返回 `200` 墓碑（保留 7 天）。

## 存储

```
<YANSHU_BLOB_DIR>/<transfer_id[0:2]>/<transfer_id>/prelude
<YANSHU_BLOB_DIR>/<transfer_id[0:2]>/<transfer_id>/chunks/<8 位块序号>
```

磁盘上只有不透明字节；除了 transfer_id 与块序号，没有任何用户可控字符串。

## 测试与自查

```sh
cd server
go vet ./...
TEST_DATABASE_URL='postgres://yanshu_test:***@127.0.0.1:5432/yanshu_test?sslmode=disable' go test ./...
```

没有 `TEST_DATABASE_URL` 时集成测试自动 skip（单元测试照跑）。每个测试包使用独立 schema，
不会污染 Gate 用的默认 schema。

## Gate 取数（存储根目录与 schema）

Gate 要复跑「库里/盘上查不到文件名与明文」，按下面三步取参数即可（无需读代码）：

1. **存储根目录**：服务端启动时的 `YANSHU_BLOB_DIR`（默认 `<cwd>/data/blobs`）。
   布局固定为 `<BLOB_DIR>/<transfer_id 前 2 位>/<transfer_id>/{prelude,chunks/<8 位序号>}`。
2. **库与 schema**：`YANSHU_DATABASE_URL` 指向的库；schema 由 DSN 的 `search_path` 决定，
   未指定即 `public`。查询示例：
   ```sh
   psql "$YANSHU_DATABASE_URL" -c "select current_database(), current_schema();"
   psql "$YANSHU_DATABASE_URL" -c '\dt'
   psql "$YANSHU_DATABASE_URL" -c 'select transfer_id,state,plaintext_size,prelude_len from transfers limit 5;'
   ```
3. **自查脚本**（也可直接跑测试）：
   ```sh
   find "$YANSHU_BLOB_DIR" -type f            # 只有 prelude 与数字块名
   strings -n 6 $(find "$YANSHU_BLOB_DIR" -type f) | head   # 只会看到你自己上传的密文
   ```
   自动化等价物：`internal/store/schema_test.go`（列名白名单）、
   `internal/httpapi/api_test.go::TestNoFilenameOrPlaintextPersisted`（全库文本列 + 磁盘文件名探针）。

## 未做（本轮明确不做）

- 真实 SM2 验签（接口与桩已就位，接入点 `internal/auth/verifier.go`）。
- WebSocket 信令与在线表：`GET /v1/ws` 目前回 `503 SERVICE_UNAVAILABLE`（降级语义见上）。
- 举报下架（v1 无公开入口）、跨实例限速/配额。
- 前端、WASM、密评相关。
