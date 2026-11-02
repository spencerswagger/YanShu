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
YANSHU_LOG_FILE=/var/log/yanshu/server.log \
YANSHU_VERIFIER=stub-allow \
YANSHU_TOKEN_SECRET="$(cat /var/lib/yanshu/token-secret)" \
./bin/yanshu-server

# 5) 探活
curl -fsS http://127.0.0.1:8080/healthz
```

| 项 | 值 / 说明 |
|---|---|
| 监听 | 默认 `:8080`（所有网卡）；常驻本机建议显式 `YANSHU_ADDR=127.0.0.1:8080`，与默认不冲突 |
| 端口 | `8080`（`YANSHU_STUN_URLS`/`YANSHU_WS_URL` 与它无关，前者是客户端 ICE 配置） |
| 迁移 | `./bin/yanshu-server -migrate-only`（幂等；启动时也会自动执行） |
| 存储根 | `YANSHU_BLOB_DIR`，布局 `<root>/<transfer_id 前2位>/<transfer_id>/{prelude,chunks/<8位序号>}` |
| 日志 | stdout + `YANSHU_LOG_FILE`（追加写，自动建目录，文件权限 0640） |
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
| `--no-ack` | 取件后不 ack，保留密文给 Gate 检索 |
| `--blob-dir` | 服务端的 `YANSHU_BLOB_DIR`，用于打印/校验存储路径 |
| `--dsn` | 服务端 DSN，用于打印 `database` / `schema` |
| `--json-out` | 结果写 JSON |
| `--sm3-cmd` | 外部 SM3 命令（hex 进 hex 出），用于与端侧实现对齐 |

stdout 字段固定（Gate 按名字解析，`=== DELIVERY ===` 与 `================` 之间）：

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
| `log_path` | 服务端日志路径（来自 `--log`） |

输出（示例）：

```
=== DELIVERY ===
code=0KHJ
recipient_code=57YV
package_id=e36350a11e7a44642b1fefdba019c12c
chunks=1
chunk_size=1024
plaintext_size=48
prelude_len=503
ciphertext_bytes=567
state=LEASED
acked=false
blob_dir=/var/lib/yanshu/blobs
storage_path=/var/lib/yanshu/blobs/e3/e36350a11e7a44642b1fefdba019c12c
db_url=postgres://<user>@127.0.0.1:5432/<db>?search_path=yanshu_core&sslmode=disable
schema=yanshu_core
log_path=/var/log/yanshu/server.log
================
```

退出码：`0` 成功 / `1` 业务失败 / `2` 用法错误 / `3` 服务不可达 / `4` 服务端验签未就绪
（用 `YANSHU_VERIFIER=stub-allow` 启动即可）。

注意：
- 本工具用**占位签名**，只能配合 `stub-allow`；接真实 SM2 验签后需改真签名。
- 连续跑两次会生成两个不同的 `package_id`，互不冲突；`--no-ack` 的包会留到 TTL 清理。

### 给自动化脚本的 `--deliver-cmd`

```sh
<repo>/server/bin/deliver --base-url http://127.0.0.1:18080 --yspk <PACK> --no-ack \
  --blob-dir <BLOB_DIR> --dsn '<DSN>' --json-out <OUT_JSON>
```

判定：退出码 `0` 即投递成功；`--json-out` 里的 `package_id` / `storage_path` / `schema` / `db_url`
可直接作为后续检索的入参（JSON 与 stdout 同名字段）。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `YANSHU_ADDR` | `:8080` | 监听地址 |
| `YANSHU_DATABASE_URL` | 无（必填） | PG DSN |
| `YANSHU_BLOB_DIR` | `./data/blobs` | 密文块根目录 |
| `YANSHU_VERIFIER` | `stub-deny` | `sm2` / `stub-deny`（fail closed）/ `stub-allow`（仅测试） |
| `YANSHU_TOKEN_SECRET` | 进程内随机 | `upload_token` 的 HMAC 密钥；为空时重启后旧 token 失效 |
| `YANSHU_TRUST_PROXY` | `false` | 是否信任 `X-Forwarded-For` |
| `YANSHU_STUN_URLS` | 公共 STUN | `/v1/config` 下发的 STUN 列表（**没有 TURN**） |
| `YANSHU_WS_URL` | 空 | `/v1/config` 下发的 `ws_url` |
| `YANSHU_STORAGE_QUOTA_BYTES` | `8GiB` | 单 IP 未取走密文总量上限（超出 → `507`） |
| `YANSHU_SWEEP_INTERVAL` | `30s` | 清理任务周期 |
| `YANSHU_SHUTDOWN_TIMEOUT` | `10s` | 优雅退出超时 |

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
- WebSocket 信令与在线表：`GET /v1/ws` 目前回 `503 SERVICE_UNAVAILABLE`。
- 举报下架（v1 无公开入口）、跨实例限速/配额。
- 前端、WASM、密评相关。
