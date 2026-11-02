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

## 跑起来

```sh
cd server
export YANSHU_DATABASE_URL='postgres://yanshu_dev:***@127.0.0.1:5432/yanshu_dev?sslmode=disable'
export YANSHU_BLOB_DIR='./data/blobs'
export YANSHU_ADDR=':8080'
export YANSHU_TOKEN_SECRET='<random>'
go run ./cmd/yanshu-server
```

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
