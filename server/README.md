# 雁书 · 服务端（Core）

中转服务端：**只做码/公钥登记、密文块存取、TTL/次数策略、审计与限速**。
它不解析 prelude，不解析块，不实现加密——文件名与明文从头到尾不上行、不落库、不落盘。

## 状态

骨架阶段。对外契约是**暂定值**，`docs/API.md` 冻结后按 `docs/DRAFT-FIELDS.md` 的清单对齐；
全部对外名字集中在 `internal/spec/`，对齐时只改那一处。

## 目录

```
server/
├── cmd/yanshu-server/      # 入口：配置 → 迁移 → 路由 → 清理任务 → 优雅退出
├── internal/spec/          # ★ 对外契约唯一来源（路径/字段/错误码/限值/WS 消息类型）
├── internal/gm/            # 自研 SM3 + Crockford 码派生与归一化
├── internal/auth/          # 挑战消息、会话令牌、SM2 验签接口 + 桩
├── internal/store/         # PG 持久层 + migrations
├── internal/blob/          # 密文块磁盘存储（不透明字节）
├── internal/httpapi/       # HTTP 接口、鉴权边界、限速
├── internal/ratelimit/     # 令牌桶 + 失败锁定（内存版）
├── internal/cleanup/       # TTL/终结态清道夫（真删）
└── internal/testutil/      # 集成测试夹具（独立 schema）
```

## 跑起来

```sh
cd server
export YANSHU_DATABASE_URL='postgres://yanshu_dev:***@127.0.0.1:5432/yanshu_dev?sslmode=disable'
export YANSHU_BLOB_DIR='./data/blobs'
export YANSHU_ADDR=':8080'
go run ./cmd/yanshu-server
```

启动会打印 `wire contract is DRAFT ...` 与验签模式警告（如果用了 `stub-allow`）。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `YANSHU_ADDR` | `:8080` | 监听地址 |
| `YANSHU_DATABASE_URL` | 无（必填） | PG DSN |
| `YANSHU_BLOB_DIR` | `./data/blobs` | 密文块根目录 |
| `YANSHU_VERIFIER` | `stub-deny` | `sm2` / `stub-deny`（fail closed）/ `stub-allow`（仅测试） |
| `YANSHU_CODE_STRICT` | `false` | true 时只接受已归一化的 4 位码 |
| `YANSHU_TRUST_PROXY` | `false` | 是否信任 `X-Forwarded-For` |
| `YANSHU_CODE_TTL` | `720h` | 码有效期 |
| `YANSHU_PACKAGE_TTL` | `24h` | 包默认 TTL |
| `YANSHU_SESSION_TTL` | `24h` | 会话有效期 |
| `YANSHU_CHALLENGE_TTL` | `5m` | 挑战有效期 |
| `YANSHU_MAX_PACKAGE_BYTES` | `4GiB` | 单包密文上限 |
| `YANSHU_MAX_PRELUDE_BYTES` | `8MiB` | prelude 上限 |
| `YANSHU_MAX_CHUNK_BYTES` | `1MiB+16` | 单块切片上限 |
| `YANSHU_STORAGE_QUOTA_BYTES` | `8GiB` | 单发送方在途配额 |
| `YANSHU_SWEEP_INTERVAL` | `30s` | 清理任务周期 |
| `YANSHU_SHUTDOWN_TIMEOUT` | `10s` | 优雅退出超时 |

## 接口

完整清单（含字段、错误码、鉴权边界）见 `docs/DRAFT-FIELDS.md`。速览：

- 码：`POST /api/v1/codes`、`GET|PATCH /api/v1/codes/{code}`
- 鉴权：`POST /api/v1/auth/challenges`、`POST /api/v1/auth/sessions`
- 包：`POST /api/v1/packages`、`GET /api/v1/packages/{id}`、`GET /api/v1/inbox`
- 传：`PUT|GET .../prelude`、`PUT|GET .../chunks/{index}`、`POST .../commit`、`GET .../progress`
- 终结：`POST .../ack`、`POST .../revoke`
- 健康：`GET /healthz`

## 安全边界（写死在代码里）

1. **不存私钥相关物**：库里只有公钥、昵称、尺寸、计数、状态、时间、密文摘要。
2. **不存文件名/明文**：文件名与 MIME 在端侧加密清单里；服务端只接收 prelude 与块切片。
3. **终结即不可下载**：`expired` / `revoked` / `exhausted` 三种终结态一律 410，随后物理删除。
4. **写操作要私钥证明**：建包/传块/commit/revoke 需要发送方会话；ack 需要接收方会话；改昵称还要绑定新昵称的签名挑战。
5. **日志不打印敏感值**：只记路由模板、状态、耗时、字节数、请求 ID；不记路径参数、请求体、令牌。
6. **验签 fail closed**：`YANSHU_VERIFIER` 默认 `stub-deny`，SM2 未接入时不会"误放行"。

## 存储

```
<YANSHU_BLOB_DIR>/<pkg[0:2]>/<pkg>/prelude
<YANSHU_BLOB_DIR>/<pkg[0:2]>/<pkg>/chunks/<8 位块序号>
```

磁盘上只有不透明字节；除了包 ID 与块序号，没有任何用户可控字符串。

## 测试与自查

```sh
cd server
go vet ./...
TEST_DATABASE_URL='postgres://yanshu_test:***@127.0.0.1:5432/yanshu_test?sslmode=disable' go test ./...
```

没有 `TEST_DATABASE_URL` 时集成测试自动 skip（单元测试照跑）。集成测试每个包使用独立 schema，
不会污染 Gate 用的默认 schema。

### 「库里/盘上查不到文件名与明文」怎么验证

- `internal/store/schema_test.go`：**列名白名单**断言——库里只允许出现列出的那些列，多一列就红；
  另有第二道闸禁止 `filename/mime/content/body/plaintext_data` 这类语义的列名。
- `internal/httpapi/api_test.go` → `TestNoFilenameOrPlaintextPersisted`：走完整上传/下载流程后，
  扫描当前 schema 所有 text/bytea 列与磁盘文件名，确认探针字符串（`secret-report.pdf` 等）不出现；
  并断言包目录里只可能有 `prelude` 与 `chunks` 两项。
- `internal/blob/disk_test.go`：断言磁盘布局只有 `<id>/chunks/<序号>`，且路径穿越 ID 被拒。

人工复核可以这样：

```sh
# 库里
psql "$YANSHU_DATABASE_URL" -c '\dt'
psql "$YANSHU_DATABASE_URL" -c 'select * from packages limit 1;'   # 只有尺寸/状态/时间
# 盘里
find "$YANSHU_BLOB_DIR" -type f | head
strings -n 6 $(find "$YANSHU_BLOB_DIR" -type f) | head             # 只会看到你自己上传的密文
```

## 未做（本轮明确不做）

- 真实 SM2 验签（接口与桩已就位，接入点 `internal/auth/verifier.go`）。
- WebSocket 信令与在线表（只留消息类型 + 501 桩）。
- 举报下架、跨实例限速/配额（接口已留，实现待补）。
- 前端、WASM、密评相关。
