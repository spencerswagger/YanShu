# 雁书（YanShu）

一次性加密文件互传：发送方在浏览器里加密，服务端只做**不透明中转**，接收方凭 4 位码取回后在本机解密。
不做账号、不做云端明文、取走即删。

**状态**：可运行 ｜ **许可**：内部项目，未附带开源许可 ｜ **镜像**：`swr.cn-east-5.myhuaweicloud.com/spencerswagger/yanshu-server:<tag>`

## 1. 是什么（30 秒版）

- 服务端**只存密文块**：不解析包内容、不落文件名、不落明文、不持有任何私钥。
- 国密全自研：SM4-GCM 加密、SM3 摘要、SM2 签名验签（服务端用加载端侧内核的方式验签，不维护第二套 SM2）。
- 4 位 Crockford Base32 用户码 + 一次性传输：TTL、下载次数、撤回三种终结方式，`ack` 后物理删除。
- 默认走服务端中转；浏览器之间尝试直连，通了会提示切换（无 TURN，只配 STUN）。
- **边界**：不做账号体系、不做云盘、不做 TURN 中继、不做国密合规测评、v1 不支持多副本横向扩展。

## 2. 快速开始（零配置，三行）

```sh
mkdir yanshu && cd yanshu
# 带上时间戳/禁缓存，避免拿到 CDN 上的旧版本
curl -fsSL -H 'Cache-Control: no-cache' -o docker-compose.yml \
  "https://raw.githubusercontent.com/spencerswagger/YanShu/main/docker-compose.yml?cb=$(date +%s)"
grep -q PG_PW_ENC docker-compose.yml || { echo "拿到的是旧版 compose，请重试"; exit 1; }
docker compose up -d
```

- 首次启动自动生成密钥到当前目录 **`./secrets/`**（`token_secret` / `pg_password`，属主 10001、权限 600）——**别删**；
  重启用同一份，`docker compose down -v` + 删 `./secrets` 才算彻底重来。
- **打开 `http://<host>:18080/` 就是界面**（nginx 提供静态页，并把 `/v1`、`/healthz` 反代给服务端）。
- 起来后自检：
  ```sh
  curl -s http://127.0.0.1:18080/healthz      # {"status":"ok","api_version":"v1","contract":"v1"}
  docker compose logs yanshu-server | grep -i "sm2 verifier loaded"   # version=0x00010000
  ```
- **所有镜像都来自国内源**（华为云 SWR，含 postgres 与 app 镜像；不需要访问 Docker Hub）。
- 端口/镜像标签可选覆盖（不写也能跑）：`YANSHU_PORT=8000 docker compose up -d`，或写一个 `.env`（见 `.env.example`）。
- 要**改代码自己构建**才用 dev override：`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`。

出问题看 §7 排错。

## 3. 环境要求

| 依赖 | 版本 | 说明 |
|---|---|---|
| Go | 1.27 | 编译服务端（`server/go.mod` 声明 `go 1.27`） |
| PostgreSQL | 16 | 存码、传输元数据、审计；**必须**，无内置存储替代 |
| Docker | 24+（可选） | 只用容器部署时需要；构建镜像建议启用 BuildKit |
| 冻结内核 | `server/kernel/yanshu_sm.wasm`，140,762 B，sha256 `daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de`（白名单另收 `8766048f…` 回滚版与 `c1b87d0a…` 灰度版） | `YANSHU_VERIFIER=sm2` 时必需，仓库已附带 |

## 4. 本地开发（从源码直接跑，不用 Docker）

前提：本机有 PostgreSQL 16 与 Go 1.27（见 §3）。

```sh
# 1) 编译（在仓库根目录）
cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server

# 2) 建库（示例用本机 postgres；换成你自己的 DSN）
createdb yanshu

# 3) 起服务（自检最小配置）
export YANSHU_DATABASE_URL="postgres://$USER@127.0.0.1:5432/yanshu?sslmode=disable"
export YANSHU_TOKEN_SECRET="$(head -c 32 /dev/urandom | base64)"   # ≥16 字节
export YANSHU_VERIFIER=sm2
export YANSHU_KERNEL_WASM=./kernel/yanshu_sm.wasm
./yanshu-server -migrate-only        # 建表；成功输出 msg="migrations applied"
./yanshu-server                      # 起服务，默认监听 :8080

# 4) 验证成功（看到这个响应就算起来了）
curl -s http://127.0.0.1:8080/healthz
# {"status":"ok","api_version":"v1","contract":"v1"}
```

启动日志里应同时出现这两行（内核版本与哈希校验）：

```
msg="sm2 verifier loaded" kernel=./kernel/yanshu_sm.wasm version=0x00010000
msg="kernel verified" sha256=daa94926…31de version=0x00010000 exports=44
```

需要你改的地方：`YANSHU_DATABASE_URL`（换成真实 DSN）、`YANSHU_TOKEN_SECRET`（换成固定随机值并存好）。

### 4.1 其他常用命令

```sh
# 在 server/ 下执行
cd server

# 只跑数据库迁移（不启动服务）
YANSHU_DATABASE_URL="postgres://$USER@127.0.0.1:5432/yanshu?sslmode=disable" \
  go run ./cmd/yanshu-server -migrate-only

# 校验内核（不连数据库，CI 可用）
YANSHU_KERNEL_WASM=./kernel/yanshu_sm.wasm go run ./cmd/yanshu-server -verify-kernel
# kernel_sha256=daa94926…31de / ys_version=0x00010000 / exports=44 / allowlisted=true

# 起服务（stub-allow 只能本地调试：要求 YANSHU_ENV=local|test 且监听 loopback）
YANSHU_VERIFIER=stub-allow YANSHU_ENV=local YANSHU_ADDR=127.0.0.1:8080 \
YANSHU_TOKEN_SECRET=0123456789abcdef0123456789abcdef \
YANSHU_DATABASE_URL="postgres://$USER@127.0.0.1:5432/yanshu?sslmode=disable" \
  go run ./cmd/yanshu-server

# 测试（集成测试需要 TEST_DATABASE_URL，没有则自动 skip）
TEST_DATABASE_URL="postgres://$USER@127.0.0.1:5432/yanshu_test?sslmode=disable" go test ./... -count=1
```

端口：默认 `:8080`（`YANSHU_ADDR`）。测试库与开发库建议分开，测试会各自建 schema 隔离。

## 5. 配置项

| 变量 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `YANSHU_DATABASE_URL` | **必填** | — | PostgreSQL DSN；缺失 → 启动失败退出 |
| `YANSHU_TOKEN_SECRET` | **必填** | — | `upload_token` 派生密钥，**≥16 字节**；缺失/过短 → 启动失败退出 |
| `YANSHU_TOKEN_EPOCH` | 否 | `1` | 凭据版本，正整数且**严格递增**；**小于库内已记录值 → 拒绝启动**（防旧凭据复活）。旧名 `YANSHU_TOKEN_KID` 可读 |
| `YANSHU_VERIFIER` | 否 | `stub-deny` | `sm2`（真验签）/ `stub-deny`（全拒）/ `stub-allow`（全放行，仅 `YANSHU_ENV=local\|test` 且 loopback 可用） |
| `YANSHU_KERNEL_WASM` | `sm2` 时必填 | 自动探测 `./kernel/yanshu_sm.wasm` | 内核路径；镜像内为 `/app/kernel/yanshu_sm.wasm`；sha256 不在白名单 → 拒绝启动 |
| `YANSHU_BLOB_DIR` | 否 | `./data/blobs` | 密文块目录（需持久化） |
| `YANSHU_LOG_DIR` | 否 | 空（只写 stdout） | 按 UTC 日滚动写 `<dir>/yanshu-server-YYYY-MM-DD.log` |
| `YANSHU_ADDR` | 否 | `:8080` | 监听地址；容器内需 `0.0.0.0:8080` 才能映射端口 |
| `YANSHU_ENV` | 否 | 空 | 部署环境标识；`stub-allow` 需 `local\|test` |
| `YANSHU_STUN_URLS` | 否 | `stun:stun.l.google.com:19302` | 下发给客户端的 STUN 列表（逗号分隔）；**不支持 TURN** |
| `YANSHU_WS_URL` | 否 | 空（`ws_url: null`） | 直传信令地址，如 `wss://host/v1/ws`；为空时客户端按契约 §9.6 直接走中转 |
| `YANSHU_STORAGE_QUOTA_BYTES` | 否 | `8589934592`（8 GiB） | 单 IP 未取走密文总量上限 |
| `YANSHU_SWEEP_INTERVAL` | 否 | `30s` | 过期清理扫描间隔 |

敏感值只从环境变量或 0600 文件读取，仓库里没有任何真实凭据。

## 6. 部署

### 6.1 镜像与标签

- 完整地址：`swr.cn-east-5.myhuaweicloud.com/spencerswagger/yanshu-server:<tag>`
- 标签规则（`.github/workflows/build-images.yml`）：
  - push tag `vX.Y.Z` → `:<tag>`；**正式版**额外打 `:latest`，预发布（如 `v1.0.0-rc1`）**不打** `latest`；
  - 手动触发（workflow_dispatch）→ `:<short-sha>` 与 `:latest`。
- 平台 `linux/amd64`；仓库目前**私有**，拉取前先 `docker login swr.cn-east-5.myhuaweicloud.com`
  （或把仓库设为公开后匿名拉取）。
- 镜像由 CI 构建并推送（workflow `build-images`，run `41568888831`）：登录成功
  （`Login Succeeded!`），推送了 `:latest` 与 `:f47d0f3`，digest `sha256:802ee7d2…`。
- CI 未配置 `SWR_USERNAME`/`SWR_PASSWORD` 时**只构建不推送**（job 仍成功，Summary 里标注“未推送”）。

### 6.2 升级与回滚

- 升级：改 `docker-compose.yml` 的 `image:` 标签（或 `docker compose pull` 后 `up -d`）；迁移随启动自动执行。
- 回滚：把标签改回上一个版本并 `up -d`；迁移是**只增不改**的，旧版本可继续运行。

## 7. 运维与排错

- **健康检查**：`GET /healthz` → `{"status":"ok","api_version":"v1","contract":"v1"}`；数据库不通时为 `503` + `degraded`。
- **运行信息**：`GET /v1/config` 返回 `token_epoch`、`verifier`、`env`、`kernel_sha256`、`kernel_version`、`kernel_exports`。
- **日志**：`YANSHU_LOG_DIR` 下按日滚动，保留 7 天（`YANSHU_LOG_RETENTION_DAYS`）。

**全量吊销凭据**（`upload_token`）：递增 EPOCH，在线生效、**不需要重启**：

```sh
docker compose exec postgres psql -U yanshu -d yanshu \
  -c "UPDATE token_kid_state SET kid = kid + 1;"
```

此后旧凭据一律 `401 AUTH_TOKEN_STALE`，客户端应重建传输；已上传密文块不受影响。
若改的是 `YANSHU_TOKEN_EPOCH` 环境变量则需重启，且**调小会被拒绝启动**。

常见报错 → 原因 → 处置（以下四条均为实际部署中遇到过的）：

| 现象 | 原因 | 处置 |
|---|---|---|
| 打开 `http://<host>:18080/` 是 **404** | 只起了服务端、没起 web 容器；或 nginx 配置未生效 | `docker compose ps` 确认 `web` 在跑（应为 3 个容器：postgres/server/web）；只 publish web 的 18080 端口 |
| `docker compose pull` 报 `unauthorized` / `denied` | 仓库是私有的，未登录就匿名拉取 | `docker login swr.cn-east-5.myhuaweicloud.com`，或把仓库设为公开 |
| `docker compose up` 直接退出，提示 `set YANSHU_TOKEN_SECRET` | `.env`/环境中缺 `YANSHU_TOKEN_SECRET`（必填，≥16 字节） | 补上该变量；compose 里用的是 `${YANSHU_TOKEN_SECRET:?…}`，缺失会立即失败 |
| 启动即退出，`kernel sha256 … is not in the frozen allowlist`（或内核文件不存在） | 内核缺失，或不是冻结产物（从错误目录构建会得到不同字节） | 用仓库内 `server/kernel/yanshu_sm.wasm`（140,762 B / `daa94926…31de`）；镜像内应为 `/app/kernel/yanshu_sm.wasm`；可用 `-verify-kernel` 自检 |
| 启动即退出，`YANSHU_VERIFIER=stub-allow requires YANSHU_ENV=local\|test`（或要求 loopback） | 在容器/非本地环境开了全放行 | 容器部署一律 `YANSHU_VERIFIER=sm2`；`stub-allow` 只在 `local\|test` + loopback 调试用 |

其余业务侧报错：

| 现象 | 原因 | 处置 |
|---|---|---|
| `401 AUTH_TOKEN_STALE` | 凭据版本（EPOCH）被轮换 | 重建传输取新凭据，不要重算签名 |
| `401 AUTH_TOKEN_INVALID` | 凭据值不对（串了传输/伪造） | 检查本地 token 与 transfer_id 是否配对 |
| `401 AUTH_TOKEN_EXPIRED` | 上传凭据超过 6 小时，或下载租约超过 30 分钟 | 重建传输 / 重新取租约 |
| `410 TRANSFER_EXPIRED` / `410 TRANSFER_CONSUMED` | 传输终态（过期或已取完） | 重新发起一次传输；终态不可恢复 |
| `401 AUTH_CODE_MISMATCH` | `X-YS-Code` 与签名覆盖的码不一致 | 签名用的头码必须与请求头一致 |
| `401 AUTH_SIGNATURE_INVALID` | 签名本身不被接受 | 检查 `SIG_INPUT` 拼装与私钥；与 token 无关 |

备份：备份 PostgreSQL（`pg_dump`）与 `blobdata` 卷；两者需成对恢复，否则元数据与密文块会错位。

## 8. 测试与验收

```sh
cd server
go build ./... && go vet ./... && go test ./... -count=1      # 单元 + 集成（需 TEST_DATABASE_URL）
go test ./internal/auth/ -run TestVerifyVectors -v            # 验签向量（加载冻结内核）
go test ./internal/gm/ -run 'TestSM3Vectors|TestNormalizeCodeVectors' -v   # 摘要与码归一化向量
./yanshu-server -verify-kernel                                # 内核 sha256/版本/导出数自检
```

- 集成测试按包各自建 schema，不污染开发库；没有 `TEST_DATABASE_URL` 时自动 skip。
- 端到端可用 `server/scripts/token-rotation-check.sh` 自起停四轮，验证凭据轮换与 EPOCH 吊销。
- 契约与协议细节见 `docs/API.md`；凭据生命周期见 `docs/TOKEN-LIFECYCLE.md`；部署细节见 `docs/DEPLOY.md`。

## 9. 目录结构

| 路径 | 内容 |
|---|---|
| `server/` | Go 服务端（唯一可执行入口 `cmd/yanshu-server`，另有 `cmd/deliver` 投递驱动） |
| `server/internal/` | `spec`（路径/错误码/限值）、`auth`（SIG_INPUT/token/验签）、`store`（PG）、`httpapi`（路由）、`blob`（磁盘密文块） |
| `server/kernel/` | 端侧内核副本 `yanshu_sm.wasm`（验签用，入库，sha256 白名单校验） |
| `server/scripts/` | 可复跑脚本（凭据轮换对照） |
| `crypto/` | 端侧国密实现（SM2/SM3/SM4-GCM）与内核源码 |
| `web/` | 浏览器端（加密、分块上传、取回解密） |
| `docs/` | 契约（`API.md`、`CRYPTO-PACK.md`）、部署（`DEPLOY.md`）、凭据生命周期、ADR |
| `qa/` | 可复跑验收脚本与结果记录 |
| `docker-compose.yml` | 本地/单机部署（postgres + 服务端） |
| `.github/workflows/` | 镜像构建（tag / 手动触发） |
