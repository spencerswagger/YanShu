# 部署（v1）

面向单实例部署：一个 `yanshu-server` 容器 + 一个 PostgreSQL。

## 1. 一键起（docker compose）

```sh
# 必填：≥16 字节随机串（只作派生盐；轮换它不会吊销既有凭据）
export YANSHU_TOKEN_SECRET="$(head -c 32 /dev/urandom | base64)"

docker compose up -d
docker compose ps
curl -s http://127.0.0.1:18080/healthz          # 期望 {"status":"ok"}
curl -s http://127.0.0.1:18080/v1/config | head  # 含 token_epoch / verifier / kernel_sha256
```

服务启动时会先跑 `-migrate-only` 再起进程（镜像入口脚本），因此**首次启动即完成建表**。
`postgres` 自带 healthcheck，服务通过 `depends_on: condition: service_healthy` 等它就绪。

### 1.1 端口与组件

- 对外**只暴露一个端口**（默认 `18080`）：`web` 容器（nginx）提供界面，并把 `/v1/`、`/healthz`
  反代到内部网络里的 `yanshu-server:8080`。服务端**不 publish 端口**。
- 常驻容器：`postgres`、`yanshu-server`、`web`；另有一次性 `init`（生成密钥 + 修卷属主，跑完退出）。
- 打开 `http://<host>:18080/` 是界面；`/healthz` 经 nginx 直通仍返回 200。

## 2. 环境变量

| 变量 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `YANSHU_DATABASE_URL` | 是 | — | PostgreSQL DSN；compose 内为 `postgres://yanshu:***@postgres:5432/yanshu?sslmode=disable` |
| `YANSHU_TOKEN_SECRET` | 是 | — | `upload_token` 的派生密钥，**≥16 字节**；缺失/过短 → 启动失败 |
| `YANSHU_TOKEN_EPOCH` | 否 | `1` | 凭据版本，正整数且**严格单调递增**；**调小拒绝启动** |
| `YANSHU_VERIFIER` | 否 | `stub-deny` | `sm2` / `stub-deny` / `stub-allow`；`stub-allow` 仅允许 `YANSHU_ENV=local\|test` **且**监听 loopback |
| `YANSHU_KERNEL_WASM` | `sm2` 时是 | 自动探测 `./kernel/yanshu_sm.wasm` | 内核路径；镜像内固定为 `/app/kernel/yanshu_sm.wasm` |
| `YANSHU_BLOB_DIR` | 否 | `./data/blobs` | 密文块目录；compose 挂命名卷 |
| `YANSHU_LOG_DIR` | 否 | 空（只写 stdout） | 按 UTC 日滚动日志目录 |
| `YANSHU_ADDR` | 否 | `:8080` | 监听地址；容器内必须是 `0.0.0.0:8080` 才能映射端口 |
| `YANSHU_ENV` | 否 | 空 | 部署环境标识；`stub-allow` 需 `local\|test` |
| `YANSHU_STORAGE_QUOTA_BYTES` | 否 | `8589934592`（8 GiB） | 单 IP 未取走密文总量上限 |

镜像内的内核 sha256 必须命中内建白名单（当前仅
`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`），否则进程拒绝启动。
自检命令（不需要数据库）：

```sh
docker run --rm --entrypoint /app/yanshu-server yanshu-server:local -verify-kernel
# kernel_sha256=… / ys_version=0x00010000 / exports=35 / allowlisted=true
```

## 3. 全量吊销凭据（递增 EPOCH）

凭据（`upload_token`）的吊销开关是 EPOCH，**在线生效、不需要重启**：

```sh
docker compose exec postgres psql -U yanshu -d yanshu \
  -c "UPDATE token_kid_state SET kid = kid + 1;"
```

- 效果：此前签发的所有 `upload_token` 立刻返回 `401 AUTH_TOKEN_STALE`，新传输用新 EPOCH 签发。
- 已上传的密文块不受影响；客户端拿到 `AUTH_TOKEN_STALE` 应**重建传输**（不要重算签名）。
- `/v1/config` 的 `token_epoch` 会随之变化，可用来观测。
- 若改的是环境变量 `YANSHU_TOKEN_EPOCH`，则需要重启容器；**调小会被拒绝启动**（防止旧凭据复活）。

只换 `TOKEN_SECRET` **不会吊销**既有凭据（它只是派生盐）。

## 4. 镜像与版本策略

- 注册表：`swr.cn-east-5.myhuaweicloud.com/spencerswagger`
- 镜像：`yanshu-server`
- tag 规则：
  - push tag `vX.Y.Z` → `:<tag>`；**正式版**（不以 `-` 结尾段）额外打 `:latest`，预发布（如 `v1.0.0-rc1`）不打 `latest`；
  - 手动触发（workflow_dispatch）→ `:<short-sha>` 与 `:latest`。
- 平台：`linux/amd64`。
- 登录 SWR 用 `SWR_USERNAME`/`SWR_PASSWORD`；**为兼容旧命名，也接受 `DOCKER_USERNAME`/`DOCKER_PASSWORD`**（两者都存在时优先 `SWR_*`）。均未配置时 workflow **只构建不推送**并打 warning，不失败。

前端静态资源：当前服务端**不提供静态文件服务**（无 `web/` 产物进镜像）；若后续引入前端构建产物，
需要另建 `yanshu-web` 镜像或由服务端同端口提供，届时同步更新本文件与 workflow 矩阵。

## 4.1 STUN 与网络

- 默认 STUN 是公共服务器，**部分地区不可用**。替换方式：设置 `YANSHU_STUN_URLS`（逗号分隔，
  只支持 STUN，本项目**没有 TURN**），例如 compose 里加 `YANSHU_STUN_URLS=stun:stun.example.net:3478`。
- 该值只影响 `/v1/config` 下发给客户端的 ICE 配置，不影响服务端连通性。
- 构建镜像需要 BuildKit（`docker buildx` 或 `DOCKER_BUILDKIT=1`）；Dockerfile 已避免 `COPY --chmod`
  这类仅 BuildKit 支持的写法，用 `RUN chmod` 代替。

## 5. v1 限制

- **单实例**：限速额度是进程内内存实现，多副本会让有效额度变成 N 倍且互不同步。
- 不支持 TURN；`stun_urls` 只配置 STUN。
- `/v1/ws`（直传信令）当前返回 503 桩，客户端按轮询处理。

## 6. 冒烟检查

```sh
curl -sf http://127.0.0.1:18080/healthz
docker compose logs --tail=20 yanshu-server | grep "sm2 verifier loaded"   # 期望含 version=0x00010000
curl -s http://127.0.0.1:18080/v1/config | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["token_epoch"], d["verifier"], d["kernel_sha256"][:16])'
```

## 7. 前置反向代理（外层 nginx）

服务前面再挂一层 nginx（TLS 终止 + 统一入口）时的要点。示例配置见
`deploy/nginx-front.conf.example`（不含真实域名/证书路径）。

① **端口只绑本机**：`YANSHU_PORT=127.0.0.1:18080 docker compose up -d`，不要公网直接暴露 18080。
   开启 `YANSHU_TRUST_PROXY=true` 后服务端会采信 `X-Forwarded-For`，直接暴露等于把限速/配额交给客户端伪造。

② **`client_max_body_size`**：内层已是 32m，**外层不能小于它**（nginx 默认 1m，会让分块上传直接 413）。

③ **缓冲与超时**：外层需 `proxy_request_buffering off; proxy_buffering off;`，
   并把 `proxy_send_timeout` / `proxy_read_timeout` 放大到 300s（大文件上传/下载）。

④ **Range 透传**：分段下载依赖 `Range` / `If-Range`，不要在外层做响应缓存或改写这两个头。

⑤ **WebSocket**：`/v1/ws` 目前返回 503 桩，但外层仍应透传 `Upgrade` / `Connection`（预留）。

⑥ **TLS 只在外层终止**：内层 compose 的 web 容器只监听 HTTP 80（映射到本机 18080），不需要证书。

⑦ **CSP**：内层下发 `connect-src 'self'` 与 `frame-ancestors 'none'` —— 前端若从**其他域名/端口**
   访问，或因需要被 iframe 嵌入，都会被浏览器拦；这类场景要改 `web/nginx.conf` 的 CSP，而不是只改外层。

### 7.1 X-Forwarded-For 取值链（决定真实 IP 是否正确）

服务端 `clientIP()`（`server/internal/httpapi/api.go:86`）在 `YANSHU_TRUST_PROXY=true` 时取
**第一跳（最左）**，遇到第一个 `,` 即截断。

因此链路必须是：**外层覆盖写 → 内层原样透传**：

- 外层：`proxy_set_header X-Forwarded-For $remote_addr;`（直接赋值，同时清掉客户端伪造的头）
- 内层（`web/nginx.conf`）：上游给了 XFF 就原样传（`$http_x_forwarded_for`），无上游时用 `$remote_addr`
  —— 不再用 `$proxy_add_x_forwarded_for` 追加，否则真实 IP 会被挤到后面，服务端取到的是内层看到的地址。

校验：`go test ./internal/httpapi -run TestClientIPUsesFirstHop`。

