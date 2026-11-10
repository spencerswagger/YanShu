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

界面由 `yanshu-web` 镜像提供（nginx 静态站 + `/v1`、`/healthz` 反代到服务端）；compose 对外只发布 web 的 `${YANSHU_PORT:-18080}:80`，服务端仅在内部网络监听。
当前推荐版本：`v0.2.2`（见 Release）；`v0.2.1`、`v0.2.0` 保留可回滚（改 `YANSHU_IMAGE_TAG=v0.2.1` 即可）；`v0.1.2` 已作废，勿用。

**v0.2.1 镜像 digest（核验用，来源：tag 触发的 `build-images` run `42881934667`，两条 leg 均 success）**

| 镜像 | digest |
|---|---|
| `yanshu-server:v0.2.1` | `sha256:022f7424abf63bd1c6e4f175ee9a57cca87934b87d984fc27b44a531327e8a37` |
| `yanshu-web:v0.2.1` | `sha256:bb0fd73f4be252aa54f4c7b3e992582836678d0ba3a537edf6cd846cf8cebfe8` |

核验：`docker buildx imagetools inspect swr.cn-east-5.myhuaweicloud.com/spencerswagger/yanshu-server:v0.2.1`（需先 `docker login` SWR，仓库是私有的，匿名拉取 401）。
`:latest` 与 `v0.2.1` 同一 digest。

**v0.2.0 镜像 digest（核验用，来源：tag 触发的 `build-images` run `42758758565`，两条 leg 均 success）**

| 镜像 | digest |
|---|---|
| `yanshu-server:v0.2.0` | `sha256:c2f781ff7f2f9938720319f7fe0a8dc88e67a5ea64d9a312154f8cf56c24cffb` |
| `yanshu-web:v0.2.0` | `sha256:59c4edc46c4f38d841a54aa0e8aa0380452348c03c1d8d22c4c26cf7bb924efc` |

核验：`docker buildx imagetools inspect swr.cn-east-5.myhuaweicloud.com/spencerswagger/yanshu-server:v0.2.0`（需先 `docker login` SWR，仓库是私有的，匿名拉取 401）。

## 4.1 STUN 与网络

- `YANSHU_WS_URL`：直传信令地址（`wss://<你的域名>/v1/ws`）。**不设则 `config.ws_url` 为 null**，
  客户端按契约 §9.6 直接走中转（功能不受影响，只是没有直传与在线通知）。
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

## 7. 前置反向代理（CDN → 外层 nginx → 容器）

线上拓扑：**客户端 → CDN（终止 TLS）→ 本机 nginx(:80) → web 容器(:18080) → 服务端**。
示例配置见 `deploy/nginx-front.conf.example`。

① **端口只绑本机**：`YANSHU_PORT=127.0.0.1:18080 docker compose up -d`。开启
   `YANSHU_TRUST_PROXY=true` 后服务端采信 `X-Forwarded-For`，公网直暴露等于把限速/配额交给客户端伪造。

② **对外只听 80**：TLS 由 CDN 终止，机器上不放证书。只有「客户端直连本机、不经 CDN」时才需要
   自己起 443（示例里那段是注释掉的）。

③ **`client_max_body_size`**：内层 32m，外层不得小于它（nginx 默认 1m → 分块上传 413）。
   **CDN 侧同样要放大**（例：Cloudflare 免费版单请求 100 MB），否则大文件在 CDN 就被拒。

④ **CDN 缓存规则必须排除 `/v1/` 与 `/healthz`**：前者被缓存会拿到过期响应（撤回/取件/ack 全错），
   后者被缓存会让健康检查假活。

⑤ **缓冲与超时**：外层 `proxy_request_buffering off; proxy_buffering off;`，
   `proxy_send_timeout`/`proxy_read_timeout` 放大到 300s。

⑥ **Range 透传**：分段下载依赖 `Range`/`If-Range`，不要在外层做响应缓存或改写这两个头。

⑦ **WebSocket**：v1 **未启用**（`/v1/ws` 只是 503 占位），示例里的 `Upgrade`/`Connection` 三行是注释；
   真启用时再加 `map $http_upgrade …`（`map` 必须在 `http {}` 层）。

⑧ **CSP**：内层下发 `connect-src 'self'` 与 `frame-ancestors 'none'`；跨域或被 iframe 嵌入会被浏览器拦，
   这类场景要改 `web/nginx.conf`，而不是只改外层。

### 7.1 X-Forwarded-For 取值链

服务端 `clientIP()`（`server/internal/httpapi/api.go:86`）在 `YANSHU_TRUST_PROXY=true` 时取
**第一跳（最左）**，遇第一个 `,` 截断。拓扑里有两层代理，取值必须按 CDN 行为二选一：

- **方案 A（推荐）**：CDN 提供专用客户端 IP 头（Cloudflare `CF-Connecting-IP`、阿里云 `Ali-CDN-Real-IP`）
  → 外层用该头赋值 `X-Forwarded-For`（无该头时回落 `$remote_addr`）。示例里用 `map` 实现。
- **方案 B**：CDN 只写/覆盖 `X-Forwarded-For` → 外层原样透传（`$http_x_forwarded_for`，空则 `$remote_addr`）。

无论哪种，**不要在 CDN 已给出真实 IP 的情况下再用 `$remote_addr` 覆盖**——那会写成 CDN 节点 IP，
限速与审计就全按 CDN 节点记。内层（`web/nginx.conf`）保持「有上游 XFF 就透传」即可。

校验：`go test ./internal/httpapi -run TestClientIPUsesFirstHop`。

> 注意：`map` 只能写在 `http {}` 层；`deploy/nginx-front.conf.example` 由 `conf.d` 的 http 上下文 include，
> 因此顶层的 `map` 合法，塞进 `server {}` 会导致 nginx 起不来。

