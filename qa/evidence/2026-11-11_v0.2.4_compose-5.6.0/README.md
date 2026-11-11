# v0.2.4 干净环境真收发 · 验收清单与结果（Gate · 2026-11-11）

跑场：InstaBox `sbx-yanshu-yanshu-clean-225e`（4 vCPU / 8 GiB / 20 GiB `/data`，Debian 13）
运行环境：Docker **29.8.2**（overlayfs / cgroup=systemd）、Docker Compose **v5.6.0**、Chromium **154.0.8037.57**
被测：`yanshu-server:v0.2.4` / `yanshu-web:v0.2.4`（华为云 SWR 官方 tag）+ 官方 `docker-compose.yml`

## 0. 结论（先看这三行）

| # | 口径 | 结果 |
|---|---|---|
| 1 | 干净空目录 + 官方 compose + SWR 官方镜像，无本地 build、无改 tag | **PASS（12/12）** |
| 2 | 双浏览器 ≥1 GiB 真收发，源/落地 sha256 逐字相同 | **FAIL** —— 发送端 76s 完成；接收端拉到 1072 个块（含 81 次 429 限速重试）但**没有落地文件**，28 分钟内未产出 sha256 |
| 3 | `down && up -d` 后 `./secrets/` 两个密钥 sha256 不变 | **PASS**（前后两值逐字相同） |

来源 sha256（已算出）：`39094ee9f6ba02c4b18f120f8bfae347d96eefd33da4e30ef08e780277b2c315`（1 GiB，1073741824 B）
落地 sha256：**没有**（接收端未产出文件）→ 口径 2 判 FAIL。

## 1. 怎么复跑（一条命令）

```sh
# 0) 准备：一台真 docker（能 docker run、非只有 socket）+ 一个 chromium；目录放 /data 这类大盘
ssh <box>
mkdir -p /data/gate-pkg && cd /data/gate-pkg      # 把本目录内容拷进来
./run.sh preflight                                # 前置检查（docker/compose/磁盘/SWR/浏览器）
./run.sh up        --work /data/clean-v0.2.4      # 干净目录→官方 compose→拉 SWR 镜像→起服务→探活
./run.sh transfer  --work /data/clean-v0.2.4 --ev <上一步打印的证据目录> --gib 1
./run.sh secrets   --work /data/clean-v0.2.4 --ev <同上>
# 或者一次跑完：./run.sh all --work /data/clean-v0.2.4
```

判定：`0` PASS / `1` FAIL / `2` INCONCLUSIVE（缺依赖或环境不满足 —— **不算通过**）。
每一步的原始输出落在 `<证据目录>/logs/NN-*.log`，命令与退出码索引在 `logs/index.txt`。

## 2. 前置条件（清单）

- **必须真能跑容器**：`docker run --rm <SWR>/library-alpine:3.20 /bin/sh -c 'echo container-ok'` 要出 `container-ok`。
  只有 socket、`docker run` 报 `error during container init: operation not permitted` 的机器**不算**（沙盒 bwrap 就是这样）。
- 磁盘：源文件 + 落地文件 + 卷，≥ 3× 文件大小余量（1 GiB 用例建议 ≥ 6 GiB 空闲）；**别用 `/tmp`**（很多机器 `/tmp` 只有 2 GiB）。
- 网络出口：`https://swr.cn-east-5.myhuaweicloud.com/v2/`（返回 401/403 也算可达；匿名拉取不需要 token）。
  若 SWR 要登录，用**一次性 pull token**，不要落长期凭据。
- 浏览器：`chromium` / `chromium-browser` / `google-chrome` 任一；两端用**两个独立 `--user-data-dir` 实例**
  （脚本里是 `launchPersistentContext` 两个独立 profile，等价「两端各一」，不是同一浏览器两个标签页）。
- `node` + `npm i playwright-core`（脚本用系统 chromium，不下载 bundled browser）。
- 端口：compose 里 `web` 发布 `18080→80`，需 18080 空闲且可达。

## 3. 逐条命令与每步证据（口径 1）

```sh
mkdir -p /data/clean-v0.2.4 && cd /data/clean-v0.2.4     # 必须是**新的空目录**
curl -fsS -o docker-compose.yml \
  https://raw.githubusercontent.com/spencerswagger/YanShu/v0.2.4/docker-compose.yml
sha256sum docker-compose.yml      # 必须是 16baed7e89f848386edfa00da9f0fcc4f48f43103ef0cab86ea8d5689a76884d
grep -cE '^[[:space:]]*build:' docker-compose.yml        # 必须是 0（禁本地 build）
docker compose config | grep -E '^\s+image:'             # 三个服务 tag 必须是 v0.2.4 / 3.20 / 16-alpine
docker compose pull
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  swr.cn-east-5.myhuaweicloud.com/spencerswagger/yanshu-server:v0.2.4   # digest 见 §5
docker compose up -d --wait
docker compose ps
curl -fsS http://127.0.0.1:18080/healthz                 # {"status":"ok"}
docker compose logs yanshu-server | grep 'sm2 verifier loaded'
ls -l secrets/                                           # token_secret / pg_password，0600
```

每步要留的证据：compose 文件 sha256、`compose config` 解析出的镜像清单、`pull` 原始输出、`docker image inspect`
的 digest、`ps` 状态、`/healthz` 响应体、server 启动日志、`secrets/` 清单与权限。

## 4. 逐条命令与判定（口径 2 / 3）

口径 2（本机实测 **FAIL**，原因与现象见 §6）：

```sh
head -c 1073741824 /dev/urandom > /data/ys-fixtures/src.bin
sha256sum /data/ys-fixtures/src.bin                       # 记源值（完整 64 位）
node browser-transfer.mjs --url http://127.0.0.1:18080/ \
  --src /data/ys-fixtures/src.bin --out /data/ys-fixtures/landed.bin \
  --gib 1 --evidence <证据目录> --dl-dir /data/ys-fixtures/downloads
./verify-sha256.sh /data/ys-fixtures/src.bin /data/ys-fixtures/landed.bin
# PASS 条件：两侧 sha256 完整 64 位逐字相同 **且** 字节数相同
```

口径 3（本机实测 **PASS**）：

```sh
# 密钥是 0600 属主 10001，宿主用户读不了 → 用容器算
docker run --rm -v /data/clean-v0.2.4/secrets:/s:ro <SWR>/library-alpine:3.20 sha256sum /s/token_secret /s/pg_password
docker compose down            # 注意：不是 down -v，卷和 ./secrets 都要留着
docker compose up -d --wait
docker run --rm -v /data/clean-v0.2.4/secrets:/s:ro <SWR>/library-alpine:3.20 sha256sum /s/token_secret /s/pg_password
# PASS 条件：两个文件 sha256 与重启前**完全一致**
```

## 5. 本次实测数据

镜像 digest（`docker image inspect` 实测，与登记值一致）：

| 镜像 | digest |
|---|---|
| yanshu-server:v0.2.4 | `sha256:e253e71ee238fec49bf0e0eff84dcfa126241d608bc708e3865a1be79a677370` |
| yanshu-web:v0.2.4 | `sha256:ee3c8e7a085cb3974374b704c44a92467c7416be73ebb494443fd35705f3a6e0` |
| library-alpine:3.20 | `sha256:ec7ca0b6e94fe97eacac06ae7c8a5c20fca978adb4446af4abf1d46b7cdc818c` |
| library-postgres:16-alpine | `sha256:14f55ab28d36faa81870fdb6d182677caf2729a2330bd5be84afecc77d1c9601` |

compose 文件 sha256 = `16baed7e89f848386edfa00da9f0fcc4f48f43103ef0cab86ea8d5689a76884d`（与 tag v0.2.4 仓库文件一致）
起服务结果：`init` 一次性退出、`postgres` / `yanshu-server` / `web` 三容器 healthy，`web` 发布 `0.0.0.0:18080→80`。

密钥 sha256（口径 3，重启前 = 重启后）：

```
token_secret cf97310487aa2df166afa65d8b1302a0b3f976c5bfe4fa46fc2b71908b96bb1b
pg_password  667ccf1225949321088d729715684a3242dda05859c4aea4a760a27b61ad9a04
token_secret cf97310487aa2df166afa65d8b1302a0b3f976c5bfe4fa46fc2b71908b96bb1b
pg_password  667ccf1225949321088d729715684a3242dda05859c4aea4a760a27b61ad9a04
```

## 6. 口径 2 的失败细节（FAIL 依据，别含糊）

1 GiB 用例时间线（`logs/21-browser-transfer.log`）：

```
[10.1s] 接收端已就绪，码 GVCN      [13.5s] 发送端已就绪，码 0EZH
[14.8s] 已选文件 1.00 GiB         [14.9s] 已点发送
[91.2s] 发送端显示已发送            ← 加密+上传 1 GiB 用了 76s
[121.2s] 30s 内接收端列表未自动出现 → 点「刷新」
[121.3s] 点「下载并解密」
[421.3s] 没收到 download 事件，改盯 downloadsPath
（此后 28 分钟内：/data/ys-fixtures/downloads 始终为空，页面也没有出现「已保存至本机」）
```

服务端（`GET /v1/transfers/{id}/chunks/{index}`）实测：**2273 次请求 / 1072 次 200 / 81 次 429**，
每块 1048592 B（≈1 MiB，与前端 `ys_default_chunk_size` 一致）。429 发生在 15:34:55Z—15:42:17Z 之间，
客户端有重试（1072 > 1024 块）。

同时观察到的产品问题（非本次口径判定项，但建议进任务书）：

- **接收端不自动刷新**：新到的文件 30s 内不出现，必须点「刷新」或重载页面（16 MB 与 1 GiB 两个用例都复现）。
- **1 GiB 等级下载会撞 429 限速**：81 次 429，客户端重试能继续，但整单落地未完成，需要定位是限速策略、
  还是浏览器侧 1 GiB Blob 组装/保存的问题（下一步：在同一沙箱复跑并抓浏览器 console + 内存峰值）。

## 7. 处置建议（按口径第 4 条）

口径 2 未通过 → 不能当「发布出去的东西真能用」。但**根因还没定位到唯一原因**（429 与浏览器侧保存两个候选），
在没定位前**不宜盲发 v0.2.5**。建议顺序：
① 复跑 1 GiB 抓 console/内存，判定是限速还是保存；② 定位到哪层就在那层修（限速参数或前端保存路径）；
③ 修完按本清单一键复跑；④ 出 v0.2.5 并留本目录结果。原口径「当场修出 v0.2.5」在根因未定前会变成盲修。

## 8. 已知环境坑（写下来省下次时间）

- 沙盒 bwrap：`docker` 起得来但 `docker run` 必失败（无 NET_ADMIN 建 bridge；嵌套 userns 里 `/proc` 挂不上，
  dmesg `VFS: Mount too revealing`）→ 必须用真 docker 机器，别在沙盒里耗。
- headless chromium 下载：`launchPersistentContext` 的 `downloadsPath` 有时不生效，下载会被**静默丢弃**
  （页面照样显示「已保存至本机」而磁盘为空）→ 脚本里显式 `Browser.setDownloadBehavior{behavior:'allow'}`。
- 密钥文件 0600 属主 10001：宿主用户 `sha256sum` 会得到空值（假绿风险），必须走容器算。
- `run.sh` 是 `#!/bin/sh`（dash）：不要用 `${var:0:12}` 这类 bash 扩展（本次已踩，`Bad substitution`）。
- 证据目录命名：`2026-11-11_v0.2.4_compose-5.6.0/`（日期 + 镜像 tag + compose 版本）。
