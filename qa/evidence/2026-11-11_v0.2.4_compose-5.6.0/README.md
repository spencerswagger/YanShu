# v0.2.4 干净环境真收发 · 验收清单与结果（Gate · 2026-11-11）

跑场：InstaBox `sbx-yanshu-yanshu-clean-225e`（4 vCPU / 8 GiB / 20 GiB `/data`，Debian 13）
运行环境：Docker **29.8.2**（overlayfs / cgroup=systemd）、Docker Compose **v5.6.0**、Chromium **154.0.8037.57**
被测：`yanshu-server:v0.2.4` / `yanshu-web:v0.2.4`（华为云 SWR 官方 tag）+ 官方 `docker-compose.yml`

## 0. 结论（先看这三行）

| # | 口径 | 结果 |
|---|---|---|
| 1 | 干净空目录 + 官方 compose + SWR 官方镜像，无本地 build、无改 tag | **PASS（12/12）** |
| 2 | 双浏览器 ≥1 GiB 真收发，源/落地 sha256 逐字相同 | **FAIL** —— 发送端 76s 完成；接收端拉到 1072 个块（含 81 次 429 限速重试）但**没有落地文件**，28 分钟内未产出 sha256。**根因已定案（§6.6）**：流式接收路径从不把数据交给浏览器（P0），429 只是把速率顶到 2 MiB/s 的独立设计问题 |
| 3 | `down && up -d` 后 `./secrets/` 两个密钥 sha256 不变 | **PASS**（前后两值逐字相同） |

来源 sha256（已算出）：`39094ee9f6ba02c4b18f120f8bfae347d96eefd33da4e30ef08e780277b2c315`（1 GiB，1073741824 B）
落地 sha256：**没有**（接收端未产出文件）→ 口径 2 判 FAIL。

## 0.5 沙箱必须具备的条件（开机器时照这张单子核）

| 项 | 要求 | 不满足会怎样 |
|---|---|---|
| docker | 真 root docker，**能 `docker run`**（不是只给 socket）；`docker info` 里 Driver 正常 | `docker run` 报 `error during container init: operation not permitted` → 直接 INCONCLUSIVE，别指望 |
| docker.sock | 执行用户能访问 `/var/run/docker.sock`（在 docker 组，或 root） | compose 全线不可用 |
| 端口 | 只需 **18080/tcp 本机可用**（compose 里 `web` 发布 18080→80）；不外联也不需要开放入站 | 起服务报 port already allocated |
| 浏览器 | chromium/chrome 与 docker **必须在同一台机器**（脚本走 `http://127.0.0.1:18080`） | 跨机器需改 `--url`，且两端 profile 也得在能访问该地址的机器上 |
| node | `node` ≥ 18 + `npm i playwright-core`（不下载 bundled browser，用系统 chromium） | transfer 阶段只能手工跑 |
| 磁盘 | `/data` 这类大盘 ≥ 6 GiB 空闲（1 GiB 用例：源 + 落地 + 镜像/卷）；**别用 `/tmp`** | 中途 ENOSPC，落地文件残缺 |
| 网络 | 能到 `swr.cn-east-5.myhuaweicloud.com`（匿名拉取；要登录就用一次性 pull token，别落长期凭据）、能到 `raw.githubusercontent.com` 取 compose | 拉不到镜像/compose → INCONCLUSIVE |
| 时间 | 整轮 ~15 分钟（1 GiB 加密+上传 76s，下载视限速而定） | 机器到期会腰斩 |

## 0.6 静态核验（**未含运行期**，只在镜像/文件层面）

| 项 | 值 | 判定 |
|---|---|---|
| SWR 上四个镜像的 tag | `yanshu-server:v0.2.4`、`yanshu-web:v0.2.4`、`library-alpine:3.20`、`library-postgres:16-alpine` 全部存在 | 齐全 |
| 镜像 label `org.opencontainers.image.revision` | `e886fc6c2a259229236284e257b9d81d23102bf6` | = `git rev-parse v0.2.4^{commit}`，逐字相同 |
| 镜像内 `/app/kernel/yanshu_sm.wasm` sha256 | `daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de` | = 仓库 `v0.2.4` 同文件，且 = `verifier.go` 白名单首条 |
| 镜像内 `/app/yanshu-server` sha256 | `4f3a4ba5fb9d45de29ea8cae1f2a26b1d9c555c41b5fdd09a6fc622c859eb5ec` | Go 1.27.4 / CGO_ENABLED=0 / -trimpath |
| `docker-compose.yml`（tag v0.2.4） | sha256 `16baed7e89f848386edfa00da9f0fcc4f48f43103ef0cab86ea8d5689a76884d` | = `origin/main` 同文件 |
| `docker compose config` | 三服务镜像 tag 解析为 v0.2.4 / 3.20 / 16-alpine，`web` 发布 18080→80，无 `build:` 段 | 无本地构建 |

> 这块**不能**代替运行期结论：镜像里有正确的二进制，不等于 `compose up` 后真能收发。

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

## 6.5 第二次复跑（带浏览器 console/进度埋点，`results/20261111T155607-v0.2.4/`）

第一轮判 FAIL 后，为了区分「限速」还是「浏览器侧保存」，在同一台机器的新栈上复跑了一次 1 GiB 并抓 console/进度。
结论比第一轮更清楚，**FAIL 判定不变，但根因收敛到浏览器侧最后一步**：

| 观测点 | 数据 |
|---|---|
| 服务端块传输 | `GET .../chunks/{i}` **1024 次 200 = 块数 1024，全拉完**（16:04:42Z 结束），另有若干 429（`scope` 级重试，最终都补齐） |
| 接收端进度 | `下载中 69% · 解密中 69%`（707/1024）→ 之后进度条不再变化；终点**没有**出现「已保存至本机」（`grep -c 已保存至本机 = 0`） |
| 落地 | `downloads/` 目录**空**；`landed` 文件不存在；无 `download` 事件 |
| 渲染进程内存 | 单个 renderer RSS **≈1.3 GB**（1 GiB 明文 + 1 GiB 密文都在页内），机器还剩 3.6 GB 空闲，未 OOM |
| 页内报错 | 无 `pageerror`，只有 429 的 console error（`Failed to load resource: 429`） |

判读：**传输层不是瓶颈**（1024 块全部 200 拿到），卡在「浏览器把 1 GiB 组装成 Blob → 保存」这一跳；
`web/src/net/download.js` 是把整份明文 `new Blob([plain])` 一次性组装，`web/src/lib/save.js` 再
`URL.createObjectURL + a.click()`。1 GiB 场景下这一路径没有走通（两轮都停在最后一步）。
下一步建议：① 换成流式写盘（`saveStream.js` 已有骨架，确认是否真按块落盘）；② 或至少在 1 GiB 场景给出明确失败提示，
而不是停在 69% 不动（当前用户看到的是「永远差一点」）。

> 注意：这一轮**没有**产出落地 sha256，所以口径 2 仍是 FAIL。

### 6.6 256 MiB 对照（**未完成，不算证据**）

想在机器到期前补一个"多大开始坏"的对照：256 MiB（`src` sha256 `2f813aa22990f000f5c52233b9045a7540346ee0b9975bd26a2e494c4c59582e`），
发起端正常、接收端 58.9s 出现待接收项、点「下载并解密」后**每 ~5.5s 一次 429**（客户端在退避重试），
机器 00:14 被回收（SSH `Permission denied (publickey)`，早于约定的 00:28），**没有拿到落地文件**。
这一条**不作为任何判定依据**，只记「429 退避会让大文件下载变成数分钟级」这个观感。

## 6.7 机器生命周期（供下次排期参考）

- 到手 23:06，健康可用；**00:14 被回收**（约定 00:28，提前约 14 分钟，`ssh` 直接 `Permission denied (publickey)`）。
- 教训：大文件用例（1 GiB）单次约 8–12 分钟且受 429 拖累，**排期要留 ≥2× 余量**，别把对照实验排在到期前 10 分钟。

同时观察到的产品问题（非本次口径判定项，但建议进任务书）：
- **接收端不自动刷新**：新到的文件 30s 内不出现，必须点「刷新」或重载页面（16 MB 与 1 GiB 两个用例都复现）。
- **1 GiB 等级下载会撞 429 限速**：81 次 429，客户端重试能继续，但整单落地未完成，需要定位是限速策略、
  还是浏览器侧 1 GiB Blob 组装/保存的问题（下一步：在同一沙箱复跑并抓浏览器 console + 内存峰值）。

## 6.6 根因定案（2026-11-12 00:51–01:02 CST，新机 `sbx-yanshu-yanshu-v025-767e`）

§6.5 的判读方向对（卡在最后一步），但**具体机理说错了**：不是「1 GiB Blob 组装太慢/没走通」，
而是**流式路径根本没有调用 `save()`**。证据链三步：

### ① 代码：`sink.close()` 的返回值被丢掉

```js
// web/src/net/download.js:139（流式接收，默认路径）
await sink.close()          // ← 返回 {blob,name} 或 {file,name}，这里丢弃
// :145
return { name: sink.name, size: done, transferId, dataVerified: true }
```

`save()`（`saveBlob`）**只**在非流式 `receiveOnce` 的 `:257` 调用。而 `receiveStreaming` 是否启用取决于
`kernel.supportsStreaming && sinkFactory` —— App 恒传 `sinkFactory`，内核支持流式 → **走的一直是流式**。

### ② 环境：没有 File System Access 时退回内存 sink，然后丢弃

实测 headless Chromium 154：`typeof window.showSaveFilePicker === "undefined"`
→ `defaultSinkFactory` 返回 `createMemorySink()`（明文全攒在 JS 内存里）
→ 1 GiB 组装完，`close()` 的结果没人接 → 数据进垃圾桶。
**Safari / Firefox 同样没有该 API**（`lib/saveStream.js` 注释自己写了）→ 真实用户同样中招。

### ③ 实测：同一镜像，两种落盘环境

| 用例 | 结果 |
|---|---|
| A 真 headless（产品原样） | 1024/1024 块、100%、584.5 s 完成；UI 报「已保存至本机：…（1.0 GB）」；**磁盘 0 B**（`downloads/` 与全盘都找不到） |
| B 同镜像 + `showSaveFilePicker` 测试替身（`save-sink-probe.mjs`，字节写到真实文件） | 1073741824 B / 1024 次写入 / 601.8 s；`src` 与 `out` sha256 **逐字相同** `424f4769…f58a8e4` |

→ **解密链路逐字节正确**，断点唯一：浏览器落盘这一跳。

### ④ 顺带把 429 说清楚（与本 FAIL 无关，但同为缺陷）

`spec/limits.go` `TransferReadPerIP = {60s, 120, 120}`，每块 ≈1 MiB → **2 MiB/s 硬顶**；`handlers_blobs.go:211`
先查 `read:ip` 再查 `read:transfer`。本轮服务端实测：`GET chunks` **1097 = 1024×200 + 73×429**，跨度 456.7 s，
任意 60 s 窗口最多 245 次；令牌桶预测 `120 + 2/s×456.7 = 1033`，实测 1024（差 0.9%）→ 就是这个桶在限。
429 间隔中位 6.02 s。**单浏览器也照样打满**，与「双浏览器共用出口 IP」无关。

### ⑤ 我方 harness 的错（已修）

`browser-transfer.mjs` 的 `waitForEvent('download')` 硬编码 **5 分钟**，而 1 GiB 在 2 MiB/s 下要 8.5 分钟
→ 必然先超时；旧证据里「进度停在 69%/74%」是**采样器在 423 s 被 `clearInterval` 停掉**，不是产品停住。
已加 `--dl-timeout-s`（默认 900）并在日志里打印该值。

原始数据：`results/20261112T0051-v0.2.4-rerun/`（`summary.txt`、`save-sink-probe.json`、`probe.log`、
`server-chunks-get.log.gz`）。



口径 2 未通过 → 不能当「发布出去的东西真能用」。根因已在两次复跑中收敛到**浏览器侧「1 GiB 组装 Blob → 保存」**
（§6.5：1024 块全 200 拿到，但进度停在 69%、无落地文件、无 download 事件）。建议顺序：
① 前端改流式落盘（`saveStream.js`）并给 1 GiB 明确失败提示；② 按本清单一键复跑拿两侧 sha256；
③ 复跑 PASS 后再出 v0.2.5 —— 修复本身走特性分支 + tag + 镜像构建，不在验收仓里手改。

## 8. 已知环境坑（写下来省下次时间）

- 沙盒 bwrap：`docker` 起得来但 `docker run` 必失败（无 NET_ADMIN 建 bridge；嵌套 userns 里 `/proc` 挂不上，
  dmesg `VFS: Mount too revealing`）→ 必须用真 docker 机器，别在沙盒里耗。
- headless chromium 下载：`launchPersistentContext` 的 `downloadsPath` 有时不生效，下载会被**静默丢弃**
  （页面照样显示「已保存至本机」而磁盘为空）→ 脚本里显式 `Browser.setDownloadBehavior{behavior:'allow'}`。
- 密钥文件 0600 属主 10001：宿主用户 `sha256sum` 会得到空值（假绿风险），必须走容器算。
- `run.sh` 是 `#!/bin/sh`（dash）：不要用 `${var:0:12}` 这类 bash 扩展（本次已踩，`Bad substitution`）。
- 证据目录命名：`2026-11-11_v0.2.4_compose-5.6.0/`（日期 + 镜像 tag + compose 版本）。
