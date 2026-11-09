# v5 前端三块 · 证据（真跑）

生成方式（一条命令跑完，失败非 0 退出）：

```bash
cd web
npm run build
node scripts/v5-evidence.mjs --api=http://127.0.0.1:18080 --serve=dist \
  --dsn="$PG_DEV_DSN" --size=96 --out=../results/ui-v5
```

- 真服务端：`feat/v5-metadata-stats`（#48）× `feat/v5-ttl-visible`（#49）本地合并后构建（含 `server_time`、到期即时 410）；
  `YANSHU_VERIFIER=sm2` + 真内核，独立 schema（脚本用 `PGOPTIONS="-c search_path=<schema>"` 指定）；
- 真前端：`npm run build` 产物，由脚本起静态服务并把 `/v1` 反代到服务端（同源，CSP 只放 `'self'`）；
- 两个 Chrome profile = 两个独立身份（IndexedDB 隔离），A 发、B 收，96 MiB 真文件；
- 脚本断言 24 项，全过才 exit 0；断言明细在 `evidence.json.checks`。

## 截图

| 文件 | 视口 | 覆盖 |
|---|---|---|
| `inbox-first-screen-390x844.png` | 390×844 | **首屏待收列表**：加载完成即 4 行（不点刷新）——修的是 `InboxPanel` 在 `api` 注入前就 `refresh()` 的 P0 |
| `ttl-four-states-*.png` | 390×844 / 1440×900 | ① TTL 四态同一屏：`23 小时后过期` / `42 分钟后过期` / `2 天后过期` / `已过期，无法取回`；过期行**整行灰化（opacity .55）+ 发件人名删除线 + 下载置灰**（收件列表不显示文件名——文件名在 prelude 里，下载解密后才拿到；`.rname` 是发件人昵称/码） |
| `sending-speed-*.png` | 同上 | ② 发送：`67.9 MB/s · 即将完成` + `62 MB / 96 MB` + 块矩阵 |
| `sent-done-390x844.png` | 390×844 | ① 发送完成态显示服务端 TTL（`23 小时后过期`） |
| `receiving-two-stage-390x844.png` | 390×844 | ② 接收：`下载中 N% · 解密中 N%` + 速度行 + `已取到/总大小` |
| `received-done-390x844.png` | 390×844 | 接收完成提示（`已保存至本机…`） |
| `stats-platform-*.png` | 同上 | ④ 平台统计六格（今日/累计：已取走 / 流量 / 新建），真 `/v1/stats` |
| `empty-*.png` | 同上 | 空态（界面未变，沿用上一版） |

## 真数字（本次运行，evidence.json 可复核）

- 首屏 `inboxAuto = 4`（不点刷新）；TTL 四态：`23 小时后过期` / `42 分钟后过期` / `2 天后过期` / `已过期，无法取回`，
  过期行 `opacity=0.55`、`text-decoration=line-through`、下载按钮 `disabled=true`。
- `/v1/stats`：今日 `consumed=1 / consumed_bytes=100663296 / created=4`（= 96 MiB，与界面逐项一致）。
- 发送采样：`0 B/s → 67.9 MB/s → 70.9 MB/s`，`62 MB / 96 MB → 93 MB / 96 MB`。
- 接收采样：`evidence.json` 留**首尾两段**（首 12 条 + 末 12 条，共 `recv.count=95` 条中的 24 条）——
  头部 `下载中 1% · 解密中 1%`、尾部 `下载中 100% · 解密中 100%` 与 `saved=true` 那条都在里面；
  速度 `15.2 MB/s`，进度行同时显示 `解密块 i/96`。发送侧同样留首尾两段（`send.count=38`）。
- TTL 三态的 `expires_at` 是**测试夹具**：真发 3 笔 1 MiB 后把库里三行改成 `now()+43m` / `now()+50h` / `now()+20s`；
  最后一笔**等它在页面里到点**再截——因为 #49 之后「过期即终结」，`/v1/inbox` 不会再返回已过期的行，
  过期态只会在「行已加载、时间到点」时出现（这也是用户真实遇到的情形）。

## TTL 翻转：单一定时器（P3）

原来胶囊与整行各挂一个 30s `setInterval`：文字到点就翻，整行灰化/删除线/下载置灰要等下一格，实测**滞后 29.6s**，
这 30 秒里「已过期」但按钮还能点（点了吃 `410 TRANSFER_EXPIRED`）。

现在收敛成 `web/src/lib/expiryTicker.js` 的**一个**定时器与**一个** `now`：

- 胶囊（`TtlPill`）与整行状态（`InboxPanel`）都读同一个 `now`，同帧翻转；
- 平时 30s 粒度（不忙轮询）；任一截止时刻进入 **≤60s** 窗口后直接 `setTimeout` 到那一刻 +20ms；
- `visibilitychange` 回到前台、以及每次 `syncServerTime` 之后立刻重算一次（补偿后台节流）；
- **点击兜底**：即使状态没来得及翻，`take()` 也会按 `serverClock` 再判一次到期 → 直接置成过期态、不发请求。

实测（见 `flip-lag.json`，两次独立跑）：胶囊 / 整行 / 下载按钮**三者同帧**（skew = 0），
滞后 **45ms** 与 **-162ms**（负值是页面侧 `/v1/config` 往返误差，不是提前过期），都远小于 1s。
复现：真发 3 笔小文件，把一笔 `expires_at` 改到 +20s → 首屏加载（不刷新，`inboxAuto=4`）→ 页面内每 25ms 采样到点那一刻。

**降级行为（如实）**：后台标签页会被浏览器节流（定时器最短 1s，某些省电模式到 1min），翻转可能延后到下一格；
页面回到前台立刻重算并补翻（`visibilitychange`）。另外点击兜底保证"延后"不会变成"点了报 410"。

## Gate 脚本复跑

四条后端脚本（`qa/evidence/v5/`，PR #50）在本合并态上的结果见 `gate-run.md`：TTL 14/14、速度 8/8、统计 13/13、元数据 10/10；
界面脚本 `ui_v5_shots.mjs` 只有「首屏自动加载」与「统计六格」通过，其「过期行」断言与 #49 的读路径终结语义冲突（原因与建议在该文件里）。

## 未覆盖（如实）

- **`网络较慢` / `连接停滞，重试中`**：需要人为限速/断流。本轮以 Gate 的 `check_speed_eta.py` 覆盖（回放真采样，两态均 PASS），未单独截图。
- **`解密中` 的阶段划分**：流式接收**按块边下边解**，`下载中 X%` 与 `解密中 Y%` 通常同步推进（X≈Y），
  两段数字都来自真实字节计数（`done`=已取到密文，`decrypted`=已解密写出明文）；非流式回退路径的最终验签没有增量进度，
  只显示阶段名「解密中」，该分支由单测覆盖。
- **门禁**：`npm run check`（= `node --test tests/*.test.js` + `vite build`）**rc=0**。本仓库是纯 JS SFC，
  没有 `tsconfig.json` / `typescript` / `vue-tsc` / `typecheck` 脚本，门禁里不涉及任何 TS 工具链。
- `web/scripts/v5-evidence.mjs` 只是**取证脚本、不是门禁**：它要起真服务端 + 真 Chromium，并轮询等
  `/v1/stats` 的 60s 进程内缓存过期、等 3 笔小传输落成 READY，跑批时长敏感（约 3 分钟），不适合当合入门槛。
