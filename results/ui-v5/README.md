# v5 前端三块 · 证据（真跑）

生成方式（一条命令跑完，失败非 0 退出）：

```bash
cd web
npm run build
node scripts/v5-evidence.mjs --api=http://127.0.0.1:18080 --serve=dist \
  --dsn="$PG_DEV_DSN" --size=96 --out=../results/ui-v5
```

- 真服务端：`server` 的 `feat/v5-metadata-stats`（PR #48，含 `GET /v1/stats`），`YANSHU_VERIFIER=sm2`、真内核；
- 真前端：`npm run build` 产物，由脚本起静态服务并把 `/v1` 反代到服务端（同源，CSP 只放 `'self'`）；
- 两个 Chrome profile = 两个独立身份（IndexedDB 隔离），A 发、B 收，96 MiB 真文件；
- 脚本断言 16 项，全过才 exit 0；断言明细在 `evidence.json.checks`。

## 截图

| 文件 | 视口 | 覆盖 |
|---|---|---|
| `stats-platform-*.png` | 390×844 / 1440×900 | ④ 平台统计：今日/累计的「已取走 / 流量 / 新建」六个数字（真 `/v1/stats`） |
| `ttl-four-states-*.png` | 同上 | ① TTL 四态同一屏：`23 小时后过期` / `42 分钟后过期` / `2 天后过期` / `已过期，无法取回`，过期行灰化 + 下载置灰 |
| `sending-speed-*.png` | 同上 | ② 发送：`67.9 MB/s · 即将完成` + `62 MB / 96 MB` + 块矩阵 |
| `sent-done-390x844.png` | 390×844 | ① 发送完成态显示服务端 TTL（`23 小时后过期`，替换原来写死的「24 小时后自动删除」） |
| `receiving-two-stage-390x844.png` | 390×844 | ② 接收：`下载中 N%` + 速度行 + `N MB / 96 MB` + `解密块 i/N` |
| `received-done-390x844.png` | 390×844 | 接收完成提示（`已保存至本机…`） |
| `empty-*.png` | 390×844 / 1440×900 | 空态（沿用上一版，界面未变） |

## 真数字（本次运行，evidence.json 可复核）

- `/v1/stats`：今日 `consumed=9 / consumed_bytes=208666624 / created=35`，累计 `35 / 1273903439 / 84`；
  界面六项与之逐项一致（`199 MB` = 208666624 B，`1.2 GB` = 1273903439 B）。
- 发送速度采样：`0 B/s → 67.9 MB/s → 70.9 MB/s`，`62 MB / 96 MB → 93 MB / 96 MB`（96 MiB 真文件）；
- 接收采样：`下载中 1% … 100%` 共 96 个采样点，速度 `15.2 MB/s`，`解密块 1/96 … 96/96`；
- TTL 四态的 `expires_at` 是**测试夹具**：真发 3 笔 1 MiB 后把库里三行的 `expires_at` 改成
  `now() + 42m30s` / `now() + 50h` / `now() - 1m`，界面文案由前端按服务端时间基准实算。

## 未覆盖（如实）

- **「解密中 N%」**：流式接收是**按块边下边解**（进度里是 `解密块 i/N`），没有独立的「解密中」阶段；
  只有非流式回退路径（`receiveOnce`）才会出现该阶段，该分支由单测覆盖（`stageLabel('decrypting')`），
  无截图。UI-COPY S3 的 `解密中 18%` 与流式实现不一致，需产品口径确认。
- **`网络较慢` / `连接停滞，重试中`**：需要人为限速/断流，只有单测（状态机），无截图。
