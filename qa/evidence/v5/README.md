# qa/evidence/v5 · v5 四块验收（TTL 可见 / 速度 ETA / 元数据永久 / 全平台统计）

对 v5 的四块各给**一条命令跑出结论**的脚本，跑的是**真服务 + 真库 + 前端真实模块**，
不用占位符、不 mock 后端。退出码与 `qa/evidence` 其余脚本一致：

| 码 | 含义 |
|---|---|
| 0 | PASS —— 所有项都真跑且通过 |
| 1 | FAIL —— 至少一项不成立 |
| 2 | BLOCKED —— 起不来 / 依赖缺失 |
| 3 | INCONCLUSIVE —— 有项没跑（如缺 `--web-dir`），**不算通过** |
| 4 | PENDING —— 参数没给够，一步都没跑 |

## 0. 三十秒上手

前置：仓库形态的检出（脚本要 `web/src`、`docs/`、`server/kernel`）、`psql` 可达、
`TEST_DATABASE_URL` 指向 Gate 的测试库。

```sh
# 后端用要验的那条分支构建（不要把 main 的二进制拿来验分支）
git archive <branch> server | tar -x -C /tmp/v5/server --strip-components=1
(cd /tmp/v5/server && go build -o /tmp/v5/bin/yanshu-server ./cmd/yanshu-server)

# 前端要验的那条分支
git archive <branch> web docs | tar -x -C /tmp/v5

# 四块，逐条跑
python3 qa/evidence/v5/check_ttl_visible.py         --binary /tmp/v5/bin/yanshu-server --dsn "$TEST_DATABASE_URL" --web-dir /tmp/v5/web
python3 qa/evidence/v5/check_speed_eta.py           --binary /tmp/v5/bin/yanshu-server --dsn "$TEST_DATABASE_URL" --web-dir /tmp/v5/web
python3 qa/evidence/v5/check_metadata_permanent.py  --binary /tmp/v5/bin/yanshu-server --dsn "$TEST_DATABASE_URL"
python3 qa/evidence/v5/check_stats_consistency.py   --binary /tmp/v5/bin/yanshu-server --dsn "$TEST_DATABASE_URL" --web-dir /tmp/v5/web
```

界面取证（真 Chromium + 生产构建 + 真 API）：

```sh
(cd /tmp/v5/web && npx vite build && ln -s <web>/node_modules node_modules)   # 只借依赖，不改别人树
node qa/evidence/v5/ui_v5_shots.mjs --dist /tmp/v5/web/dist --api http://127.0.0.1:18099 \
     --out /tmp/v5/results/ui-v5 --dsn "$TEST_DATABASE_URL" --schema gate_v5_ui
```

## 1. 各脚本验什么、怎么算通过

| 脚本 | 块 | 关键断言（节选） | 依赖 |
|---|---|---|---|
| `check_ttl_visible.py` | ① TTL 可见 | `expires_at − created_at == ttl`；TTL 夹到 `[3600, 86400]`；`/v1/inbox` 每行带 `expires_at`；`config.server_time`、`status.expires_at`（#49）；到期 → `EXPIRED` + `410 TRANSFER_EXPIRED` + 密文物理删除；**清道夫拉到 600s，到点也必须立刻 410**（读写路径即时生效）；用响应头 `Date` 当"现在"跑前端 `formatTtl` 得 `23 小时后过期` / `42 分钟后过期` / `已过期，无法取回` | 后端 #48+#49 + 前端分支（文案项） |
| `check_speed_eta.py` | ② 速度 / ETA | 真传 16 MiB 量吞吐；节流到 1 MB/s 取 16s 采样窗；回放进 `createSpeedMeter`：50% 处 ETA 与真实剩余耗时 `|Δ|≤1.5s`；`<10 KB/s` 3s → `网络较慢`；3s 无进展 → `连接停滞，重试中` 且 ETA 隐藏 | 后端分支 + 前端分支 |
| `check_metadata_permanent.py` | ③ 元数据永久 | 取件后密文删净；`terminal_at` 推到 10 天前 **行仍在**（v4 的 7 天删除已取消）；40 天前三列 `uploader_ip/prelude_sm3/upload_token_sm3` 置 NULL；其余 9 个字段逐值不变；`GET` 仍 200 tombstone；`prelude`/块仍 410；清道夫幂等 | 后端分支 |
| `check_stats_consistency.py` | ④ 全平台统计 | 空库基线 0；三个 `no-store`；字段集精确无个例；建 3 取 2 → `created+3 / consumed+2 / consumed_bytes=明文和`；**计数器表 == transfers 直算 == HTTP JSON**；今日按 UTC 日界；`generated_at` 与 `Date` ≤5s；前端格式化真数字；另一客户端同数；撤回不计入 consumed | 后端分支（+ 前端格式化项） |
| `ui_v5_shots.mjs` | ①④ 界面 | 真 Chromium 打开生产构建：首屏不点刷新就应拉到 4 行；其中一条 `expires_at=now()+30s`，**页面内等到点**后该行必须自己翻成「已过期，无法取回」+ 整行灰化 + 删除线 + 下载置灰（全程不刷新、不重载），并核对服务端此刻 `state=EXPIRED`；平台统计六格文案齐全 | 前后端两条分支 + Chromium |
| `check_purge_fallback.py` | ③b 兜底删密文 | 种 250 条（> 批次 200）未删密文终结行 + 真文件：残留归零、**第 1/2 轮删的是不同批（交集空）**、各轮并集=全部、日志 `purged` 非常量、`purgeRemaining` 归零；再加「事务内终结 `newly=false`」两条（到期取件 / ack）在 sweep=600s 下密文必须当场删净 | 后端分支 |
| `ui_ttl_flip.mjs` | ① 翻转/兜底 | 造一条 `expires_at=now+N秒` 的真实传输：页内 rAF 探针记录「胶囊翻 / 整行灰化 / 下载置灰」三件事的**翻转时刻**（判同帧、判是否比服务端早判过期，并与库内精确值、接口秒级值分别对比）；再用 `?freeze=1` 在应用脚本前冻掉定时器（模拟后台节流），点下载验证**一个请求都不发**、直接置过期态 | 前后端 + Chromium |
| `check_migrations.py` | 迁移专项 | `0010` 非事务 CIC：干净库 0→0010、0009 补跑、CIC 期间写不阻塞（并抓锁模式必须是 `ShareUpdateExclusiveLock`）、**杀后端会话**制造 INVALID 再验重跑自愈、幂等、两实例并发不死锁、advisory 锁不残留；附迁移器切句/指令单测 | 后端分支 + migrations 目录 |
| `check_block_redaction.py` | ③d 块级脱敏 | `transfer_chunks.ciphertext_sm3` 30 天后归 NULL；`transfers` 除三列外**逐列**不变（按 information_schema 比，不手抄）；块侧候选集单调不增 | 后端分支 |
| `check_redact_index.py` | ③c 脱敏索引 | 20 万行稳态上 `EXPLAIN (ANALYZE, BUFFERS)`：子查询与整条 UPDATE 都必须走 Index Scan、buffers/耗时达标；再测「一次性脱敏 18 万行后」的瞬时退化与 `VACUUM` 后的回落 | 后端分支 |

`v5_ui_seed.py` 的第 4 条是**短 TTL**（默认 30s，`--short-ttl` 可调）：「已过期」这一态在
v5/`#49` 的「过期即终结」语义下**不能靠种一条过期记录来造**（`/v1/inbox` 永不返回过期行），
只能「行已加载 + 时间到点」。`check_purge_fallback.py` 供元数据永久保留后的 P0 回归用。

`render_web.mjs` 是共用跑分器：把后端真数字塞进 `web/src/lib/serverClock.js` /
`web/src/lib/speed.js` / `web/src/net/stats.js` 跑一遍，避免"后端对、界面文案错"漏检。
`v5_ui_seed.py` 只给界面取证造三条真传输（23h / 42m / 已过期），不单独作验收。

## 2. 复跑时注意

- **日报边界**：`check_stats_consistency.py` 第 6 项用 `(now() at time zone 'utc')::date` 对齐 UTC 日界；
  若把服务端会话时区改成非 UTC（`...&options=-c%20timezone%3DAsia%2FShanghai`），这一项必须变红 —— 这是**阳性对照**，
  用来证明脚本不是瞎的（实现用的是 `$1::date`，会跟着会话时区走）。
- `check_stats_consistency.py` 会等 `/v1/stats` 的 60s 内部缓存过期，整条跑约 70s，不是卡住。
- 前端用例需要 `public/ys_kernel.wasm`（`*.wasm` 在 `.gitignore` 里）：拷内核产物过去，否则内核相关用例会 SKIP。
- 所有脚本自己建 `gate_v5_*` schema，跑完即删；不碰 `yanshu_test` 默认 schema，也不碰别人的数据。
- **schema 名会统一转小写**：PG 的 `search_path` 是未加引号标识符（折小写），带大写会让"建 schema 保留大写 + search_path 折小写"对不上，服务直接起不来。
- 脚本不写别人的业务代码，只读产物、只打自己的 schema。

## 3. 结果

见 `results/2026-11-10-v5-evidence.md`（真跑数字 + 缺口 + 发现的缺陷）。
