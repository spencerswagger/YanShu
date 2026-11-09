# Gate 脚本 · 在 #48+#49 合并态上的复跑结果（前端 Web 侧自查）

服务端二进制：`origin/feat/v5-metadata-stats`（441245b）与 `origin/feat/v5-ttl-visible`（0bc4958）在本地合并（merge commit 675051f，
与 Gate 报的合并态 `5cb9b11` 内容相同——该 commit 未推远端，这里用两个已推送的 head 复现）后 `go build`。
前端：本分支（`--web-dir` 指向 `web/`，脚本通过 `render_web.mjs` 直接 import `src/lib/serverClock.js`、`src/lib/speed.js`、`src/net/stats.js`）。
脚本来源：`origin/qa/v5-evidence`（PR #50），未做任何改动。

## 四条后端检查

```sh
python3 qa/evidence/v5/check_ttl_visible.py        --binary <ys-server-v5> --dsn "$TEST_DATABASE_URL" --schema gate_web_ttl   --web-dir web
python3 qa/evidence/v5/check_speed_eta.py          --binary <ys-server-v5> --dsn "$TEST_DATABASE_URL" --schema gate_web_speed --web-dir web
python3 qa/evidence/v5/check_stats_consistency.py  --binary <ys-server-v5> --dsn "$TEST_DATABASE_URL" --schema gate_web_stats --web-dir web
python3 qa/evidence/v5/check_metadata_permanent.py --binary <ys-server-v5> --dsn "$TEST_DATABASE_URL" --schema gate_web_meta
```

| 脚本 | 结果 | 关键项 |
|---|---|---|
| `check_ttl_visible.py` | **14/14 PASS** | `config.server_time`（与 `Date` 差 0s）、`status.expires_at`、TTL 夹取、到期 `410 TRANSFER_EXPIRED`、密文物理删除、清道夫 600s 也即时生效 |
| `check_speed_eta.py` | **8/8 PASS** | 16 MiB 真传 25.3 MB/s；50% 处 ETA 与真实剩余耗时 Δ=0.00s；停滞/慢速两态与 ETA 隐藏 |
| `check_stats_consistency.py` | **13/13 PASS** | 三个 `no-store`、字段集、计数器==transfers 直算==HTTP、UTC 日界、前端格式化、撤回不计 consumed |
| `check_metadata_permanent.py` | **10/10 PASS** | 取件后密文删净、10 天后行仍在、40 天后三列脱敏、其余字段不变、tombstone 200 / 内容 410、清道夫幂等 |

## 界面取证 `ui_v5_shots.mjs`

```sh
node qa/evidence/v5/ui_v5_shots.mjs --dist web/dist --api http://127.0.0.1:18099 \
  --out <tmp> --dsn "$TEST_DATABASE_URL" --schema gate_web_ui
```

结果：**部分通过**。

- ✅ **首屏自动加载**：`inboxAuto = 2`（不点刷新就有 2 行）——即本轮修的 P0 在 Gate 脚本下成立。
- ✅ 平台统计六格文案齐全。
- ❌ `待收列表 TTL 胶囊数量 2 != 3`、`过期行没有 expired 态`：
  #49 之后 TTL 在读写路径即时终结，`/v1/inbox` 不再返回过期的行，所以脚本里"直接造一条已过期的记录"永远进不了列表。
  过期态只会在「行已加载、时间到点」时出现。本分支的 `scripts/v5-evidence.mjs` 用这个真实路径复现：
  种一笔 20 秒后到期的行 → 打开页面 → 等到点 → 该行自己翻成「已过期，无法取回」+ 整行灰化（opacity 0.55）+ 文件名删除线 + 下载置灰
  （见 `ttl-three-states-*.png` 与 `evidence.json` 的 4 条 TTL 记录）。

> 建议（脚本归 Gate）：`v5_ui_seed.py` 的"已过期"那条改成短 TTL + 页面内等到点，或由脚本先把行种成 10 秒后到期再加载。
