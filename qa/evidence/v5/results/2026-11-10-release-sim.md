# 合入模拟 + 发布验证单（v0.2.0，2026-11-10）

## 一、逐 PR 合并模拟（起点 `origin/main@fe68c47`，独立 clone 里做，不动任何人的工作区）

| 步 | PR | head | 结果 | 冲突文件 | 按哪侧解 |
|---|---|---|---|---|---|
| 1 | #46 `docs/api-stats-retention` | `427446a` | **CLEAN** | — | — |
| 2 | #48 `feat/v5-metadata-stats` | `7ed85bc` | **CLEAN** | — | — |
| 3 | #49 `feat/v5-ttl-visible` | `86f6e2b` | **CLEAN** | — | — |
| 4 | #47 `feat/v5-ttl-eta-stats` | `24adc00` | **CLEAN** | — | — |
| 5 | #51 `qa/fix-nosilent-flake` | `f662e9c` | **CLEAN** | — | — |
| 6 | #50 `qa/v5-evidence` | `7658043` | **CLEAN** | — | — |
| 7 | #52 `fix/ensure-wasm-pinning` | `c872f37` | **CLEAN** | — | — |
| 8 | #45 `chore/v4-evidence-script` | `07624c3` | **CLEAN** | — | — |
| 9 | #53 `chore/release-v0.2.0`（分支名是这个，不是 `bump-compose-v020`） | `ca9759a` | **CLEAN** | — | — |
| 10 | #54 `ci/expose-digests` | `92380f3` | **CLEAN** | — | — |

- **10 步全部 0 冲突**（上一轮 `#46 × #49` 的 `docs/API.md §5.2` 冲突出现在 #49 `86f6e2b` 同步四列口径后已消失）。
- 第 5 步单独核对：#51 合并点（`#47` 之后）**只改 `web/tests/helpers/kernel.js` 与 `web/tests/no-silent-pass.test.js`**，
  `web/src` 零改动；合完后全树 `web/scripts/v4-evidence.mjs` **恰好 1 份**（来自 #45，未被 #47/#52 重带）。
- 提醒：`#53` 的远端分支名是 `chore/release-v0.2.0`（按 `ca9759a` 反查），PR 号对应的分支名若不是这个，合并会取错 ref。

## 二、合并树上的全量门禁（HEAD = 10 步后的 `sim` 分支）

| 项 | 命令 | 结果 |
|---|---|---|
| 后端测试 | `cd server && TEST_DATABASE_URL=… go test ./...` | **13 包 ok / 0 fail**（+2 个无测试包） |
| 前端门禁 | `cd web && npm ci && npm run check` | **126 例 / 126 pass / 0 fail / 0 skip**，`vite build` 通过 |
| ① TTL | `check_ttl_visible.py` | **15/15 PASS** |
| ② 速度/ETA | `check_speed_eta.py` | **8/8 PASS** |
| ③ 元数据永久 | `check_metadata_permanent.py` | **10/10 PASS** |
| ④ 全平台统计 | `check_stats_consistency.py` | **13/13 PASS** |
| ⑤ P0 清理水位 | `check_purge_fallback.py` | **8/8 PASS**，250 条 → 残留 **0/250**，第 1/2 轮 200+50、交集 0、`purged=[200,50]` |
| 首屏行数 | `ui_v5_shots.mjs` | **`inboxAuto=4`**，30s 那条 24069ms 自翻，服务端 `EXPIRED`（等待 10ms） |

> 本轮修了自己脚本的一个过严断言：前端可能比库内**精确**到期时刻早 ≤1s 翻（契约 `expires_at`/`server_time` 是秒级），
> 原先「翻转瞬间服务端必须已 EXPIRED」会偶发红；改成给 ≤5s 收敛窗口并记录等待毫秒——判定没放宽（仍要求最终 EXPIRED）。

## 三、合完立刻跑什么（可直接粘贴）

### A. 仓库侧（本地/CI，tag 之后，`git checkout v0.2.0`）

```sh
set -e
export TEST_DATABASE_URL='postgres://yanshu_test:***@127.0.0.1:5432/yanshu_test?sslmode=disable'

# 1) 后端全量测试（13 包）
(cd server && go test ./...)

# 2) 前端门禁（126 例 + 构建）
(cd web && npm ci && npm run check)

# 3) 用 tag 的代码构建服务端二进制（五脚本都要它）
(cd server && go build -o /tmp/ys-v020-server ./cmd/yanshu-server)

# 4) 五脚本（各给 PASS/FAIL 计数）
python3 qa/evidence/v5/check_ttl_visible.py         --binary /tmp/ys-v020-server --dsn "$TEST_DATABASE_URL" --web-dir web
python3 qa/evidence/v5/check_speed_eta.py           --binary /tmp/ys-v020-server --dsn "$TEST_DATABASE_URL" --web-dir web
python3 qa/evidence/v5/check_metadata_permanent.py  --binary /tmp/ys-v020-server --dsn "$TEST_DATABASE_URL"
python3 qa/evidence/v5/check_stats_consistency.py   --binary /tmp/ys-v020-server --dsn "$TEST_DATABASE_URL" --web-dir web
python3 qa/evidence/v5/check_purge_fallback.py      --binary /tmp/ys-v020-server --dsn "$TEST_DATABASE_URL"
#   ↑ 期望 15/15、8/8、10/10、13/13、8/8；清理水位那条报「残留=0/250」

# 5) 首屏行数（真 Chromium + 生产构建 + 真 API；先起一个本地服务实例在 18099）
(cd web && npx vite build)
node qa/evidence/v5/ui_v5_shots.mjs --dist web/dist --api http://127.0.0.1:18099 \
     --dsn "$TEST_DATABASE_URL" --schema gate_rel_ui --out /tmp/ui-v020
#   ↑ 期望：首屏自动 4 行；30s 那条自翻「已过期」；服务端 EXPIRED

# 6) 迁移专项（0010 非事务 CIC / 中断自愈 / 并发不死锁）
python3 qa/evidence/v5/check_migrations.py --binary /tmp/ys-v020-server \
     --migrations server/internal/store/migrations --dsn "$TEST_DATABASE_URL"
#   ↑ 期望 13/13；CIC 期间 INSERT 不被阻塞、锁模式只有 ShareUpdateExclusiveLock
```

### B. 真实部署侧（必须在**部署机**上跑，本地跑不出结论）

```sh
# 0) 镜像 digest 与版本（#54 的 Run Summary 里应能直接粘）
docker compose images --format '{{.Repository}}:{{.Tag}} {{.ID}}'
docker image inspect --format '{{index .RepoDigests 0}}' "$(docker compose images -q yanshu-server)"

# 1) compose 默认 tag 是 v0.2.0（#53）
grep -n 'v0\.2\.0' docker-compose.yml docs/DEPLOY.md

# 2) 探活 + 配置不可缓存（时钟基准不能被 CDN 冻住）
curl -fsS http://127.0.0.1:8080/healthz
curl -sS -D - -o /tmp/cfg.json http://127.0.0.1:8080/v1/config | grep -iE 'cache-control|cdn-cache-control'
python3 -c 'import json;print(json.load(open("/tmp/cfg.json"))["server_time"])'

# 3) 统计：三个 no-store + 只有聚合数字 + UTC 日界
curl -sS -D - -o /tmp/stats.json http://127.0.0.1:8080/v1/stats | grep -iE 'cache-control|cdn-cache-control|surrogate-control'
python3 - <<'PY'
import json; d=json.load(open('/tmp/stats.json'))
assert set(d)=={'today','total','generated_at'}, d
assert set(d['today'])=={'consumed','consumed_bytes','created'}
print('stats ok', d['today'], d['generated_at'])
PY

# 4) 真实 TTL：建一条 → 取件 → 过期后必须 410（这里用 curl 验 410 语义，需带一次 upload_token 的完整流程）
#    最省事：真机用浏览器走一遍「发件→对方取走」，再查
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/v1/transfers/<expired_transfer_id>/prelude   # 期望 410

# 5) 清理水位与密文残留（部署机看真实磁盘）
docker compose logs --tail=200 yanshu-server | grep -E 'sweep' | tail -5      # purgeRemaining 应逐步归 0
du -sh "$(docker compose exec -T yanshu-server printenv YANSHU_BLOB_DIR)"
```

**哪些必须真机跑**：B 全部（缓存头、镜像 digest、compose tag、真实 410、日志里的 sweep 数字、磁盘占用）。
**哪些本地即可**：A 全部（`go test`、`npm run check`、五脚本、首屏行数、迁移专项）。

## 四、需回修

无阻塞项。两条操作提醒：
1. `#53` 的分支名是 `chore/release-v0.2.0`（不是 `bump-compose-v020`），合入时别取错 ref；
2. `#53`、`#54` 必须在 **tag `v0.2.0` 之前**合入，否则 tag 里的 compose 还是 `v0.1.4`、CI 也不会写 digest。
