# 合入顺序 + 每张合入后的最小回归

> 只写**客观状态**与**可执行项**。合并动作由主持人点名，本文件不下"可以合"的结论。
> 状态会过期：本文件所有 sha 都是**快照**，复跑前先用 `git log --oneline -1 origin/main` 核一遍。

## 0. 状态更新（2026-11-10 19:22Z / 2026-11-11 03:22 CST，合并执行 = Core）

**main 现为 `1f6b9e0`；v0.2.1 已于 2026-11-10T19:10:29Z 发布。**

已合入（本文件上一版 §0 把 `#56/#57/#58` 都列在"待合"里，已过期；#58 仍在队列，见下表）：

| PR | 合入时间 | 合入点 sha | 内容 |
|---|---|---|---|
| #56 | 19:02:25Z | `7385f8b` | §1.7.4 终结态 410 先于凭据 401 |
| #57 | 19:04:36Z | `9efc88f` | 建索引锁写的防回退门禁 |
| #62 | — | `72890a1` | release v0.2.1（compose 默认 tag） |
| #63 | — | `1f6b9e0` | v0.2.1 两个镜像 digest 记录 |

当前待合（同一时刻 `gh pr list --state open` 实测 **5 张**，head sha 为 19:22Z 快照）：

| 顺序 | PR | 分支 | head | 改了什么 | 文件面 |
|---|---|---|---|---|---|
| 1 | #60 | `fix/crosscheck-tool-path` | `dfda335` | crosscheck 用 cargo 自报的 `ys-tool` 路径（裸跑不再中断） | `scripts/crosscheck/run.sh` |
| 2 | #58 | `fix/contract-envelope-fallback` | `760dfdb` | 未匹配路由 / 未定义方法也走 §0.2 错误信封 | `server/internal/httpapi`、`server/internal/spec`、`docs/API.md` |
| 3 | #61 | `fix/wasm-sync-provenance` | `de31ccb` | `wasm:sync` 不写溯源导致"产物↔commit 同源"静默 SKIP | `web/scripts`、`web/tests`、`web/README.md` |
| 4 | #59 | `qa/fix-ab-evidence` | `639d94f`（本 PR） | 纯 qa 证据脚本 + 结果 + 本文件 | `qa/evidence/fix-ab/` |
| — | #64 | `qa/release-clean-env` | `bf813a6` | 干净环境收发自测脚本 + 最小 CI 方案（**另一条线**，不在本次合入序列） | `qa/evidence/release/` |

**与"8 张"的出入（旧账，2026-11-10 17:25Z 快照）**：那份快照里 `gh pr list --state open` 只有 3 张
（#56/#57/#58），加上本 PR cherry-pick 的 `qa/v5-evidence` 2 个未合提交（v0.2.0 核验留档）、以及 4 个
**没建 PR**的旧分支（`docs/readme-rewrite`、`feat/web-image-nginx`、`fix/compose-volume-perms`、
`docs/contract-clarify`，最后提交 2026-11-02/03，`main..branch` 领先 37 个提交，属 stale），
凑成 8 项。**这 8 项里 5 项从来不是"待合 PR"**，以后再有人问"是不是 8 张"，按本节口径回答。

## 1. 本轮顺序：`#60 → #58 → #61 → #59`

由执行人（Core）定，理由是可核的：

- **#59 必须最后**：它是纯证据/文档 PR，本文件写的就是"剩下几张的合入状态"，先合就会立刻自我过期。
- **前三张文件面零重叠**（#60 `scripts/` / #58 `server/internal/**` / #61 `web/**`），无硬依赖，
  顺序可按需要调；把服务端行为变更（#58）排在中段，是为了让 #61 这条纯前端工具链修复在它之后
  再跑一次 `npm run check`，确认契约改动没有波及前端用例。
- #64 不参与本序列（发布自测脚本，见该 PR 自身的方案页）。

## 2. 历史顺序：`#57 → #58 → #56`（已执行完，仅留档）

三张 PR 文件面零重叠（#57 store / #58 api+spec / #56 handlers），当时按「行为变更尽量靠后、
门禁尽量靠前」排：#57 先上锁 → #58 定错误信封口径 → #56 改上传侧状态码（影响客户端最大，放最后便于 bisect）。
**实际执行是 `#56`(19:02Z) → `#57`(19:04Z)，计划的 `#57 → #56` 互换了**：二者文件面零重叠，
顺序对结果无影响（#57 的门禁与 #56 的 handlers 互不引用），只影响 bisect 时的边界清晰度。

- **#57 不是"纯测试"**：`isNoTxMigration` 的语义被收紧（未来迁移里散文提一句指令不再误触发
  no-transaction），是**有意的行为变更**。
- 与 Ark（架构）的分歧只有措辞：他说"#57 不是零行为变更"，我原记成"纯测试"；以他的说法为准——
  **#57 = 零现存行为变更，但不是零行为变更**。其余无分歧。

## 3. 每张合入后的最小回归（一条一项，可执行）

前置（每张都先做）：`git fetch origin && git switch main && git pull --ff-only`，再合；
合完在 main 的干净树上跑。下面每条都用子 shell，**不依赖上一条的 cwd**。

### #60 合入后（crosscheck 工具路径）

```sh
sh scripts/crosscheck/run.sh          # 期望 PASS 84 / FAIL 0 / SKIP 0，退出码 0（不 source /.keys/env.sh 也要过）
# 回归：源环境变量后再跑一次，确认原本能用的路径没退步
sh -c '. /.keys/env.sh && sh scripts/crosscheck/run.sh'
```

### #58 合入后（契约错误信封）

```sh
(cd server && go build -o ./yanshu-server ./cmd/yanshu-server)            # 重编，别用旧二进制
qa/evidence/fix-ab/ab_contract_envelope.py --binary ./server/yanshu-server --expect after
# 期望 4/4 信封（404 ROUTE_NOT_FOUND / 405 METHOD_NOT_ALLOWED，带 request_id）+ 2 条对照组 PASS
(cd server && go test ./internal/httpapi -list 'Envelope|Fallback|Routed')   # 先核名字：名字变了 -run 会空转
(cd server && go test ./internal/httpapi \
  -run 'TestUnroutedPathKeepsContractEnvelope|TestWrongMethodKeepsContractEnvelope|TestHandlerWiresUnroutedFallback' -v)
# 期望：3 条 --- PASS（-run 匹配不到时静默 exit 0，所以先 -list 再跑）
```

### #61 合入后（wasm 溯源）

```sh
(cd web && npm run check)             # = node --test tests/*.test.js && vite build
# 期望 # tests 130 / # pass 130 / # fail 0 / # skipped 0（skipped>0 就是溯源没写，别当通过）
# 前置：web/node_modules 已装（干净检出先 npm ci）
```

### #56 / #57 合入后（已合，回查用）

```sh
(cd server && go build -o ./yanshu-server ./cmd/yanshu-server)
qa/evidence/fix-ab/ab_terminal_410.py --binary ./server/yanshu-server --expect after
# 期望 24/24 = 410 + 对应终态码；阴性对照 8 条仍是 401 AUTH_MISSING / AUTH_TOKEN_INVALID
(cd server && go test ./internal/httpapi -run 'Terminal|NonTerminal' -v)

(cd server && go test ./internal/store \
  -run 'TestMigrationsCreateIndexesWithoutBlockingWrites|TestNoTxMigrationHasConcurrentIndex' -v)
(cd server && YANSHU_DATABASE_URL="$TEST_DATABASE_URL" ./yanshu-server -migrate-only)  # 9 份迁移全过
(cd server && YANSHU_DATABASE_URL="$TEST_DATABASE_URL" ./yanshu-server -migrate-only)  # 重跑幂等
```

### 全合完（发版前）

```sh
(cd server && go build ./... && go vet ./... && gofmt -l . && go test ./...)   # 真 PG：TEST_DATABASE_URL
(cd server && go build -o ./yanshu-server ./cmd/yanshu-server)
qa/evidence/fix-ab/ab_contract_envelope.py --binary ./server/yanshu-server --expect after
qa/evidence/fix-ab/ab_terminal_410.py --binary ./server/yanshu-server --expect after
qa/evidence/fix-ab/ab_index_lock_write.py --rows 600000
(cd web && npm run check)
sh scripts/crosscheck/run.sh
```

## 4. `--before-ref` 口径（最容易踩的一条）

**不要再用 `origin/main` 当"修前"基线**：#56（19:02Z）已合入，main 现在**本身就带着 410 修复**；
#58 一合，连契约信封也进 main。照抄旧文档写 `--before-ref origin/main`，before 树就成了"修后"，
A/B 直接反着判。

写死已合的 sha：

| 参数 | 值 | 是什么 |
|---|---|---|
| `--before-ref` | `bf84457` | #55 合入点 = #56/#57 合入前的 main（真·修前基线） |
| `--after-ref` | `7385f8b` | #56 合入点（含 410 修复） |
| `--envelope-after-ref` | `760dfdb` | #58 分支 head（#58 合入后改用其合入点 sha） |
| `--guard-ref` | `9efc88f` | #57 合入点（含建索引门禁） |

`run_all.sh` 的默认 `--before-ref` 已改成 `bf84457`；并加了保护：**before 与任一 after ref 解析到同一
commit 时直接 BLOCKED（exit 2）**，不再让人拿一份树自证。

已核过的树面（`git grep` 快照）：

```
bf84457  ROUTE_NOT_FOUND:0  410(StatusGone):0  建索引门禁:0   ← 三处修复全都没有
7385f8b  ROUTE_NOT_FOUND:0  410(StatusGone):1  建索引门禁:0
9efc88f  ROUTE_NOT_FOUND:0  410(StatusGone):1  建索引门禁:1
760dfdb  ROUTE_NOT_FOUND:2  410(StatusGone):0  建索引门禁:0   ← 只含信封修复
```

## 5. 两处观察（不影响合入，供提交人决定）

1. **`Allow` 头与修前一致**：`DELETE /healthz` 修前 `Allow: GET, HEAD`、修后同样是 `GET, HEAD`
   （#58 在 17:39 的复审修复里补齐了 HEAD）。此前一版只回 `GET`，已复测不再存在，本条留档防止
   有人拿旧结论复核。
2. **`/healthz` 不在 `/v1` 前缀下**：`DELETE /v1/healthz` 属"路径不存在"，按 404 处理是对的；
   要复现 405 必须用 `DELETE /healthz`。列在这里只是防止别人用错路径得出相反结论。

> **`results/` 里的结果对应哪几棵树**（2026-11-10T17:52Z 那一轮）：before = `bf84457`（当时
> `origin/main` 就是它，与本节写死的基线**同一个 commit**）、after(410) = `884fbe4`（#56 分支 head，
> `git diff 7385f8b 884fbe4 -- server` 为空，即服务端树相同）、envelope-after = `760dfdb`（#58 分支 head）、
> guard = `f941589`（#57 分支 head，`git diff 9efc88f f941589 -- server/internal/store` 为空，
> 门禁实验只看 store）。任何人复跑时树换了就必须重出一份结果，别拿旧结果套新树。
