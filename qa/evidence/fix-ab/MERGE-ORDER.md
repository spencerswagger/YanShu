# 待合 PR：依赖顺序 + 每张合入后的最小回归

> 只写**客观状态**与**可执行项**。合并动作由主持人点名，本文件不下"可以合"的结论。

## 0. 实际待合清单（截至 2026-11-11 01:25 CST / 2026-11-10 17:25Z）

| PR | 分支 | 改了什么 | 文件面 |
|---|---|---|---|
| #57 | `fix/migration-index-lock-guard` | 建索引锁写的防回退门禁；顺带把 `isNoTxMigration` 从"注释里出现字样就算"收紧为"整行独占" | `store.go` + 新增 store 测试 |
| #58 | `fix/contract-envelope-fallback` | 未匹配路由 / 未定义方法也走 §0.2 错误信封（`ROUTE_NOT_FOUND` / `METHOD_NOT_ALLOWED`） | `api.go`、`fallback.go`、`spec/errors.go` + 测试 + 文档 + 脚本 |
| #56 | `fix/terminal-410-before-token` | §1.7.4 终结态 410 先于凭据 401（四条上传路径） | `handlers_transfers.go` + 新增测试 |

**与"8 张"的出入（必须点明）**：`gh pr list --state open` 只有上面 **3 张**。#47–#55 已 MERGED。
剩下能对得上"待合"的只有两笔：本 PR cherry-pick 的 `qa/v5-evidence` 2 个未合提交（v0.2.0 核验留档）。
另有 4 个**没建 PR**的旧分支（最后提交 2026-11-02/03）：`docs/readme-rewrite`、`feat/web-image-nginx`、
`fix/compose-volume-perms`、`docs/contract-clarify`（`main..branch` **领先** 37 个提交、`branch..main`
落后 357 个，属 stale）。3 + 1（QA 两笔）+ 4 = 8 能对上账，但其中 5 项不是"待合 PR"。
若主持人手上另有 PR 单，说明它们还没推上来。

## 1. 顺序：没有硬依赖，这是**风险序**

三张 PR 的文件面零重叠（#57 store / #58 api+spec / #56 handlers），任一顺序都能合。
按「行为变更尽量靠后、门禁尽量靠前」排：

```
#57  →  #58  →  #56
```

- **#57 先**：对现有 9 份迁移**等价**（`0010` 的指令本来就在独占行），属于"先上锁"。
  注意它不是纯测试：`isNoTxMigration` 的语义被收紧（未来迁移里散文提一句指令不再误触发
  no-transaction），这是有意的行为变更，回归项里必须覆盖迁移执行本身。
- **#58 次**：把全局错误信封定型，后面 #56 的门禁/客户端按 `error.code` 分支时不会二次换口径。
- **#56 最后**：改的是上传侧错误码（401/409 → 410），对现有客户端行为影响最大，放最后便于
  bisect。

**与 Ark（架构）的分歧点**：Ark 的顺序也是 `#57 → #58 → #56`，一致；分歧只有一处措辞 ——
他说"#57 不是零行为变更"（因为动了 `isNoTxMigration`），我原先把 #57 记成"纯测试"。以他的
说法为准：**#57 = 零现存行为变更，但不是零行为变更**。其余无分歧。

## 2. 每张合入后的最小回归（一条一项，可执行）

前置（每张都先做）：`git fetch origin && git switch main && git pull --ff-only`，再合；
合完在 main 的干净树上跑。下面每条都用子 shell，**不依赖上一条的 cwd**。

### #57 合入后

```sh
(cd server && go build ./... && go vet ./... && gofmt -l .)                # 期望：无输出
(cd server && go test ./internal/store \
  -run 'TestMigrationsCreateIndexesWithoutBlockingWrites|TestNoTxMigrationHasConcurrentIndex' -v)
(cd server && go build -o ./yanshu-server ./cmd/yanshu-server)            # -migrate-only 要用的二进制
(cd server && YANSHU_DATABASE_URL="$TEST_DATABASE_URL" ./yanshu-server -migrate-only)  # 9 份迁移全过
(cd server && YANSHU_DATABASE_URL="$TEST_DATABASE_URL" ./yanshu-server -migrate-only)  # 重跑幂等
```

### #58 合入后

```sh
(cd server && go build -o ./yanshu-server ./cmd/yanshu-server)            # 重编，别用上一块的旧二进制
qa/evidence/fix-ab/ab_contract_envelope.py --binary ./server/yanshu-server --expect after
# 期望 4/4 信封（404 ROUTE_NOT_FOUND / 405 METHOD_NOT_ALLOWED，带 request_id）+ 2 条对照组 PASS
(cd server && go test ./internal/httpapi -list 'Envelope|Fallback|Routed')   # 先核名字：名字变了 -run 会空转
(cd server && go test ./internal/httpapi \
  -run 'TestUnroutedPathKeepsContractEnvelope|TestWrongMethodKeepsContractEnvelope|TestHandlerWiresUnroutedFallback' -v)
# 期望：3 条 --- PASS（-run 匹配不到时静默 exit 0，所以先 -list 再跑）
```

### #56 合入后

```sh
qa/evidence/fix-ab/ab_terminal_410.py --binary ./server/yanshu-server --expect after
# 期望 24/24 = 410 + 对应终态码；阴性对照 8 条仍是 401 AUTH_MISSING / AUTH_TOKEN_INVALID
(cd server && go test ./internal/httpapi -run 'Terminal|NonTerminal' -v)
```

### 三张全合完（发版前）

```sh
(cd server && go build ./... && go vet ./... && gofmt -l . && go test ./...)   # 真 PG：TEST_DATABASE_URL
(cd server && go build -o ./yanshu-server ./cmd/yanshu-server)
qa/evidence/fix-ab/ab_contract_envelope.py --binary ./server/yanshu-server --expect after
qa/evidence/fix-ab/ab_terminal_410.py --binary ./server/yanshu-server --expect after
qa/evidence/fix-ab/ab_index_lock_write.py --rows 600000
```

## 3. 两处观察（不影响合入，供提交人决定）

1. **`Allow` 头与修前一致**：`DELETE /healthz` 修前 `Allow: GET, HEAD`、修后同样是 `GET, HEAD`
   （#58 在 17:39 的复审修复里补齐了 HEAD）。此前一版只回 `GET`，已复测不再存在，本条留档防止
   有人拿旧结论复核。
2. **`/healthz` 不在 `/v1` 前缀下**：`DELETE /v1/healthz` 属"路径不存在"，按 404 处理是对的；
   要复现 405 必须用 `DELETE /healthz`。列在这里只是防止别人用错路径得出相反结论。

> 说明：本轮的 A/B 结果对应 #58 `760dfdb`（17:39）、#57 `f941589`（17:21）、#56 `884fbe4`（14:26）。
> 提交人后续再推，回归项要按同一组脚本重跑。
