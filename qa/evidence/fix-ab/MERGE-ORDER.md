# 待合 PR：依赖顺序 + 每张合入后的最小回归

> 只写**客观状态**与**可执行项**。合并动作由主持人点名，本文件不下"可以合"的结论。

## 0. 实际待合清单（截至 2026-11-11 01:25 CST / 2026-11-10 17:25Z）

| PR | 分支 | 改了什么 | 文件面 |
|---|---|---|---|
| #57 | `fix/migration-index-lock-guard` | 建索引锁写的防回退门禁；顺带把 `isNoTxMigration` 从"注释里出现字样就算"收紧为"整行独占" | `store.go` + 新增 store 测试 |
| #58 | `fix/contract-envelope-fallback` | 未匹配路由 / 未定义方法也走 §0.2 错误信封（`ROUTE_NOT_FOUND` / `METHOD_NOT_ALLOWED`） | `api.go`、`fallback.go`、`spec/errors.go` + 测试 + 文档 + 脚本 |
| #56 | `fix/terminal-410-before-token` | §1.7.4 终结态 410 先于凭据 401（四条上传路径） | `handlers_transfers.go` + 新增测试 |

**与"8 张"的出入（必须点明）**：`gh pr list --state open` 只有上面 **3 张**。#47–#55 已 MERGED；
`docs/readme-rewrite`、`feat/web-image-nginx`、`fix/compose-volume-perms`、`docs/contract-clarify`
是没建 PR 的旧分支（最后提交 2026-11-02/03，`contract-clarify` 已落后 main 37 个提交），
不算待合。若主持人手上另有 5 张单，说明它们还没推上来。

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
合完在 main 的干净树上跑。

### #57 合入后

```sh
cd server && go build ./... && go vet ./... && gofmt -l .        # 期望：无输出
go test ./internal/store -run 'TestMigrationsCreateIndexesWithoutBlockingWrites|TestNoTxMigrationHasConcurrentIndex' -v
YANSHU_DATABASE_URL="$TEST_DATABASE_URL" ./yanshu-server -migrate-only   # 期望：9 份迁移全过
YANSHU_DATABASE_URL="$TEST_DATABASE_URL" ./yanshu-server -migrate-only   # 期望：重跑幂等、不报错
```

### #58 合入后

```sh
qa/evidence/fix-ab/ab_contract_envelope.py --binary ./yanshu-server --expect after
# 期望 4/4 信封（404 ROUTE_NOT_FOUND / 405 METHOD_NOT_ALLOWED，带 request_id）+ 两条对照组 PASS
cd server && go test ./internal/httpapi -run 'Routes|Unrouted|Fallback' -v
```

### #56 合入后

```sh
qa/evidence/fix-ab/ab_terminal_410.py --binary ./yanshu-server --expect after
# 期望 24/24 = 410 + 对应终态码；阴性对照仍是 401 AUTH_MISSING / AUTH_TOKEN_INVALID
cd server && go test ./internal/httpapi -run 'Terminal|NonTerminal' -v
```

### 三张全合完（发版前）

```sh
cd server && go build ./... && go vet ./... && gofmt -l . && go test ./...   # 真 PG：TEST_DATABASE_URL
qa/evidence/fix-ab/run_all.sh --before-ref origin/main~3 --after-ref origin/main \
  --envelope-after-ref origin/main --guard-ref origin/main
```

## 3. 两处观察（不影响合入，供提交人决定）

1. **`Allow` 头少 `HEAD`**：修前 `DELETE /healthz` 的 405 回 `Allow: GET, HEAD`（Go ServeMux
   对 GET 隐式放行 HEAD），修后只回 `Allow: GET`。客户端若按 `Allow` 判断能不能探活/取块，
   这是可观测差异（不影响 `code` 分支）。
2. **`DELETE /healthz` 走 404 而不是 405**：`/healthz` 不在 `/v1` 前缀下，属"路径不存在"，
   这条按 404 处理是对的；列在这里只是防止别人用 `/v1/healthz` 复现出相反结论（那是真 404）。
