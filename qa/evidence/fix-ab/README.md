# fix-ab：两处真修复的**独立** A/B 证据

目的：对「契约规则运行时没真跑」与「建索引锁写」两处修复，各拿一份**不看提交人自证**的
可复跑证据 —— 同一份脚本打「修前」和「修后」两棵树，只按 `docs/API.md` 的线格式与真 PG
的行为判定。

| 脚本 | 守的规则 | 修前（main） | 修后 |
|---|---|---|---|
| `ab_contract_envelope.py` | API.md §0.2「所有非 2xx 响应统一错误信封」 | 未路由的 404/405 是 `text/plain`，无 `error.code`/`request_id` | 404 `ROUTE_NOT_FOUND` / 405 `METHOD_NOT_ALLOWED` 的 JSON 信封 |
| `ab_terminal_410.py` | API.md §1.7.4「终结态 410 先于凭据 401」 | 24 例里 0 例 410（`401 AUTH_MISSING` / `AUTH_TOKEN_INVALID` / `409`） | 24/24 都是 410 + 对应终态码 |
| `ab_index_lock_write.py` | 迁移里的 `CREATE INDEX` 不得挡住写入 | 事务 + 普通 `CREATE INDEX`：单条写最长阻塞 ≈ 建索引耗时，`pg_locks` 见 `ShareLock` | `CREATE INDEX CONCURRENTLY`：写入持续，只见 `ShareUpdateExclusiveLock` |

三份脚本共用 `ab_common.py`（纯标准库：SM3、用户码派生、最小 API 客户端、起真服务）。
不 import 被测代码，不 import 提交人的测试；判据只来自契约文本与 PG 的实际行为。

## 怎么跑

前置：`go`（run_all 现编两版二进制）、`psql`（ab_common 直查）、一个可连的 PostgreSQL
（脚本自己建/删独立 schema，不碰别的库）+ `TEST_DATABASE_URL`。

```sh
# 一条命令：建两棵树 → 编二进制 → 跑三组 A/B（结果写 results/）
qa/evidence/fix-ab/run_all.sh \
  --before-ref origin/main \
  --after-ref  origin/fix/terminal-410-before-token \
  --envelope-after-ref ''            # 契约信封兜底分支还没推 → 留空，只跑修前基线并标 SKIP
  --guard-ref origin/fix/migration-index-lock-guard   # 防回退门禁（PR #57）+ 变异体反向验证

# 或单跑某一份
python3 qa/evidence/fix-ab/ab_terminal_410.py --binary bin/yanshu-server --expect after
python3 qa/evidence/fix-ab/ab_index_lock_write.py --rows 600000
```

退出码：0 = 与 `--expect` 相符；1 = 不符；2 = 环境/前置失败（BLOCKED）。
`run_all.sh` 会聚合：**任何一项非 0 → 整体 exit 1**（`results/*.rc` 逐项记录；验证方式是
把 `--after-ref/--envelope-after-ref/--guard-ref` 全换成 `origin/main`，整体必须非 0，
留档见 `results/negative-run-rc.txt`）。
每份脚本都会把结构化结果写成 JSON（含 `at` 时间戳、二进制 `sha256`、逐例原始状态码与
错误名），可直接给评审看。

## 判据为什么是这样

- **契约**：错误信封与判定顺序是契约**写死**的（§0.2 / §1.7.4），不是"实现口味"。脚本
  只断言契约明文要求的部分：非 2xx 必须带 `error.code`；终结态下 24 例必须全是 410 且
  码与终态一致；同时保留**阴性对照**（未终结仍须 401），防止"一律 410/一律包信封"式假绿。
- **索引**：锁的类型和阻塞时长不是推断出来的，是 `pg_locks` 采样 + 同期真实 `INSERT`
  的单条延迟实测。同一个 writer 贯穿基线/A/B 三段，避免"两段分别测"带来的漂移。

## 已知边界

- `ab_terminal_410.py` 的 CONSUMED 用例是**真的走完**取件：complete → GET prelude 拿租约
  → 取两块 → ack（只取件不 ack 只到 READY，不是终态）。
- `ab_index_lock_write.py` 在 phase A 建索引 <300ms 时会直接 BLOCKED（窗口太短、判定不可靠），
  默认 60 万行约 800ms；绝对值随机器/数据量变化（本机 60 万行 / 113 MB：A 808 ms 建
  索引、单条写最长 778.9 ms；B 886 ms、最长 55.3 ms）。结论看**相对关系**与锁模式，不看
  某个固定毫秒数。
- `run_all.sh` 需要本地 git 仓库（用 `git archive` 取两棵树），不需要切分支、不动工作树。
