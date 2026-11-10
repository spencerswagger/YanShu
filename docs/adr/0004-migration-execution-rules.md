# ADR-0004：迁移执行的硬约定（no-transaction 指令与幂等）

| 项 | 值 |
|---|---|
| 状态 | **已采纳**（2026-11-10） |
| 日期 | 2026-11-10 |
| 适用版本 | 服务端 v0.2.x 起（迁移器 `server/internal/store`） |
| 关联文档 | `server/README.md` §库表 · `docs/DEPLOY.md` §部署；`migrations/0010_indexes_concurrently.sql` 文件注释 |
| 影响面 | 只定约定，不改迁移器行为、不改任何既有迁移文件 |

---

## 0. 为什么要有这份 ADR

这两条规则此前**只写在 `0010` 的文件注释里**。注释跟着一个文件走，下一个写 no-tx 迁移的人不会读到它；
而违反后的症状是"部署启动失败"或"半截 schema + 迁移记录缺失"，都不是能靠读 diff 看出来的。所以升格为文档。

以下两条都由本 ADR 作者**实跑验证**（真二进制 + 真 PG 17），不是推演。

## 1. 规则一：`-- yanshu:no-transaction` 必须**独占一行**

迁移器（`store.isNoTxMigration`，PR #57 收紧）只认「整行就是该指令」的写法，出现位置必须在**第一条语句之前**。

**违反后的实测行为（fail-closed，不会静默锁表）**：

```
$ # 把指令混在别的注释同一行，文件里放 CREATE INDEX CONCURRENTLY
$ ./yanshu-server -migrate-only
time=2026-11-10T20:48:36.114Z level=ERROR msg=fatal err="store: apply 0011_probe_inline_directive.sql:
  ERROR: CREATE INDEX CONCURRENTLY cannot run inside a transaction block (SQLSTATE 25001)"
exit=1
```

即：文件被当成事务式执行 → PostgreSQL 直接拒绝 `CREATE INDEX CONCURRENTLY` → **进程退出、服务起不来**。
这是**期望**的失败方式：宁可启动失败，也不要"以为在并发建、实际在锁表"。

**规矩**：

1. 指令行只有一个内容：`-- yanshu:no-transaction`（前后可有空行，不得与其它文字同行）。
2. 文件里出现 `CONCURRENTLY` 就**必须**带这条指令；带这条指令就**必须**确认每条语句都能自动提交（不能有需要跨语句事务的语义）。
3. 门禁：`server/internal/store/migrations_lock_guard_test.go`（PR #57）对全量迁移文件双向断言，写错即红。

## 2. 规则二：no-tx 迁移**非原子**，重跑必须幂等

事务式迁移靠"整文件一个事务"保证原子；no-tx 迁移是**逐条语句自动提交**，且 `schema_migrations`
的记录**只在全部语句成功之后**才写。所以中途失败会留下"半截 schema + 无迁移记录"。

**实测（第 2 条语句故意失败）**：

```
err="store: apply 0012_probe_partial.sql (statement 2/2): ERROR: relation \"probe_partial_t\" already exists (SQLSTATE 42P07)"
exit=1
# 现场核查：
probe_partial_t exists=true          ← 第 1 条语句已提交，回不去
migrations=0001…0010                 ← 0012 没有记录，下次启动会从头再跑这个文件
```

**规矩**：no-tx 迁移的每条语句都必须**可重复执行**，推荐写法（`0010` 的既有做法）：

```sql
DROP INDEX CONCURRENTLY IF EXISTS <name>;              -- 先清掉上一轮可能留下的 INVALID 残留
CREATE INDEX CONCURRENTLY IF NOT EXISTS <name> ON ...; -- 再建
```

`CREATE INDEX CONCURRENTLY` 中断会留下 `INVALID` 索引（占名字但查询用不了，`IF NOT EXISTS` 会**跳过**它），
所以「先 DROP 再 CREATE」不是洁癖，是唯一能自愈的写法。其它语句同理：`CREATE TABLE IF NOT EXISTS`、
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`、必要时用 `DO $$ ... $$` 显式判存在。

新增/修改 no-tx 文件时，PR 描述必须写一句「本文件幂等，依据是第 N 条语句的 IF EXISTS / DROP-then-CREATE」。

## 3. 与 `0010` 现状的核对（已跑）

- 全新 schema 迁移：`schema_migrations` 记 9 条（`0001,0002,0004,0005,0006,0007,0008,0009,0010`；仓库无 `0003`）。
- `transfers` / `transfer_chunks` / `codes` 上 13 个索引 `indisvalid = t` 全绿。
- `0010` 第 1 行就是指令（独占），且五个 v5 索引全部是 `DROP ... IF EXISTS` + `CREATE ... CONCURRENTLY IF NOT EXISTS`。

## 4. 待落地（由 Core 落，本 ADR 只给文字）

这两段属于 Core 维护的文件，本 ADR 不直接改，交给主持人指派：

**`server/README.md` §库表 · 迁移执行方式**（在该段末尾追加两句）：

> no-transaction 指令必须**独占一行**且位于第一条语句之前；写在别的注释同一行会被当成事务式，
> `CREATE INDEX CONCURRENTLY` 随即被 PostgreSQL 拒绝（`SQLSTATE 25001`），迁移失败、服务启动失败。
> no-tx 迁移是逐条自动提交、**非原子**：中途失败会留下半截 schema 且不写 `schema_migrations`，
> 因此每条语句必须可重复执行（`0010` 的 `DROP … IF EXISTS` + `CREATE … IF NOT EXISTS` 是标准写法）。
> 详见 `docs/adr/0004-migration-execution-rules.md`。

**`docs/DEPLOY.md` §部署**（在"服务启动时先跑 `-migrate-only`"那条之后追加一句）：

> 迁移失败会让进程直接退出（fail-closed），先看首行 ERROR 定性：`cannot run inside a transaction block`
> = 某份 no-tx 迁移的指令写法不合法；`already exists` = 某份 no-tx 迁移不幂等（重跑会再撞一次）。
> 两者都是代码问题，不要靠手工改库绕过。详见 `docs/adr/0004-migration-execution-rules.md`。
