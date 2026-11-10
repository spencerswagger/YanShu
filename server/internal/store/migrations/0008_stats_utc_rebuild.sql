-- 0008_stats_utc_rebuild.sql · v5 统计的 UTC 日界修复 + 对账用索引
--
-- 背景（ADR-0002 §2.2）：0007 的回填曾用 `terminal_at::date` / `created_at::date`，
-- 这两者在 `timestamptz → date` 截断时吃**会话 TimeZone**。任何已经执行过旧 0007 的库，
-- 若当时会话不是 UTC，计数器就按本地日界分过桶，且不会自己修复。
--
-- 本迁移只做一件事：按 UTC 日界**重算并覆盖** counters（派生数据，重建是安全的；transfers 是事实，不动）。
--
-- 注意：`TRUNCATE` 取 `ACCESS EXCLUSIVE` 锁，**仍需维护窗口**（这一条无法并发化）。
-- 索引不在本文件里建：`CREATE INDEX` 会取 `SHARE` 锁挡住写入，而 transfers 从 v5 起永久保留、
-- 只会变大，所以建索引挪到 `0010_indexes_concurrently.sql`（`CREATE INDEX CONCURRENTLY`，不停写）。

-- 1) UTC 重建计数器
TRUNCATE TABLE stats_counters;

INSERT INTO stats_counters (day, consumed, consumed_bytes, created)
SELECT (terminal_at AT TIME ZONE 'UTC')::date, count(*), COALESCE(sum(plaintext_size), 0), 0
FROM transfers
WHERE state = 'CONSUMED' AND terminal_at IS NOT NULL
GROUP BY 1;

INSERT INTO stats_counters (day, created)
SELECT (created_at AT TIME ZONE 'UTC')::date, count(*)
FROM transfers
GROUP BY 1
ON CONFLICT (day) DO UPDATE SET created = stats_counters.created + EXCLUDED.created;
