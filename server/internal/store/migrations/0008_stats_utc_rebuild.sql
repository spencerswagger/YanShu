-- 0008_stats_utc_rebuild.sql · v5 统计的 UTC 日界修复 + 对账用索引
--
-- 背景（ADR-0002 §2.2）：0007 的回填曾用 `terminal_at::date` / `created_at::date`，
-- 这两者在 `timestamptz → date` 截断时吃**会话 TimeZone**。任何已经执行过旧 0007 的库，
-- 若当时会话不是 UTC，计数器就按本地日界分过桶，且不会自己修复。
--
-- 本迁移做两件事：
-- 1) 按 UTC 日界**重算并覆盖** counters（派生数据，重建是安全的；transfers 是事实，不动）。
-- 2) 给每日对账加两个索引：对账按半开区间 [00:00Z, 次日 00:00Z) 扫一天的行，
--    没有索引时会退化成全表扫（表随年限线性变大）。

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

-- 2) 对账索引
CREATE INDEX IF NOT EXISTS transfers_terminal_at_idx
    ON transfers (terminal_at) WHERE terminal_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS transfers_created_at_idx ON transfers (created_at);
