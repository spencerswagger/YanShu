-- 0007_v5_metadata_stats.sql · v5：元数据永久保留 + 30 天脱敏 + 全平台统计计数器
--
-- 1) 终结元数据不再按时间删除（去掉 7 天墓碑清理）。
-- 2) 终结 +30 天后把三个关联性字段置 NULL，因此必须放开它们的 NOT NULL 约束。
--    老数据不受影响：列里已有值保持不变，只是约束允许未来写 NULL。
-- 3) 统计计数器：按天累加 consumed/consumed_bytes/created，读取只查这张小表，不扫 transfers。

ALTER TABLE transfers ALTER COLUMN prelude_sm3 DROP NOT NULL;
ALTER TABLE transfers ALTER COLUMN upload_token_sm3 DROP NOT NULL;

CREATE TABLE IF NOT EXISTS stats_counters (
    day            date    PRIMARY KEY,
    consumed       bigint  NOT NULL DEFAULT 0 CHECK (consumed >= 0),
    consumed_bytes bigint  NOT NULL DEFAULT 0 CHECK (consumed_bytes >= 0),
    created        bigint  NOT NULL DEFAULT 0 CHECK (created >= 0)
);

-- 回填：历史数据一次性聚合（按终结日期 / 创建日期分桶）。
INSERT INTO stats_counters (day, consumed, consumed_bytes, created)
SELECT terminal_at::date, count(*), COALESCE(sum(plaintext_size), 0), 0
FROM transfers
WHERE state = 'CONSUMED' AND terminal_at IS NOT NULL
GROUP BY terminal_at::date
ON CONFLICT (day) DO UPDATE
SET consumed = EXCLUDED.consumed, consumed_bytes = EXCLUDED.consumed_bytes;

INSERT INTO stats_counters (day, consumed, consumed_bytes, created)
SELECT created_at::date, 0, 0, count(*)
FROM transfers
GROUP BY created_at::date
ON CONFLICT (day) DO UPDATE
SET created = EXCLUDED.created;
