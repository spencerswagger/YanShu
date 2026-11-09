-- 0009_ciphertext_purge_watermark.sql · v5：密文删除水位 + 脱敏扫描索引
--
-- 1) `ciphertext_purged_at` 是兜底删密水的**水位**。
--    永久保留后，终结行的集合不再随保留期缩小；清理任务若还用
--    「ORDER BY terminal_at LIMIT n」的定长批，每个 tick 都会拿回同一批最老的行，
--    更晚终结的行永远轮不到，密文永久残留（日志还会每 30s 报一个固定值，把问题掩住）。
--    记下"这一行已经删过密文"之后，每批自然推进到不同行。
-- 2) 脱敏扫描的部分索引：`RedactOldTerminal` 每 30s 跑一次，没有索引时是
--    「终结 ∧ 未脱敏」条件的全表扫（实测 20 万行 74.7ms / 5732 buffers）。
--    索引谓词必须与查询 WHERE 逐字对齐，planner 才会用。

ALTER TABLE transfers ADD COLUMN IF NOT EXISTS ciphertext_purged_at timestamptz;

-- 排序键与查询逐字一致（含 COALESCE 表达式）：不然每 tick 都要先排序再取 200 条，
-- 积压（例如迁移后首次补齐）时会变成 200k 行 top-N 排序（实测 75ms）。
CREATE INDEX IF NOT EXISTS transfers_unpurged_terminal_idx
    ON transfers (COALESCE(terminal_at, updated_at), transfer_id)
    WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED') AND ciphertext_purged_at IS NULL;

CREATE INDEX IF NOT EXISTS transfers_terminal_unredacted_idx
    ON transfers (terminal_at)
    WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED')
      AND (uploader_ip IS NOT NULL OR prelude_sm3 IS NOT NULL OR upload_token_sm3 IS NOT NULL);
