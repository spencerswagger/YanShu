-- 0009_ciphertext_purge_watermark.sql · v5：密文删除水位 + 脱敏列放宽
--
-- 1) `ciphertext_purged_at` 是兜底删密文的**水位**。
--    永久保留后，终结行的集合不再随保留期缩小；清理任务若还用
--    「ORDER BY terminal_at LIMIT n」的定长批，每个 tick 都会拿回同一批最老的行，
--    更晚终结的行永远轮不到，密文永久残留（日志还会每 30s 报一个固定值，把问题掩住）。
--    记下"这一行已经删过密文"之后，每批自然推进到不同行。
-- 2) `transfer_chunks.ciphertext_sm3` 是**内容指纹**（密文块的 SM3），与 prelude_sm3 同类，
--    终结 30 天后必须一起脱敏 → 先放开 NOT NULL。
--
-- 索引不在这里建：见 `0010_indexes_concurrently.sql`（CONCURRENTLY，不阻塞写入）。

ALTER TABLE transfers ADD COLUMN IF NOT EXISTS ciphertext_purged_at timestamptz;

ALTER TABLE transfer_chunks ALTER COLUMN ciphertext_sm3 DROP NOT NULL;
