-- yanshu:no-transaction
--
-- 0010_indexes_concurrently.sql · v5：全部新建索引改为 `CREATE INDEX CONCURRENTLY`
--
-- 为什么必须并发建：`CREATE INDEX` 默认取 `SHARE` 锁，建索引期间**阻塞所有写入**；
-- 而 transfers 从 v5 起元数据永久保留、表只会越来越大，越晚越没法等这个锁。
--
-- 为什么单独一个文件、且标了 `yanshu:no-transaction`：`CREATE INDEX CONCURRENTLY`
-- 不能在事务块内执行。迁移器看到文件头这个指令后改为**逐条语句自动提交**（见 store.Migrate）。
--
-- 为什么先 `DROP INDEX CONCURRENTLY IF EXISTS`：CONCURRENTLY 建到一半失败会留下一个
-- **INVALID** 索引（占名字但查询用不了，`CREATE ... IF NOT EXISTS` 会直接跳过它）。
-- 先删再建，保证重跑能自愈；代价是重跑会重建一次（只在"上轮失败"时发生）。

DROP INDEX CONCURRENTLY IF EXISTS transfers_terminal_at_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS transfers_terminal_at_idx
    ON transfers (terminal_at) WHERE terminal_at IS NOT NULL;

DROP INDEX CONCURRENTLY IF EXISTS transfers_created_at_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS transfers_created_at_idx ON transfers (created_at);

DROP INDEX CONCURRENTLY IF EXISTS transfers_unpurged_terminal_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS transfers_unpurged_terminal_idx
    ON transfers (COALESCE(terminal_at, updated_at), transfer_id)
    WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED') AND ciphertext_purged_at IS NULL;

DROP INDEX CONCURRENTLY IF EXISTS transfers_terminal_unredacted_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS transfers_terminal_unredacted_idx
    ON transfers (terminal_at)
    WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED')
      AND (uploader_ip IS NOT NULL OR prelude_sm3 IS NOT NULL OR upload_token_sm3 IS NOT NULL);

-- 块级指纹的脱敏扫描：由"还没脱敏的块"驱动（索引越小扫得越快），而不是由 transfers 侧驱动。
DROP INDEX CONCURRENTLY IF EXISTS transfer_chunks_unredacted_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS transfer_chunks_unredacted_idx
    ON transfer_chunks (transfer_id, chunk_index) WHERE ciphertext_sm3 IS NOT NULL;
