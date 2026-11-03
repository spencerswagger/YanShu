-- 0002_upload_token_kid.sql · 给已有库补 upload_token_kid（token 密钥版本）
--
-- 背景：0001 在合入前被重写过一次，新增了 upload_token_kid；对**已经应用过 0001 的库**，
-- 迁移器不会重跑 0001，于是缺这一列（表现为 token 校验直接报错）。这条 migration 负责补齐。
-- 对全新库它是 no-op（列已存在）。

ALTER TABLE transfers ADD COLUMN IF NOT EXISTS upload_token_kid text;

-- 存量行没有版本信息：填一个固定哨兵，轮换后的实现会把它判为"旧版本"，
-- 客户端重建传输即可拿到带当前 kid 的新 token。
UPDATE transfers SET upload_token_kid = 'pre-kid' WHERE upload_token_kid IS NULL;

ALTER TABLE transfers ALTER COLUMN upload_token_kid SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'transfers_upload_token_kid_len'
    ) THEN
        ALTER TABLE transfers ADD CONSTRAINT transfers_upload_token_kid_len
            CHECK (octet_length(upload_token_kid) BETWEEN 1 AND 32);
    END IF;
END $$;
