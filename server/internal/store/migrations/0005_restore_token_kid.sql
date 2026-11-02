-- 0005_restore_token_kid.sql · 回滚保护：把 KID 列与状态表补齐（幂等）
--
-- 背景：中间有一版 0004 曾把 upload_token_kid 列与 token_kid_state 表删掉（已从仓库移除）。
-- 对**已经跑过那次删除**的库，这条负责恢复；对新库是 no-op。
-- 存量行没有版本信息 → 填 'pre-kid'，这些 token 会被判为旧版本（客户端重建传输即可）。

ALTER TABLE transfers ADD COLUMN IF NOT EXISTS upload_token_kid text;
UPDATE transfers SET upload_token_kid = 'pre-kid' WHERE upload_token_kid IS NULL;
ALTER TABLE transfers ALTER COLUMN upload_token_kid SET NOT NULL;

CREATE TABLE IF NOT EXISTS token_kid_state (
    id         boolean     PRIMARY KEY CHECK (id),
    kid        bigint      NOT NULL CHECK (kid > 0),
    updated_at timestamptz NOT NULL
);
