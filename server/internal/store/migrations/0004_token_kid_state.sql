-- 0004 · token KID：列 + 状态表（幂等；对已经跑过 drop 版本的库也能补回来）
--
-- 最终裁决保留 KID：它是唯一吊销开关（严格单调递增，调小拒绝启动）。

ALTER TABLE transfers ADD COLUMN IF NOT EXISTS upload_token_kid text;
UPDATE transfers SET upload_token_kid = 'pre-kid' WHERE upload_token_kid IS NULL;
ALTER TABLE transfers ALTER COLUMN upload_token_kid SET NOT NULL;

CREATE TABLE IF NOT EXISTS token_kid_state (
    id         boolean     PRIMARY KEY CHECK (id),
    kid        bigint      NOT NULL CHECK (kid > 0),
    updated_at timestamptz NOT NULL
);
