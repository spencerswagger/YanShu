-- 0003_token_kid_state.sql · 记录已用过的最大 token 密钥版本（kid），保证"只增不减"
--
-- 目的：防止运维把 YANSHU_TOKEN_KID 调小后，旧版本 token 重新变得可用。
-- 只有一行（id = true），启动时比较：kid < 记录值 → 拒绝启动。

CREATE TABLE IF NOT EXISTS token_kid_state (
    id         boolean     PRIMARY KEY CHECK (id),
    kid        bigint      NOT NULL CHECK (kid > 0),
    updated_at timestamptz NOT NULL
);
