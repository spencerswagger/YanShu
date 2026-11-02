-- 0004_drop_token_epoch.sql · 撤回 EPOCH 机制（v1 不实现版本号）
--
-- 裁决：v1 的吊销开关是"轮换 token 派生密钥"，不引入 EPOCH/KID。
-- 因此删掉先前为 EPOCH 加的列与状态表（对没有这些对象的库是 no-op）。

ALTER TABLE transfers DROP COLUMN IF EXISTS upload_token_kid;
DROP TABLE IF EXISTS token_kid_state;
