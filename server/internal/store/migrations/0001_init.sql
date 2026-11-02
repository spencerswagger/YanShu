-- 0001_init.sql · 雁书服务端初始 schema（契约 v1，docs/API.md @ 376c5b5）
--
-- 红线（Gate 验收点）：本库**只**存白名单字段。
--   §2.1 白名单之外，只允许下列「派生/内部」列，它们不含任何用户内容：
--     · transfers.prelude_received / received_chunks / updated_at  —— 由上传行为派生的计数与时间
--     · transfers.upload_token_sm3                                  —— §1.5 明确要求只存 SM3
--     · transfers.uploader_ip                                       —— §11.4 按 IP 的存储配额
--     · transfer_downloads.*                                        —— 下载租约与 ack 幂等状态
--     · idempotency_keys.*                                          —— §6.2 幂等窗口（600s）
--   代码里 internal/store/schema_test.go 对列名做白名单断言，多一列即失败。
--   **没有**文件名、MIME、扩展名、明文、任何密钥材料。

CREATE TABLE IF NOT EXISTS codes (
    code          text        PRIMARY KEY CHECK (length(code) = 4),
    public_key    bytea       NOT NULL UNIQUE CHECK (octet_length(public_key) = 65),
    nickname      text        NOT NULL CHECK (octet_length(nickname) BETWEEN 1 AND 32),
    registered_at timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL
);

-- 一次性挑战：只绑 purpose（API.md §1.2），不绑 code。
CREATE TABLE IF NOT EXISTS auth_challenges (
    challenge_id text        PRIMARY KEY CHECK (challenge_id ~ '^[0-9a-f]{32}$'),
    purpose      text        NOT NULL,
    nonce        bytea       NOT NULL CHECK (octet_length(nonce) = 32),
    expires_at   timestamptz NOT NULL,
    used         boolean     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS auth_challenges_expires_at_idx ON auth_challenges (expires_at);

CREATE TABLE IF NOT EXISTS transfers (
    transfer_id            text        PRIMARY KEY CHECK (transfer_id ~ '^[0-9a-f]{32}$'),
    sender_code            text        NOT NULL,
    recipient_code         text        NOT NULL,
    plaintext_size         bigint      NOT NULL CHECK (plaintext_size BETWEEN 0 AND 4294967296),
    chunk_size             integer     NOT NULL CHECK (chunk_size BETWEEN 16 AND 1048576),
    chunk_count            integer     NOT NULL CHECK (chunk_count BETWEEN 1 AND 1048576),
    prelude_len            integer     NOT NULL CHECK (prelude_len BETWEEN 1 AND 4194304),
    prelude_sm3            bytea       NOT NULL CHECK (octet_length(prelude_sm3) = 32),
    prelude_received       boolean     NOT NULL DEFAULT false,
    received_chunks        integer     NOT NULL DEFAULT 0 CHECK (received_chunks >= 0),
    total_ciphertext_bytes bigint      NOT NULL DEFAULT 0,
    download_count         integer     NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    max_downloads          integer     NOT NULL CHECK (max_downloads BETWEEN 1 AND 3),
    state                  text        NOT NULL CHECK (state IN ('UPLOADING', 'READY', 'LEASED', 'CONSUMED', 'REVOKED', 'EXPIRED')),
    terminal_reason        text        CHECK (terminal_reason IN ('CONSUMED', 'REVOKED', 'EXPIRED')),
    terminal_at            timestamptz,
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL,
    expires_at             timestamptz NOT NULL,
    upload_token_sm3       bytea       NOT NULL CHECK (octet_length(upload_token_sm3) = 32),
    uploader_ip            text
);

CREATE INDEX IF NOT EXISTS transfers_recipient_idx ON transfers (recipient_code, state, created_at DESC);
CREATE INDEX IF NOT EXISTS transfers_sender_idx ON transfers (sender_code, state);
CREATE INDEX IF NOT EXISTS transfers_expires_at_idx ON transfers (expires_at);
CREATE INDEX IF NOT EXISTS transfers_uploader_ip_idx ON transfers (uploader_ip) WHERE state <> 'CONSUMED';

-- 块索引：只有长度与密文 SM3，没有内容、没有块头、没有明文。
CREATE TABLE IF NOT EXISTS transfer_chunks (
    transfer_id   text        NOT NULL REFERENCES transfers (transfer_id) ON DELETE CASCADE,
    chunk_index   integer     NOT NULL CHECK (chunk_index >= 0),
    length        integer     NOT NULL CHECK (length >= 16),
    ciphertext_sm3 bytea      NOT NULL CHECK (octet_length(ciphertext_sm3) = 32),
    stored_at     timestamptz NOT NULL,
    PRIMARY KEY (transfer_id, chunk_index)
);

-- 下载租约：download_id 是 ack 的幂等键（API.md §7.5）。
CREATE TABLE IF NOT EXISTS transfer_downloads (
    download_id      text        PRIMARY KEY CHECK (download_id ~ '^[0-9a-f]{32}$'),
    transfer_id      text        NOT NULL REFERENCES transfers (transfer_id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    acked_at         timestamptz
);

CREATE INDEX IF NOT EXISTS transfer_downloads_transfer_idx ON transfer_downloads (transfer_id);

-- POST /transfers 的幂等窗口（API.md §6.2，600 秒）。
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key_hash            bytea       PRIMARY KEY,
    sender_code         text        NOT NULL,
    request_fingerprint bytea       NOT NULL,
    transfer_id         text        NOT NULL,
    created_at          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idempotency_keys_expires_at_idx ON idempotency_keys (expires_at);

-- 审计：只记 §2.1 白名单字段（ip / method / path / status / bytes / ts / request_id）。
CREATE TABLE IF NOT EXISTS audit_events (
    id         bigserial   PRIMARY KEY,
    ts         timestamptz NOT NULL,
    method     text        NOT NULL,
    path       text        NOT NULL,
    status     integer     NOT NULL,
    bytes      bigint      NOT NULL DEFAULT 0,
    ip         text,
    request_id text
);

CREATE INDEX IF NOT EXISTS audit_events_ts_idx ON audit_events (ts);
