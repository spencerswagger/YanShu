-- 0001_init.sql · 雁书服务端初始 schema
--
-- 红线（Gate 验收点）：本库**只**存白名单字段。
--   · 没有文件名、没有 MIME、没有扩展名、没有任何明文片段；
--   · 与服务端无关的密钥材料（私钥、DK、KEK）一律不入库；
--   · 二进制内容只在磁盘上以不透明密文块存在，库里只留长度与摘要。
-- 任何新增列都必须先过 internal/store/schema_test.go 的白名单断言。

CREATE TABLE IF NOT EXISTS codes (
    code          text        PRIMARY KEY CHECK (length(code) = 4),
    pubkey        bytea       NOT NULL UNIQUE,
    nickname      text        NOT NULL CHECK (octet_length(nickname) BETWEEN 1 AND 64),
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS codes_expires_at_idx ON codes (expires_at);

-- 一次性签名挑战：nonce 只在这里活一次，用过即废。
CREATE TABLE IF NOT EXISTS auth_challenges (
    id          text        PRIMARY KEY,
    purpose     text        NOT NULL CHECK (purpose IN ('register', 'nickname', 'session')),
    code        text        NOT NULL CHECK (length(code) = 4),
    pubkey      bytea       NOT NULL,
    message     bytea       NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_challenges_expires_at_idx ON auth_challenges (expires_at);

-- 会话令牌只存 SHA-256，原文只在响应里出现一次。
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  bytea       PRIMARY KEY,
    code        text        NOT NULL REFERENCES codes (code) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_code_idx ON sessions (code);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS packages (
    id              text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    sender_code     text        NOT NULL,
    recipient_code  text        NOT NULL,
    state           text        NOT NULL CHECK (state IN ('uploading', 'ready', 'expired', 'revoked', 'exhausted', 'purged')),
    chunk_count     integer     NOT NULL CHECK (chunk_count BETWEEN 1 AND 1048576),
    chunk_size      integer     NOT NULL CHECK (chunk_size BETWEEN 16 AND 1048576),
    plaintext_size  bigint      NOT NULL CHECK (plaintext_size BETWEEN 0 AND 4294967296),
    prelude_len     integer     NOT NULL CHECK (prelude_len BETWEEN 1 AND 8388608),
    prelude_digest  bytea       CHECK (octet_length(prelude_digest) = 32),
    received_count  integer     NOT NULL DEFAULT 0 CHECK (received_count >= 0),
    max_downloads   integer     NOT NULL CHECK (max_downloads BETWEEN 1 AND 100),
    downloads_used  integer     NOT NULL DEFAULT 0 CHECK (downloads_used >= 0),
    delete_on_ack   boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    committed_at    timestamptz,
    terminal_at     timestamptz,
    terminal_reason text
);

CREATE INDEX IF NOT EXISTS packages_recipient_idx ON packages (recipient_code, state);
CREATE INDEX IF NOT EXISTS packages_sender_idx ON packages (sender_code);
CREATE INDEX IF NOT EXISTS packages_expires_at_idx ON packages (expires_at);

-- 块索引：只有长度与密文摘要，没有内容、没有块头、没有明文。
CREATE TABLE IF NOT EXISTS package_chunks (
    package_id  text        NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
    chunk_index integer     NOT NULL CHECK (chunk_index >= 0),
    ct_len      integer     NOT NULL CHECK (ct_len >= 0),
    ct_digest   bytea       NOT NULL CHECK (octet_length(ct_digest) = 32),
    received_at timestamptz NOT NULL,
    PRIMARY KEY (package_id, chunk_index)
);

-- 终结后的墓碑：让「已过期 / 已撤回 / 已领取 / 已删除」可区分，且不含任何内容。
CREATE TABLE IF NOT EXISTS package_tombstones (
    id             text        PRIMARY KEY,
    state          text        NOT NULL CHECK (state IN ('expired', 'revoked', 'exhausted', 'purged')),
    sender_code    text        NOT NULL,
    recipient_code text        NOT NULL,
    created_at     timestamptz NOT NULL,
    terminal_at    timestamptz NOT NULL,
    purged_at      timestamptz
);

CREATE INDEX IF NOT EXISTS package_tombstones_terminal_idx ON package_tombstones (terminal_at);

-- 审计：只记 IP / 时间 / 大小 / 次数，不记业务内容。
CREATE TABLE IF NOT EXISTS audit_events (
    id         bigserial   PRIMARY KEY,
    at         timestamptz NOT NULL,
    kind       text        NOT NULL,
    code       text,
    package_id text,
    bytes      bigint      NOT NULL DEFAULT 0,
    outcome    text        NOT NULL,
    ip         text
);

CREATE INDEX IF NOT EXISTS audit_events_at_idx ON audit_events (at);
