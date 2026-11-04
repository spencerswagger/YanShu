-- 0006_abuse_reports.sql · 举报记录（API.md §11.5）
--
-- 只记录、不改变传输状态；下架由运维执行（与用户撤回同一条终结路径）。
-- 同一 (reporter_code, transfer_id) 只记一条 —— 幂等由唯一约束保证。
-- 不存被举报内容、不存 note 之外的任何正文；note 由举报人自填。

CREATE TABLE IF NOT EXISTS abuse_reports (
    report_id      text        PRIMARY KEY CHECK (report_id ~ '^r_[0-9a-f]{8}$'),
    reporter_code  text        NOT NULL CHECK (octet_length(reporter_code) = 4),
    transfer_id    text        NOT NULL CHECK (transfer_id ~ '^[0-9a-f]{32}$'),
    reason         text        NOT NULL CHECK (reason IN ('ABUSE', 'CSAM', 'MALWARE', 'OTHER')),
    note           text        NOT NULL DEFAULT '' CHECK (octet_length(note) <= 200),
    reporter_ip    text,
    created_at     timestamptz NOT NULL,
    UNIQUE (reporter_code, transfer_id)
);

CREATE INDEX IF NOT EXISTS abuse_reports_transfer_idx ON abuse_reports (transfer_id);
