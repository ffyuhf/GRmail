-- GRmail 初始 schema（PostgreSQL 方言）
-- 依据：数据库_表结构_20260916_04-06-00_v1.0.0 第三章（与 sqlite/mysql 版语义对齐，同版本号）
-- 修改历史：
--   2026-09-16 04:38:00 | 新建 | U1 工程骨架（FR-014 三库适配）

-- +goose Up

CREATE TABLE users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    is_admin      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL,
    updated_at    TIMESTAMPTZ  NOT NULL
);

CREATE TABLE mailboxes (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    local_part    VARCHAR(64)  NOT NULL,
    domain        VARCHAR(255) NOT NULL,
    address       VARCHAR(320) NOT NULL UNIQUE,
    password_hash TEXT         NULL,
    status        VARCHAR(16)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'shadow', 'disabled')),
    created_at    TIMESTAMPTZ  NOT NULL,
    updated_at    TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_mailboxes_status ON mailboxes(status);

CREATE TABLE folders (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mailbox_id BIGINT       NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name       VARCHAR(255) NOT NULL,
    kind       VARCHAR(16)  NOT NULL CHECK (kind IN ('inbox', 'sent', 'drafts', 'junk', 'trash', 'custom')),
    created_at TIMESTAMPTZ  NOT NULL,
    UNIQUE (mailbox_id, name)
);

CREATE TABLE messages (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id          VARCHAR(998),
    blob_key            CHAR(64)    NOT NULL,
    raw_size            BIGINT      NOT NULL,
    subject             TEXT,
    from_addr           TEXT,
    to_addrs            TEXT,
    cc_addrs            TEXT,
    sent_at             TIMESTAMPTZ,
    spf_result          VARCHAR(32),
    dkim_result         VARCHAR(32),
    dmarc_result        VARCHAR(32),
    arc_result          VARCHAR(32),
    auth_results_header TEXT,
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_messages_blob_key ON messages(blob_key);
CREATE INDEX idx_messages_sent_at ON messages(sent_at DESC);
CREATE INDEX idx_messages_message_id ON messages(message_id);

CREATE TABLE mailbox_messages (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mailbox_id BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_id BIGINT      NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    folder_id  BIGINT      NOT NULL REFERENCES folders(id),
    uid        BIGINT      NOT NULL,
    is_read    BOOLEAN     NOT NULL DEFAULT FALSE,
    is_flagged BOOLEAN     NOT NULL DEFAULT FALSE,
    status     VARCHAR(16) NOT NULL DEFAULT 'normal' CHECK (status IN ('normal', 'deleted')),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (mailbox_id, uid)
);
CREATE INDEX idx_mm_list ON mailbox_messages(mailbox_id, folder_id, uid DESC);

CREATE TABLE sessions (
    id                  CHAR(64)    NOT NULL PRIMARY KEY,
    subject_type        VARCHAR(16) NOT NULL CHECK (subject_type IN ('admin', 'mailbox')),
    subject_id          BIGINT      NOT NULL,
    ip                  VARCHAR(45),
    user_agent          VARCHAR(512),
    created_at          TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_sessions_subject ON sessions(subject_type, subject_id);
CREATE INDEX idx_sessions_expires ON sessions(absolute_expires_at);

CREATE TABLE delivery_queue (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id      BIGINT       NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    envelope_from   VARCHAR(320) NOT NULL,
    rcpt_to         VARCHAR(320) NOT NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'in_flight', 'deferred', 'sent', 'failed')),
    attempts        INTEGER      NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ  NOT NULL,
    last_smtp_code  INTEGER,
    last_error      TEXT,
    created_at      TIMESTAMPTZ  NOT NULL,
    updated_at      TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_queue_due ON delivery_queue(status, next_attempt_at);

-- +goose Down

DROP TABLE IF EXISTS delivery_queue;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS mailbox_messages;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS mailboxes;
DROP TABLE IF EXISTS users;
