-- GRmail 初始 schema（MySQL 方言）
-- 依据：数据库_表结构_20260916_04-06-00_v1.0.0 第三章（与 sqlite 版语义对齐，同版本号）
-- 修改历史：
--   2026-09-16 04:38:00 | 新建 | U1 工程骨架（FR-014 三库适配）

-- +goose Up

CREATE TABLE users (
    id            BIGINT       AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    is_admin      TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    TIMESTAMP(6) NOT NULL,
    updated_at    TIMESTAMP(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE mailboxes (
    id            BIGINT       AUTO_INCREMENT PRIMARY KEY,
    local_part    VARCHAR(64)  NOT NULL,
    domain        VARCHAR(255) NOT NULL,
    address       VARCHAR(320) NOT NULL UNIQUE,
    password_hash TEXT         NULL,
    status        VARCHAR(16)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'shadow', 'disabled')),
    created_at    TIMESTAMP(6) NOT NULL,
    updated_at    TIMESTAMP(6) NOT NULL,
    INDEX idx_mailboxes_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE folders (
    id         BIGINT       AUTO_INCREMENT PRIMARY KEY,
    mailbox_id BIGINT       NOT NULL,
    name       VARCHAR(255) NOT NULL,
    kind       VARCHAR(16)  NOT NULL CHECK (kind IN ('inbox', 'sent', 'drafts', 'junk', 'trash', 'custom')),
    created_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY uq_folders_mailbox_name (mailbox_id, name),
    CONSTRAINT fk_folders_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE messages (
    id                  BIGINT       AUTO_INCREMENT PRIMARY KEY,
    message_id          VARCHAR(998),
    blob_key            CHAR(64)     NOT NULL,
    raw_size            BIGINT       NOT NULL,
    subject             TEXT,
    from_addr           TEXT,
    to_addrs            TEXT,
    cc_addrs            TEXT,
    sent_at             TIMESTAMP(6) NULL,
    spf_result          VARCHAR(32),
    dkim_result         VARCHAR(32),
    dmarc_result        VARCHAR(32),
    arc_result          VARCHAR(32),
    auth_results_header TEXT,
    created_at          TIMESTAMP(6) NOT NULL,
    INDEX idx_messages_blob_key (blob_key),
    INDEX idx_messages_sent_at (sent_at DESC),
    INDEX idx_messages_message_id (message_id(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE mailbox_messages (
    id         BIGINT       AUTO_INCREMENT PRIMARY KEY,
    mailbox_id BIGINT       NOT NULL,
    message_id BIGINT       NOT NULL,
    folder_id  BIGINT       NOT NULL,
    uid        BIGINT       NOT NULL,
    is_read    TINYINT(1)   NOT NULL DEFAULT 0,
    is_flagged TINYINT(1)   NOT NULL DEFAULT 0,
    status     VARCHAR(16)  NOT NULL DEFAULT 'normal' CHECK (status IN ('normal', 'deleted')),
    created_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY uq_mm_mailbox_uid (mailbox_id, uid),
    INDEX idx_mm_list (mailbox_id, folder_id, uid DESC),
    CONSTRAINT fk_mm_mailbox FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE,
    CONSTRAINT fk_mm_message FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    CONSTRAINT fk_mm_folder  FOREIGN KEY (folder_id)  REFERENCES folders(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sessions (
    id                  CHAR(64)     NOT NULL PRIMARY KEY,
    subject_type        VARCHAR(16)  NOT NULL CHECK (subject_type IN ('admin', 'mailbox')),
    subject_id          BIGINT       NOT NULL,
    ip                  VARCHAR(45),
    user_agent          VARCHAR(512),
    created_at          TIMESTAMP(6) NOT NULL,
    last_seen_at        TIMESTAMP(6) NOT NULL,
    absolute_expires_at TIMESTAMP(6) NOT NULL,
    INDEX idx_sessions_subject (subject_type, subject_id),
    INDEX idx_sessions_expires (absolute_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE delivery_queue (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    message_id      BIGINT       NOT NULL,
    envelope_from   VARCHAR(320) NOT NULL,
    rcpt_to         VARCHAR(320) NOT NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'in_flight', 'deferred', 'sent', 'failed')),
    attempts        INT          NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP(6) NOT NULL,
    last_smtp_code  INT,
    last_error      TEXT,
    created_at      TIMESTAMP(6) NOT NULL,
    updated_at      TIMESTAMP(6) NOT NULL,
    INDEX idx_queue_due (status, next_attempt_at),
    CONSTRAINT fk_queue_message FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- +goose Down

DROP TABLE IF EXISTS delivery_queue;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS mailbox_messages;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS mailboxes;
DROP TABLE IF EXISTS users;
