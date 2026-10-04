-- GRmail 初始 schema（SQLite 方言）
-- 依据：数据库_表结构_20260916_04-06-00_v1.0.0 第三章（七表）
-- 修改历史：
--   2026-09-16 04:37:00 | 新建 | U1 工程骨架

-- +goose Up

-- 管理员账户（单管理员模型 REQ-001；argon2id PHC 串 Q12）
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 1 CHECK (is_admin IN (0, 1)),
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

-- 邮箱账号（FR-001/003/004；影子状态机 shadow→active，REQ-020）
CREATE TABLE mailboxes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    local_part    TEXT    NOT NULL,
    domain        TEXT    NOT NULL,
    address       TEXT    NOT NULL UNIQUE,      -- 小写规范化写入（三库统一口径）
    password_hash TEXT    NULL,                  -- shadow 状态为 NULL（无凭据不可登录）
    status        TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'shadow', 'disabled')),
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);
CREATE INDEX idx_mailboxes_status ON mailboxes(status);

-- 单层文件夹（FR-012/REQ-021：无 parent_id，系统文件夹不可删）
CREATE TABLE folders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('inbox', 'sent', 'drafts', 'junk', 'trash', 'custom')),
    created_at TEXT    NOT NULL,
    UNIQUE (mailbox_id, name)
);

-- 邮件元数据（Q13 CAS：无 raw 列，blob_key 引用外置字节）
CREATE TABLE messages (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id           TEXT,                 -- RFC 5322 Message-ID 头
    blob_key             TEXT    NOT NULL,     -- SHA-256 hex（原始字节外置寻址）
    raw_size             INTEGER NOT NULL,     -- 字节数
    subject              TEXT,
    from_addr            TEXT,
    to_addrs             TEXT,                 -- JSON 数组缓存（列表渲染免解析）
    cc_addrs             TEXT,
    sent_at              TEXT,                 -- Date 头时间（RFC3339 UTC）
    spf_result           TEXT,
    dkim_result          TEXT,
    dmarc_result         TEXT,
    arc_result           TEXT,
    auth_results_header  TEXT,                 -- rfc8601 原文
    created_at           TEXT    NOT NULL
);
CREATE INDEX idx_messages_blob_key ON messages(blob_key);
CREATE INDEX idx_messages_sent_at ON messages(sent_at DESC);
CREATE INDEX idx_messages_message_id ON messages(message_id);

-- 邮箱-邮件关联（FR-001 按地址隔离载体；IMAP UID 语义 rfc9051）
CREATE TABLE mailbox_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    folder_id  INTEGER NOT NULL REFERENCES folders(id),
    uid        INTEGER NOT NULL,               -- mailbox 内单调递增
    is_read    INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
    is_flagged INTEGER NOT NULL DEFAULT 0 CHECK (is_flagged IN (0, 1)),
    status     TEXT    NOT NULL DEFAULT 'normal' CHECK (status IN ('normal', 'deleted')),
    created_at TEXT    NOT NULL,
    UNIQUE (mailbox_id, uid)
);
-- 列表分页主查询路径（NFR-001：P95 ≤ 2s 锚点索引）
CREATE INDEX idx_mm_list ON mailbox_messages(mailbox_id, folder_id, uid DESC);

-- 自研会话（Q7 + OWASP：库存 session ID 的 SHA-256 哈希，cookie 载原文）
CREATE TABLE sessions (
    id                   TEXT    PRIMARY KEY,  -- hex(SHA-256(sessionID 原文))
    subject_type         TEXT    NOT NULL CHECK (subject_type IN ('admin', 'mailbox')),
    subject_id           INTEGER NOT NULL,
    ip                   TEXT,
    user_agent           TEXT,
    created_at           TEXT    NOT NULL,
    last_seen_at         TEXT    NOT NULL,     -- 空闲超时判定（服务端强制）
    absolute_expires_at  TEXT    NOT NULL      -- 绝对超时（OWASP 双超时）
);
CREATE INDEX idx_sessions_subject ON sessions(subject_type, subject_id);
CREATE INDEX idx_sessions_expires ON sessions(absolute_expires_at);

-- 出站投递队列（CON-004/NFR-007 防丢信状态机）
CREATE TABLE delivery_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    envelope_from   TEXT    NOT NULL,
    rcpt_to         TEXT    NOT NULL,          -- 单行单收件人
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'in_flight', 'deferred', 'sent', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT    NOT NULL,          -- 退避调度
    last_smtp_code  INTEGER,                   -- 4xx/5xx 分类依据
    last_error      TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
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
