-- GRmail D8登记项处置批次迁移：mailbox_keywords 表（IMAP keyword 持久存储，PostgreSQL 方言）
-- 依据：D8登记项处置_计划_20260930_23-45-00_v1.0.0 1.2#1（G2 批准 2026-09-30 23:40:58）；
-- rfc9051 §2.3.2 L565-569（keyword 服务器实现定义）；§6.4.4/§6.4.6/L573-574/L5186-5192
-- （SEARCH/STORE/APPEND/COPY/MOVE/PERMANENTFLAGS 全承载——同 sqlite 版注记）
-- SRS 条目：FR-006（3.3.1）；TC-006；契约 v1.19.0；表结构 v1.6.0 3.12
-- 修改历史：
--   2026-09-30 23:47:00 | 新建 | D8登记项处置批次（G2 批准 2026-09-30 23:40:58）

-- +goose Up

CREATE TABLE mailbox_keywords (
    id                   BIGSERIAL     NOT NULL PRIMARY KEY,
    mailbox_message_id   BIGINT        NOT NULL REFERENCES mailbox_messages (id) ON DELETE CASCADE,
    keyword              VARCHAR(255)  NOT NULL,
    created_at           TIMESTAMPTZ   NOT NULL,
    UNIQUE (mailbox_message_id, keyword)
);
CREATE INDEX idx_mk_keyword ON mailbox_keywords (keyword);

-- +goose Down

DROP TABLE mailbox_keywords;
