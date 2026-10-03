-- GRmail U14 迁移：API Token 表（PostgreSQL 方言，与 sqlite/00004 语义版本对齐）
-- 依据：U14APIToken管理_计划_20260924_02-26-00_v1.0.0 1.5①（数据模型 v1.2.0 3.11——Q2-B）
-- 裁决来源：Q1 启动（2026-09-24 02:13:12）/ Q1-A/Q2-B/Q3-B（2026-09-24 02:24:36）
-- SRS 条目：FR-013（3.8 Token 管理子项）；TC-013；契约 v1.10.0 2.1 TokenRepo
-- 修改历史：
--   2026-09-24 02:36:00 | 新建 | U14 API Token 管理（goose 版本号三库对齐）

-- +goose Up

CREATE TABLE api_tokens (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       BIGINT       NOT NULL,
    token_hash    CHAR(64)     NOT NULL,
    expires_at    TIMESTAMPTZ,
    client_ip     VARCHAR(45),
    created_at    TIMESTAMPTZ  NOT NULL,
    last_used_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX idx_api_tokens_expires ON api_tokens(expires_at);

-- +goose Down

DROP TABLE IF EXISTS api_tokens;
