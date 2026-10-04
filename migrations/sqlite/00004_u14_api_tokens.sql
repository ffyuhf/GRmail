-- GRmail U14 迁移：API Token 表（SQLite 方言）
-- 依据：U14APIToken管理_计划_20260924_02-26-00_v1.0.0 1.5①（数据模型 v1.2.0 3.11——
-- Q2-B 裁决 last_used_at 加列版；ER ApiToken 四列预留+U14 增量）
-- 裁决来源：Q1 启动（2026-09-24 02:13:12）/ Q1-A Bearer 并列认证+Q2-B last_used_at+Q3-B 独立端点族（2026-09-24 02:24:36）
-- SRS 条目：FR-013（3.8 Token 管理子项）；TC-013；契约 v1.10.0 2.1 TokenRepo
-- 修改历史：
--   2026-09-24 02:36:00 | 新建 | U14 API Token 管理

-- +goose Up

-- API Token（FR-013——原文 32 字节 crypto/rand 64hex 仅生成时一次性可见；
-- token_hash=hex(SHA-256(原文)) 哈希点查主路径；expires_at NULL=永久；
-- client_ip NULL=不绑定；last_used_at NULL=从未使用——Bearer 命中时尽力刷新）
CREATE TABLE api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,              -- 持有主体（管理员——Bearer 合成会话 SubjectID 来源）
    token_hash    TEXT    NOT NULL,              -- hex(SHA-256(token 原文))——CHAR(64) 语义
    expires_at    TEXT,                          -- NULL=永久（RFC3339 UTC）
    client_ip     TEXT,                          -- NULL=不绑定（非空且请求 IP 不符→认证拒绝）
    created_at    TEXT    NOT NULL,
    last_used_at  TEXT                           -- NULL=从未使用（Q2-B——使用审计列）
);
CREATE UNIQUE INDEX idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX idx_api_tokens_expires ON api_tokens(expires_at);

-- +goose Down

DROP TABLE IF EXISTS api_tokens;
