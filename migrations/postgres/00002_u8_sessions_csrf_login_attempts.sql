-- GRmail U8 迁移：会话 CSRF 列 + 登录尝试限流表（PostgreSQL 方言，与 sqlite/00002 语义版本对齐）
-- 依据：U8Web会话与登录_计划_20260919_04-55-00_v1.0.0 1.3 节（数据模型 v1.1.0 授权明细）
-- 修改历史：
--   2026-09-19 05:00:00 | 新建 | U8 Web 会话与登录（goose 版本号三库对齐；接入验证归 U11）

-- +goose Up

ALTER TABLE sessions ADD COLUMN csrf_token TEXT;

CREATE TABLE login_attempts (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_key  VARCHAR(320) NOT NULL,
    ip           VARCHAR(45),
    success      BOOLEAN      NOT NULL,
    attempted_at TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_attempts_subject ON login_attempts(subject_key, attempted_at);
CREATE INDEX idx_attempts_ip ON login_attempts(ip, attempted_at);

-- +goose Down

DROP TABLE IF EXISTS login_attempts;
ALTER TABLE sessions DROP COLUMN csrf_token;
