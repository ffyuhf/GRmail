-- GRmail U8 迁移：会话 CSRF 列 + 登录尝试限流表（SQLite 方言）
-- 依据：U8Web会话与登录_计划_20260919_04-55-00_v1.0.0 1.3 节（数据模型 v1.1.0 授权明细）
-- 裁决来源：Q5-B 会话绑定 CSRF（2026-09-19 04:48:48）/ Q4-B DB 持久化限流（同轮）
-- 修改历史：
--   2026-09-19 05:00:00 | 新建 | U8 Web 会话与登录

-- +goose Up

-- 会话绑定 CSRF token（Q5-B：登录成功生成、特权重建时刷新；空=未绑定）
ALTER TABLE sessions ADD COLUMN csrf_token TEXT;

-- 登录失败计数限流（Q4-B：DB 持久化，重启保持；逐次记录行，窗口内失败计数）
CREATE TABLE login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key  TEXT    NOT NULL,               -- 主体标识（管理员用户名或邮箱地址，小写规范化）
    ip           TEXT,                           -- 来源 IP（同 IP 维度告警辅助）
    success      INTEGER NOT NULL CHECK (success IN (0, 1)),
    attempted_at TEXT    NOT NULL                -- RFC3339 UTC（窗口滑动判定）
);
CREATE INDEX idx_attempts_subject ON login_attempts(subject_key, attempted_at);
CREATE INDEX idx_attempts_ip ON login_attempts(ip, attempted_at);

-- +goose Down

DROP TABLE IF EXISTS login_attempts;
ALTER TABLE sessions DROP COLUMN csrf_token;
