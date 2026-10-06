-- GRmail 管理员主体增强批次迁移：users 2FA 字段组（MySQL 方言）
-- 依据：管理员主体增强与Webmail职能补全_计划_20261005_23-22-00 v1.1.0 1.3 G2
-- （G2 批准 2026-10-05 23:31:37；S3-W Q2-A 裁决 2026-10-05 23:20:14）；SRS v1.1.0
-- FR-018 admin 通道扩展；沿 00009 mailboxes 先例（S4-W 三裁决同源口径）；
-- admin 无强制标记语义不设 two_factor_required 列
-- 修改历史：
--   2026-10-05 23:33:00 | 新建 | 管理员主体增强与Webmail职能补全批次（G2 批准 2026-10-05 23:31:37）

-- +goose Up

ALTER TABLE users ADD COLUMN totp_secret TEXT NULL;
ALTER TABLE users ADD COLUMN recovery_codes TEXT NULL;
ALTER TABLE users ADD COLUMN totp_last_step BIGINT NULL;

-- +goose Down

ALTER TABLE users DROP COLUMN totp_last_step;
ALTER TABLE users DROP COLUMN recovery_codes;
ALTER TABLE users DROP COLUMN totp_secret;
