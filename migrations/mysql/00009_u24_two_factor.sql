-- GRmail U24双因素认证批次迁移：mailboxes 2FA 字段组（MySQL 方言）
-- 依据：U24双因素认证_计划_20261001_16-45-00_v1.0.0 1.2#2（G2 批准 2026-10-01
-- 16:41:08；S4-W 三裁决 A/A/A：pending 凭据+SHA-256+列明文，2026-10-01 16:44:56）；
-- SRS v1.1.0 FR-018（S5-REV-20261001-001）；rfc6238 §4/§5.2 L343-347
-- 修改历史：
--   2026-10-01 16:46:00 | 新建 | U24双因素认证批次（G2 批准 2026-10-01 16:41:08）

-- +goose Up

-- 语义同 SQLite 版：totp_secret Base32 明文/recovery_codes JSON 哈希数组/
-- two_factor_required 强制标记/totp_last_step 同窗重放拒绝承载（BIGINT——
-- T 值 64 位承载，rfc6238 §4.2 L212-213「MUST support T larger than 32-bit」）
ALTER TABLE mailboxes
    ADD COLUMN totp_secret TEXT NULL,
    ADD COLUMN recovery_codes TEXT NULL,
    ADD COLUMN two_factor_required TINYINT(1) NOT NULL DEFAULT 0,
    ADD COLUMN totp_last_step BIGINT NULL;

-- +goose Down

ALTER TABLE mailboxes
    DROP COLUMN totp_last_step,
    DROP COLUMN two_factor_required,
    DROP COLUMN recovery_codes,
    DROP COLUMN totp_secret;
