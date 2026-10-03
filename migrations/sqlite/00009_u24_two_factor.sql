-- GRmail U24双因素认证批次迁移：mailboxes 2FA 字段组（SQLite 方言）
-- 依据：U24双因素认证_计划_20261001_16-45-00_v1.0.0 1.2#2（G2 批准 2026-10-01
-- 16:41:08；S4-W 三裁决 A/A/A：pending 凭据+SHA-256+列明文，2026-10-01 16:44:56）；
-- SRS v1.1.0 FR-018（S5-REV-20261001-001）；建模记录 v1.1.0 ERD Mailbox 2FA 字段组；
-- rfc6238 §4（TOTP=HOTP(K,T)，X=30s）/§5.2 L343-347（同窗重放拒绝 MUST——
-- totp_last_step 承载列：记录最近一次验证成功的时间步，拒绝不大于该步的后续码）
-- 修改历史：
--   2026-10-01 16:46:00 | 新建 | U24双因素认证批次（G2 批准 2026-10-01 16:41:08）

-- +goose Up

-- FR-018 判定①：TOTP 密钥（Base32 明文——S4-W Q3-A 列明文裁决；NULL=未发起绑定；
-- 非空=pending 或已绑定，绑定完成判定=本列与 recovery_codes 同时非空）
ALTER TABLE mailboxes ADD COLUMN totp_secret TEXT NULL;

-- FR-018 判定①③：恢复码集合（JSON 数组["sha256hex",...]——S4-W Q2-A SHA-256 快哈希；
-- 逐枚一次性消耗；绑定确认时一次性生成写入，停用时清空）
ALTER TABLE mailboxes ADD COLUMN recovery_codes TEXT NULL;

-- FR-018 判定④：管理员强制标记（REQ-20261001-004/Q3-B；0=自愿制缺省，1=强制绑定）
ALTER TABLE mailboxes ADD COLUMN two_factor_required INTEGER NOT NULL DEFAULT 0;

-- rfc6238 §5.2 MUST 同窗重放拒绝：最近一次 TOTP 验证成功的时间步（NULL=从未验证；
-- 后续验证仅接受严格大于本值的步——同窗/回退窗码拒绝）
ALTER TABLE mailboxes ADD COLUMN totp_last_step INTEGER NULL;

-- +goose Down

ALTER TABLE mailboxes DROP COLUMN totp_last_step;
ALTER TABLE mailboxes DROP COLUMN two_factor_required;
ALTER TABLE mailboxes DROP COLUMN recovery_codes;
ALTER TABLE mailboxes DROP COLUMN totp_secret;
