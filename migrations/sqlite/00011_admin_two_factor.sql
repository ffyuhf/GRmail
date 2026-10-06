-- GRmail 管理员主体增强批次迁移：users 2FA 字段组（SQLite 方言）
-- 依据：管理员主体增强与Webmail职能补全_计划_20261005_23-22-00 v1.1.0 1.3 G2
-- （G2 批准 2026-10-05 23:31:37；S3-W Q2-A 裁决 2026-10-05 23:20:14——admin 登录入口
-- 二步验证）；SRS v1.1.0 FR-018（S5-REV-20261001-001）admin 通道扩展——「仅 Webmail
-- HTTPS 登录入口」语义内承载（/login 即 Webmail 入口，协议入口零触及）；
-- 沿 00009 mailboxes 2FA 字段组先例（列明文/SHA-256 哈希集/重放步——S4-W 三裁决
-- A/A/A 2026-10-01 16:44:56 同源口径）；admin 无强制标记语义不设 two_factor_required 列
-- 修改历史：
--   2026-10-05 23:33:00 | 新建 | 管理员主体增强与Webmail职能补全批次（G2 批准 2026-10-05 23:31:37）

-- +goose Up

-- FR-018 判定①（admin 通道）：TOTP 密钥（Base32 明文——沿 00009 Q3-A 列明文裁决；
-- NULL=未发起绑定；非空=pending 或已绑定，绑定完成判定=本列与 recovery_codes 同时非空）
ALTER TABLE users ADD COLUMN totp_secret TEXT NULL;

-- FR-018 判定①③：恢复码集合（JSON 数组["sha256hex",...]——SHA-256 快哈希沿 00009
-- Q2-A；逐枚一次性消耗；绑定确认时一次性生成写入，停用时清空）
ALTER TABLE users ADD COLUMN recovery_codes TEXT NULL;

-- rfc6238 §5.2 L343-347 MUST 同窗重放拒绝：最近一次 TOTP 验证成功的时间步
-- （NULL=从未验证；后续验证仅接受严格大于本值的步——同窗/回退窗码拒绝）
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NULL;

-- +goose Down

ALTER TABLE users DROP COLUMN totp_last_step;
ALTER TABLE users DROP COLUMN recovery_codes;
ALTER TABLE users DROP COLUMN totp_secret;
