-- GRmail 传输安全合规批迁移：delivery_queue TLS 策略豁免列（SQLite 方言）
-- 依据：传输安全合规批_计划_20261007_15-10-00_v1.0.0 1.2#F1（G2 批准 2026-10-07
-- 15:13:06 含迁移 00013 三库授权+四项倾向单案候选 A；评审报告 7.2 批 5 A-9；
-- rfc8460 §5.3.1 L1050-1051「when sending failure reports via SMTP, Sending MTAs
-- MUST NOT honor MTA-STS or DANE TLSA failures」）
-- SRS v1.1.0 FR-010（S5-REV-20261001-001）报告供给侧完整性；
-- 修改历史：
--   2026-10-07 15:20:00 | 新建 | 传输安全合规批（G2 批准 2026-10-07 15:13:06）

-- +goose Up

-- A-9/F1：TLS-RPT 报告行豁免标记（1=投递链跳过 MTA-STS/DANE 策略判定——报告通道
-- 不因自身安全策略拒投；TLS 本身仍机会升级；0=普通邮件既有判定保持）
ALTER TABLE delivery_queue ADD COLUMN skip_tls_policy INTEGER NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE delivery_queue DROP COLUMN skip_tls_policy;
