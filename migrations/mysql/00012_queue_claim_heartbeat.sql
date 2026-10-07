-- GRmail 队列防丢信收口批迁移：delivery_queue 认领/心跳/DSN 回执三列（MySQL 方言）
-- 依据：队列防丢信收口批_计划_20261007_00-40-00_v1.0.0 1.2#F4/F5（G2 批准 2026-10-07
-- 08:41:07 含迁移 00012 三库授权+三项倾向单案候选 A；评审报告 7.2 批 3 A-14①④/B-R2/D1；
-- 复核报告 4.2 A-14④——MySQL ClaimDue 按 updated_at=now 回读的理论竞态由 claim_token 消除）
-- SRS v1.1.0 NFR-007 判定②；流程设计 3.2 不变量 1/3；
-- 修改历史：
--   2026-10-07 08:46:00 | 新建 | 队列防丢信收口批（G2 批准 2026-10-07 08:41:07）

-- +goose Up

-- A-14④+D1：认领令牌（回读按 claim_token 精确匹配——同值/时钟回拨竞态根治）
ALTER TABLE delivery_queue ADD COLUMN claim_token VARCHAR(64) NULL;

-- A-14①+D1：投递期心跳（每 MX 尝试前续期；Stale 判据 COALESCE(heartbeat_at, updated_at)）
ALTER TABLE delivery_queue ADD COLUMN heartbeat_at TIMESTAMP(6) NULL;

-- B-R2+D1：DSN 回执标记（failed 必产 DSN 的重扫判据）
ALTER TABLE delivery_queue ADD COLUMN dsn_sent TINYINT(1) NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE delivery_queue DROP COLUMN dsn_sent;
ALTER TABLE delivery_queue DROP COLUMN heartbeat_at;
ALTER TABLE delivery_queue DROP COLUMN claim_token;
