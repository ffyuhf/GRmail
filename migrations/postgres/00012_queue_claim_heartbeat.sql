-- GRmail 队列防丢信收口批迁移：delivery_queue 认领/心跳/DSN 回执三列（PostgreSQL 方言）
-- 依据：队列防丢信收口批_计划_20261007_00-40-00_v1.0.0 1.2#F4/F5（G2 批准 2026-10-07
-- 08:41:07 含迁移 00012 三库授权+三项倾向单案候选 A；评审报告 7.2 批 3 A-14①④/B-R2/D1）
-- SRS v1.1.0 NFR-007 判定②；流程设计 3.2 不变量 1/3；
-- 修改历史：
--   2026-10-07 08:46:00 | 新建 | 队列防丢信收口批（G2 批准 2026-10-07 08:41:07）

-- +goose Up

-- A-14④+D1：认领令牌（单语句 RETURNING 形态下承载心跳归属与三库同构语义）
ALTER TABLE delivery_queue ADD COLUMN claim_token TEXT NULL;

-- A-14①+D1：投递期心跳（每 MX 尝试前续期；Stale 判据 COALESCE(heartbeat_at, updated_at)）
ALTER TABLE delivery_queue ADD COLUMN heartbeat_at TIMESTAMPTZ NULL;

-- B-R2+D1：DSN 回执标记（failed 必产 DSN 的重扫判据）
ALTER TABLE delivery_queue ADD COLUMN dsn_sent BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down

ALTER TABLE delivery_queue DROP COLUMN dsn_sent;
ALTER TABLE delivery_queue DROP COLUMN heartbeat_at;
ALTER TABLE delivery_queue DROP COLUMN claim_token;
