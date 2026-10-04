-- GRmail RFCSHOULD修正批次迁移：internal_date（F-I4/F-I5）+ret_full（F-L3）（PostgreSQL 方言）
-- 依据：RFCSHOULD修正_计划_20260930_18-25-00_v1.0.0 1.2#5/#6/#9（G2 批准 2026-09-30
-- 18:28:20；S4-W 三裁决方案 A：2026-09-30 18:53/18:54/18:55）；数据模型 v1.5.0；
-- rfc9051 §6.3.12/§6.4.7-§6.4.8；rfc3461 §5.2.10
-- SRS 条目：FR-005/FR-006；TC-005/TC-006；契约 v1.17.0
-- 修改历史：
--   2026-09-30 18:57:00 | 新建 | RFCSHOULD修正批次（G2 批准 2026-09-30 18:28:20）

-- +goose Up

-- F-I4/F-I5：IMAP internal date（TIMESTAMPTZ 原生）
ALTER TABLE mailbox_messages ADD COLUMN internal_date TIMESTAMPTZ NULL;

-- F-L3：RET=FULL 持久化（BOOLEAN 原生）
ALTER TABLE delivery_queue ADD COLUMN ret_full BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down

ALTER TABLE mailbox_messages DROP COLUMN internal_date;
ALTER TABLE delivery_queue DROP COLUMN ret_full;
