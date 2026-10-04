-- GRmail RFC候选修正 RF-J 迁移：mailbox_messages 五系统标志列（MySQL 方言）
-- 依据：RFC候选修正_计划_20260929_17-10-00_v1.0.0 1.1 RF-J/F-I16（Q2-A 裁决 RFC 化——
-- 2026-09-29 17:05:10）；数据模型 v1.4.0 3.5；rfc9051 §2.3.2/§7.3.5 五系统标志
-- SRS 条目：FR-006（3.3.1）；TC-006；契约 v1.16.0 2.1 FlagPatch.IsAnswered/IsDraft
-- 修改历史：
--   2026-09-29 18:35:00 | 新建 | RFC候选修正批次 RF-J（G2 批准 2026-09-29 17:08:38）

-- +goose Up

-- IMAP \Answered/\Draft 系统标志持久化（F-I16——布尔按第五章适配表 TINYINT(1)）
ALTER TABLE mailbox_messages ADD COLUMN is_answered TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE mailbox_messages ADD COLUMN is_draft TINYINT(1) NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE mailbox_messages DROP COLUMN is_answered;
ALTER TABLE mailbox_messages DROP COLUMN is_draft;
