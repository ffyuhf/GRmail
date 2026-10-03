-- GRmail U12 迁移：Sieve 脚本表（SQLite 方言）
-- 依据：U12Sieve过滤与ManageSieve_计划_20260921_00-34-00_v1.0.0 1.5⑧（数据模型 v1.1.0
-- 第二章 ER 实体 sieve_scripts 结构零演进——迁移 00003 为落盘载体；前置核验：三库 00001
-- 均未建此表，「3.9 预留」为 ER 图设计预留）
-- 裁决来源：Q1 启动（2026-09-21 00:25:58）/ Q1-R1 全自研（2026-09-21 00:30:59）
-- SRS 条目：FR-011（3.6）；TC-011；契约 v1.8.0 2.1 SieveScriptRepo
-- 修改历史：
--   2026-09-21 00:40:00 | 新建 | U12 Sieve 过滤与 ManageSieve

-- +goose Up

-- Sieve 脚本（rfc5804 多脚本管理+SETACTIVE 互斥单激活——互斥由应用层事务保证：
-- SieveScriptRepo.SetActive 事务内先清后置；三库一致不依赖 partial index）
CREATE TABLE sieve_scripts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id  INTEGER NOT NULL,               -- 归属邮箱（FR-011 邮箱级脚本；仅 active 邮箱可登录编辑）
    name        TEXT    NOT NULL,               -- 脚本名（rfc5804 脚本标识）
    content     TEXT    NOT NULL,               -- 脚本源（rfc5228 文本；PUTSCRIPT/保存时编译期校验）
    is_active   INTEGER NOT NULL CHECK (is_active IN (0, 1)) DEFAULT 0
);
CREATE UNIQUE INDEX idx_sieve_scripts_mailbox_name ON sieve_scripts(mailbox_id, name);
CREATE INDEX idx_sieve_scripts_active ON sieve_scripts(mailbox_id, is_active);

-- +goose Down

DROP TABLE IF EXISTS sieve_scripts;
