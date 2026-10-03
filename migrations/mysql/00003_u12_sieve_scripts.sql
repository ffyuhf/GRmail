-- GRmail U12 迁移：Sieve 脚本表（MySQL 方言，与 sqlite/00003 语义版本对齐）
-- 依据：U12Sieve过滤与ManageSieve_计划_20260921_00-34-00_v1.0.0 1.5⑧（数据模型 v1.1.0
-- 第二章 ER 实体 sieve_scripts 结构零演进——迁移 00003 为落盘载体）
-- 裁决来源：Q1 启动（2026-09-21 00:25:58）/ Q1-R1 全自研（2026-09-21 00:30:59）
-- SRS 条目：FR-011（3.6）；TC-011；契约 v1.8.0 2.1 SieveScriptRepo
-- 修改历史：
--   2026-09-21 00:40:00 | 新建 | U12 Sieve 过滤与 ManageSieve（goose 版本号三库对齐）

-- +goose Up

-- SETACTIVE 互斥单激活由应用层事务保证（SieveScriptRepo.SetActive 事务内先清后置）
CREATE TABLE sieve_scripts (
    id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
    mailbox_id  BIGINT       NOT NULL,
    name        VARCHAR(255) NOT NULL,
    content     TEXT         NOT NULL,
    is_active   TINYINT(1)   NOT NULL DEFAULT 0,
    UNIQUE KEY idx_sieve_scripts_mailbox_name (mailbox_id, name),
    INDEX idx_sieve_scripts_active (mailbox_id, is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- +goose Down

DROP TABLE IF EXISTS sieve_scripts;
