-- GRmail U25影子邮箱聚合可达批次迁移：folders.kind CHECK 值域扩展 + postmaster
-- 聚合文件夹存量补建（SQLite 方言）。
-- 依据：U25影子邮箱聚合可达_计划_20261002_19-35-00_v1.0.0 1.3#1/#2（G2 批准
-- 2026-10-02 19:41:00；S3-W Q1-B 管道层副本+Q2-B1 第六系统文件夹裁决）；SRS v1.1.0
-- FR-003（S5-REV-20261001-001）。
-- 实现偏离登记：计划书预判「INSERT 型零 DDL」，实施核实 folders.kind 存在 00001
-- CHECK 约束（六值枚举）——值域扩展为第七值是该裁决语义的必然技术前提（否则类别
-- 无法落库）；非范围变更，偏离详情归 CHANGE5 第三章。
-- SQLite 专序：CHECK 不可 ALTER——标准重建路径；连接 foreign_keys=ON（db.go DSN
-- _pragma）下 DROP 父表受 FK 拦截且触发隐式级联风险，故整迁移以 NO TRANSACTION
-- 运行并前置 PRAGMA foreign_keys=OFF（事务内该 PRAGMA 无效——SQLite 文档 §2）。
-- 修改历史：
--   2026-10-03 06:10:00 | 新建 | U25影子邮箱聚合可达批次（G2 批准 2026-10-02 19:41:00）

-- +goose Up
-- +goose NO TRANSACTION

PRAGMA foreign_keys = OFF;

-- ① CHECK 值域扩展（重建法）：七值枚举（增 unregistered；表结构与 00001 逐列一致）
DROP TABLE IF EXISTS folders_u25;
CREATE TABLE folders_u25 (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('inbox', 'sent', 'drafts', 'junk', 'trash', 'unregistered', 'custom')),
    created_at TEXT    NOT NULL,
    UNIQUE (mailbox_id, name)
);
INSERT INTO folders_u25 (id, mailbox_id, name, kind, created_at)
SELECT id, mailbox_id, name, kind, created_at FROM folders;
DROP TABLE folders;
ALTER TABLE folders_u25 RENAME TO folders;

PRAGMA foreign_keys = ON;

-- ② 存量 postmaster 邮箱补建聚合文件夹（local_part='postmaster'——覆盖主域与全部域；
-- NOT EXISTS 幂等——手工预建/重放场景零重复行）
INSERT INTO folders (mailbox_id, name, kind, created_at)
SELECT m.id, 'Unregistered', 'unregistered', strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
FROM mailboxes m
WHERE m.local_part = 'postmaster'
  AND NOT EXISTS (
      SELECT 1 FROM folders f
      WHERE f.mailbox_id = m.id AND f.kind = 'unregistered'
  );

-- +goose Down
-- +goose NO TRANSACTION

PRAGMA foreign_keys = OFF;

-- 对称回滚：聚合副本行→聚合文件夹行→孤儿 messages 主体行→CHECK 收回六值（重建法）
DELETE FROM mailbox_messages
WHERE folder_id IN (SELECT id FROM folders WHERE kind = 'unregistered');

DELETE FROM folders WHERE kind = 'unregistered';

DELETE FROM messages
WHERE NOT EXISTS (
    SELECT 1 FROM mailbox_messages mm WHERE mm.message_id = messages.id
);

DROP TABLE IF EXISTS folders_u25;
CREATE TABLE folders_u25 (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('inbox', 'sent', 'drafts', 'junk', 'trash', 'custom')),
    created_at TEXT    NOT NULL,
    UNIQUE (mailbox_id, name)
);
INSERT INTO folders_u25 (id, mailbox_id, name, kind, created_at)
SELECT id, mailbox_id, name, kind, created_at FROM folders;
DROP TABLE folders;
ALTER TABLE folders_u25 RENAME TO folders;

PRAGMA foreign_keys = ON;
