-- GRmail D8登记项处置批次迁移：mailbox_keywords 表（IMAP keyword 持久存储，SQLite 方言）
-- 依据：D8登记项处置_计划_20260930_23-45-00_v1.0.0 1.2#1（G2 批准 2026-09-30 23:40:58）；
-- rfc9051 §2.3.2 L565-569（keyword 服务器实现定义、不以 "\" 开头、MAY 允许客户端
-- 定义新 keyword）；§6.4.4 L3908/L3980（KEYWORD/UNKEYWORD 搜索键）；§6.4.6 L4570-4592
-- （STORE FLAGS 三态承载 keyword）；L573-574（$ 类 keyword 于 SEARCH/APPEND/COPY/MOVE
-- SHOULD 支持）；L5186-5192（PERMANENTFLAGS \* 通配下新 keyword 无需新应答）
-- SRS 条目：FR-006（3.3.1）；TC-006；契约 v1.19.0 Detail.Keywords/AppendMeta.Keywords/
-- MessageRepo.SetKeywords/SearchFilter.Keywords；表结构 v1.6.0 3.12
-- 修改历史：
--   2026-09-30 23:47:00 | 新建 | D8登记项处置批次（G2 批准 2026-09-30 23:40:58）

-- +goose Up

-- IMAP keyword 持久存储（每消息多值命名标志集——多值集合独立表形态：三库同构
-- +EXISTS 子查询承载 SEARCH KEYWORD；行删除由硬删除/MOVE 删源路径显式先行清理，
-- 不依赖 FK 执行开关）
CREATE TABLE mailbox_keywords (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_message_id   INTEGER NOT NULL REFERENCES mailbox_messages(id) ON DELETE CASCADE,
    keyword              TEXT    NOT NULL,
    created_at           TEXT    NOT NULL,
    UNIQUE (mailbox_message_id, keyword)
);
CREATE INDEX idx_mk_keyword ON mailbox_keywords (keyword);

-- +goose Down

DROP TABLE mailbox_keywords;
