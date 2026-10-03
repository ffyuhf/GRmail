-- GRmail U16 迁移：messages 正文缓存列（PostgreSQL 方言）
-- 依据：U16Webmail体验收尾_计划_20260924_11-49-00_v1.0.0 1.5③/1.5⑩（数据模型 v1.3.0 3.4——
-- Q3-A 裁决正文缓存列；U9 修改文档登记项②正文检索收口）
-- 裁决来源：A2 单元启动（2026-09-24 11:41:21）/ Q3-A 正文缓存列（2026-09-24 11:47:58）
-- SRS 条目：FR-013（3.8 正文检索子项）；TC-013；契约 v1.12.0 2.1 ListBodyCachePending/FillBodyCache
-- 修改历史：
--   2026-09-24 11:58:00 | 新建 | U16 Webmail 体验收尾

-- +goose Up

-- 正文纯文本截断缓存（≤65536B——bodyCacheMaxBytes 工程上限；NULL=未回填，
-- 存量行经启动回填任务补齐；Webmail 搜索第四 LIKE 维度）
ALTER TABLE messages ADD COLUMN body_cache TEXT;

-- +goose Down

ALTER TABLE messages DROP COLUMN body_cache;
