-- GRmail 队列防丢信收口批迁移：delivery_queue 认领/心跳/DSN 回执三列（SQLite 方言）
-- 依据：队列防丢信收口批_计划_20261007_00-40-00_v1.0.0 1.2#F4/F5（G2 批准 2026-10-07
-- 08:41:07 含迁移 00012 三库授权+三项倾向单案候选 A；评审报告 7.2 批 3 A-14①④/B-R2/D1；
-- 复核报告 4.2 A-14 修正口径——sender 一次性 60s Deadline+MX 遍历长尾可累计超 10min 回收窗）
-- SRS v1.1.0 NFR-007（S5-REV-20261001-001）判定②；流程设计 3.2 不变量 1/3；
-- 修改历史：
--   2026-10-07 08:46:00 | 新建 | 队列防丢信收口批（G2 批准 2026-10-07 08:41:07）

-- +goose Up

-- A-14④+D1：认领令牌（CSPRNG hex——MySQL 双语句回读按 token 精确匹配，消除按
-- updated_at 同值回读竞态；NULL=未被认领/已回写）
ALTER TABLE delivery_queue ADD COLUMN claim_token TEXT NULL;

-- A-14①+D1：投递期心跳（每 MX 尝试前续期；ReclaimStale 判据自 updated_at 改为
-- COALESCE(heartbeat_at, updated_at)——在途投递持续续期不再被误回收重投；
-- NULL=存量行/非在途）
ALTER TABLE delivery_queue ADD COLUMN heartbeat_at TEXT NULL;

-- B-R2+D1：DSN 回执标记（failed 行 0=DSN 待发，1=已生成；emitDSN 成功后置位；
-- 启动+周期重扫 failed AND dsn_sent=0 补发——流程设计 3.2 不变量 3「failed 必产生
-- DSN」的强保证承载）
ALTER TABLE delivery_queue ADD COLUMN dsn_sent INTEGER NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE delivery_queue DROP COLUMN dsn_sent;
ALTER TABLE delivery_queue DROP COLUMN heartbeat_at;
ALTER TABLE delivery_queue DROP COLUMN claim_token;
