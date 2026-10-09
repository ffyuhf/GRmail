-- GRmail SCRAM认证批迁移：mailboxes SCRAM-SHA-1 服务端凭据四列（SQLite 方言）
-- 依据：SCRAM认证批_计划_20261009_22-57-00_v1.0.0 1.2#F2（G2 批准 2026-10-09
-- 23:37:36 含迁移 00014 三库授权+四组候选全 A〔3.1-A 四列单语句原子〕；
-- rfc5804 §1.6 L692-694「MUST implement the SCRAM-SHA-1」+rfc5802 §3 L413-422）
-- SRS v1.1.1 FR-011（S5-REV-20260908-001）ManageSieve 规范合规承载；
-- 存量策略 3.2-A：既有邮箱四列 NULL=未配备（SCRAM 拒绝回退 PLAIN），改密后即具备。
-- 修改历史：
--   2026-10-09 23:46:00 | 新建 | SCRAM认证批（G2 批准 2026-10-09 23:37:36）

-- +goose Up

-- SCRAM-SHA-1 服务端四元组（rfc5802 §3：StoredKey=H(ClientKey)/ServerKey=
-- HMAC(SaltedPassword,"Server Key")/salt/iterations——服务端验证必需，argon2id
-- PHC 单向不可逆无法转制，须设密时同步派生；三键列 20B=SHA-1 输出长，盐 16B）
ALTER TABLE mailboxes ADD COLUMN scram_stored_key BLOB NULL;
ALTER TABLE mailboxes ADD COLUMN scram_server_key BLOB NULL;
ALTER TABLE mailboxes ADD COLUMN scram_salt BLOB NULL;
ALTER TABLE mailboxes ADD COLUMN scram_iterations INTEGER NULL;

-- +goose Down

ALTER TABLE mailboxes DROP COLUMN scram_stored_key;
ALTER TABLE mailboxes DROP COLUMN scram_server_key;
ALTER TABLE mailboxes DROP COLUMN scram_salt;
ALTER TABLE mailboxes DROP COLUMN scram_iterations;
