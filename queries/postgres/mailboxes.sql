-- name: CreateMailbox :one
INSERT INTO mailboxes (local_part, domain, address, password_hash, scram_stored_key, scram_server_key, scram_salt, scram_iterations, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id;

-- name: GetMailboxByAddress :one
SELECT id, local_part, domain, address, password_hash, status, created_at, updated_at
FROM mailboxes
WHERE address = $1;

-- name: ListMailboxesByStatus :many
SELECT id, local_part, domain, address, password_hash, status, created_at, updated_at
FROM mailboxes
WHERE status = $1
ORDER BY id;

-- name: SetMailboxCredentials :execresult
UPDATE mailboxes
SET password_hash = $1, scram_stored_key = $2, scram_server_key = $3, scram_salt = $4, scram_iterations = $5, status = 'active', updated_at = $6
WHERE id = $7 AND status IN ('active', 'shadow');

-- name: SetMailboxStatus :exec
UPDATE mailboxes
SET status = $1, updated_at = $2
WHERE id = $3;

-- name: GetTwoFactorByID :one
SELECT totp_secret, recovery_codes, two_factor_required, totp_last_step
FROM mailboxes
WHERE id = $1;

-- name: SetTwoFactorSecret :exec
UPDATE mailboxes
SET totp_secret = $1, totp_last_step = NULL, updated_at = $2
WHERE id = $3;

-- name: UpdateRecoveryCodes :exec
UPDATE mailboxes
SET recovery_codes = $1, updated_at = $2
WHERE id = $3;

-- name: MarkTOTPStep :execresult
UPDATE mailboxes
SET totp_last_step = $1, updated_at = $2
WHERE id = $3 AND (totp_last_step IS NULL OR totp_last_step < $4);

-- name: ConsumeRecoveryCodeCAS :execresult
UPDATE mailboxes
SET recovery_codes = $1, updated_at = $2
WHERE id = $3 AND recovery_codes = $4;

-- name: ClearTwoFactor :exec
UPDATE mailboxes
SET totp_secret = NULL, recovery_codes = NULL, totp_last_step = NULL, updated_at = $1
WHERE id = $2;

-- name: SetTwoFactorRequired :exec
UPDATE mailboxes
SET two_factor_required = $1, updated_at = $2
WHERE id = $3;

-- name: FindMailboxByID :one
SELECT id, local_part, domain, address, password_hash, status, created_at, updated_at
FROM mailboxes
WHERE id = $1;

-- name: GetSCRAMCredentialsByAddress :one
SELECT scram_stored_key, scram_server_key, scram_salt, scram_iterations
FROM mailboxes
WHERE address = $1;

-- 配置并发批 F5（B-C2 UID 分配可串行化）：StoreAppend/CopyAtomic 事务内邮箱行锁
-- ——并发同邮箱 UID 分配（MAX+1 非锁定读撞 UNIQUE）经行锁串行化；SQLite 整库
-- 单写者保持原查询（不引入本变体）。
-- name: LockMailboxForUID :one
SELECT id FROM mailboxes WHERE id = $1 FOR UPDATE;
