-- name: CreateMailbox :execresult
INSERT INTO mailboxes (local_part, domain, address, password_hash, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetMailboxByAddress :one
SELECT id, local_part, domain, address, password_hash, status, created_at, updated_at
FROM mailboxes
WHERE address = ?;

-- name: ListMailboxesByStatus :many
SELECT id, local_part, domain, address, password_hash, status, created_at, updated_at
FROM mailboxes
WHERE status = ?
ORDER BY id;

-- name: SetMailboxCredentials :execresult
UPDATE mailboxes
SET password_hash = ?, status = 'active', updated_at = ?
WHERE id = ? AND status IN ('active', 'shadow');

-- name: SetMailboxStatus :exec
UPDATE mailboxes
SET status = ?, updated_at = ?
WHERE id = ?;

-- name: GetTwoFactorByID :one
SELECT totp_secret, recovery_codes, two_factor_required, totp_last_step
FROM mailboxes
WHERE id = ?;

-- name: SetTwoFactorSecret :exec
UPDATE mailboxes
SET totp_secret = ?, totp_last_step = NULL, updated_at = ?
WHERE id = ?;

-- name: UpdateRecoveryCodes :exec
UPDATE mailboxes
SET recovery_codes = ?, updated_at = ?
WHERE id = ?;

-- name: MarkTOTPStep :execresult
UPDATE mailboxes
SET totp_last_step = ?, updated_at = ?
WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?);

-- name: ConsumeRecoveryCodeCAS :execresult
UPDATE mailboxes
SET recovery_codes = ?, updated_at = ?
WHERE id = ? AND recovery_codes = ?;

-- name: ClearTwoFactor :exec
UPDATE mailboxes
SET totp_secret = NULL, recovery_codes = NULL, totp_last_step = NULL, updated_at = ?
WHERE id = ?;

-- name: SetTwoFactorRequired :exec
UPDATE mailboxes
SET two_factor_required = ?, updated_at = ?
WHERE id = ?;

-- 配置并发批 F5（B-C2 UID 分配可串行化）：StoreAppend/CopyAtomic 事务内邮箱行锁
-- ——并发同邮箱 UID 分配（MAX+1 非锁定读撞 UNIQUE）经行锁串行化；SQLite 整库
-- 单写者保持原查询（不引入本变体）。
-- name: LockMailboxForUID :one
SELECT id FROM mailboxes WHERE id = ? FOR UPDATE;

-- name: FindMailboxByID :one
SELECT id, local_part, domain, address, password_hash, status, created_at, updated_at
FROM mailboxes
WHERE id = ?;
