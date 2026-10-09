-- name: EnsureAdmin :execresult
INSERT IGNORE INTO users (username, password_hash, is_admin, created_at, updated_at)
VALUES (?, ?, 1, ?, ?);

-- name: GetUserByName :one
SELECT id, username, password_hash, is_admin, created_at, updated_at
FROM users
WHERE username = ?;

-- name: GetUserByID :one
SELECT id, username, password_hash, is_admin, created_at, updated_at
FROM users
WHERE id = ?;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = ?, updated_at = ?
WHERE id = ?;

-- name: GetAdmin2FAByID :one
SELECT totp_secret, recovery_codes, totp_last_step
FROM users
WHERE id = ?;

-- name: SetAdmin2FASecret :exec
UPDATE users
SET totp_secret = ?, totp_last_step = NULL, updated_at = ?
WHERE id = ?;

-- name: UpdateAdminRecoveryCodes :exec
UPDATE users
SET recovery_codes = ?, updated_at = ?
WHERE id = ?;

-- name: MarkAdminTOTPStep :execresult
UPDATE users
SET totp_last_step = ?, updated_at = ?
WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?);

-- name: ConsumeAdminRecoveryCodeCAS :execresult
UPDATE users
SET recovery_codes = ?, updated_at = ?
WHERE id = ? AND recovery_codes = ?;

-- name: ClearAdmin2FA :exec
UPDATE users
SET totp_secret = NULL, recovery_codes = NULL, totp_last_step = NULL, updated_at = ?
WHERE id = ?;
