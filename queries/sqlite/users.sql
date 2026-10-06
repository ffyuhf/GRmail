-- name: EnsureAdmin :execresult
INSERT OR IGNORE INTO users (username, password_hash, is_admin, created_at, updated_at)
VALUES (?, ?, 1, ?, ?);

-- name: GetUserByName :one
SELECT id, username, password_hash, is_admin, created_at, updated_at
FROM users
WHERE username = ?;

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

-- name: MarkAdminTOTPStep :exec
UPDATE users
SET totp_last_step = ?, updated_at = ?
WHERE id = ?;

-- name: ClearAdmin2FA :exec
UPDATE users
SET totp_secret = NULL, recovery_codes = NULL, totp_last_step = NULL, updated_at = ?
WHERE id = ?;
