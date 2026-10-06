-- name: EnsureAdmin :execresult
INSERT INTO users (username, password_hash, is_admin, created_at, updated_at)
VALUES ($1, $2, true, $3, $4)
ON CONFLICT (username) DO NOTHING;

-- name: GetUserByName :one
SELECT id, username, password_hash, is_admin, created_at, updated_at
FROM users
WHERE username = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $1, updated_at = $2
WHERE id = $3;

-- name: GetAdmin2FAByID :one
SELECT totp_secret, recovery_codes, totp_last_step
FROM users
WHERE id = $1;

-- name: SetAdmin2FASecret :exec
UPDATE users
SET totp_secret = $1, totp_last_step = NULL, updated_at = $2
WHERE id = $3;

-- name: UpdateAdminRecoveryCodes :exec
UPDATE users
SET recovery_codes = $1, updated_at = $2
WHERE id = $3;

-- name: MarkAdminTOTPStep :exec
UPDATE users
SET totp_last_step = $1, updated_at = $2
WHERE id = $3;

-- name: ClearAdmin2FA :exec
UPDATE users
SET totp_secret = NULL, recovery_codes = NULL, totp_last_step = NULL, updated_at = $1
WHERE id = $2;
