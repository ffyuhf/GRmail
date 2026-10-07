-- name: CreateMailbox :one
INSERT INTO mailboxes (local_part, domain, address, password_hash, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
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
SET password_hash = $1, status = 'active', updated_at = $2
WHERE id = $3 AND status IN ('active', 'shadow');

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
