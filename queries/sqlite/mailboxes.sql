-- name: CreateMailbox :execresult
INSERT INTO mailboxes (local_part, domain, address, password_hash, scram_stored_key, scram_server_key, scram_salt, scram_iterations, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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
SET password_hash = ?, scram_stored_key = ?, scram_server_key = ?, scram_salt = ?, scram_iterations = ?, status = 'active', updated_at = ?
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

-- name: FindMailboxByID :one
SELECT id, local_part, domain, address, password_hash, status, created_at, updated_at
FROM mailboxes
WHERE id = ?;

-- name: GetSCRAMCredentialsByAddress :one
SELECT scram_stored_key, scram_server_key, scram_salt, scram_iterations
FROM mailboxes
WHERE address = ?;
