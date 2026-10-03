-- name: CreateApiToken :exec
INSERT INTO api_tokens (user_id, token_hash, expires_at, client_ip, created_at, last_used_at)
VALUES (?, ?, ?, ?, ?, NULL);

-- name: FindValidApiTokenByHash :one
SELECT id, user_id, token_hash, expires_at, client_ip, created_at, last_used_at
FROM api_tokens
WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?);

-- name: ListApiTokensByUser :many
SELECT id, user_id, token_hash, expires_at, client_ip, created_at, last_used_at
FROM api_tokens
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: DeleteApiToken :exec
DELETE FROM api_tokens
WHERE id = ? AND user_id = ?;

-- name: PurgeExpiredApiTokens :execresult
DELETE FROM api_tokens
WHERE expires_at IS NOT NULL AND expires_at <= ?;

-- name: TouchApiTokenLastUsed :exec
UPDATE api_tokens
SET last_used_at = ?
WHERE id = ?;
