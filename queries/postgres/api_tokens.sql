-- name: CreateApiToken :exec
INSERT INTO api_tokens (user_id, token_hash, expires_at, client_ip, created_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, NULL);

-- name: FindValidApiTokenByHash :one
SELECT id, user_id, token_hash, expires_at, client_ip, created_at, last_used_at
FROM api_tokens
WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > $2);

-- name: ListApiTokensByUser :many
SELECT id, user_id, token_hash, expires_at, client_ip, created_at, last_used_at
FROM api_tokens
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: DeleteApiToken :exec
DELETE FROM api_tokens
WHERE id = $1 AND user_id = $2;

-- name: PurgeExpiredApiTokens :execresult
DELETE FROM api_tokens
WHERE expires_at IS NOT NULL AND expires_at <= $1;

-- name: TouchApiTokenLastUsed :exec
UPDATE api_tokens
SET last_used_at = $1
WHERE id = $2;
