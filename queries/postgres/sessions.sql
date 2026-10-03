-- name: CreateSession :execresult
INSERT INTO sessions (id, subject_type, subject_id, ip, user_agent, csrf_token, created_at, last_seen_at, absolute_expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetSessionByIDHash :one
SELECT id, subject_type, subject_id, ip, user_agent, csrf_token, created_at, last_seen_at, absolute_expires_at
FROM sessions
WHERE id = $1;

-- name: TouchSession :exec
UPDATE sessions
SET last_seen_at = $1, ip = $2, user_agent = $3
WHERE id = $4;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;

-- name: PurgeExpiredSessions :execrows
DELETE FROM sessions
WHERE absolute_expires_at < $1;
