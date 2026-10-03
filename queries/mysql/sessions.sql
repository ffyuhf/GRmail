-- name: CreateSession :execresult
INSERT INTO sessions (id, subject_type, subject_id, ip, user_agent, csrf_token, created_at, last_seen_at, absolute_expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSessionByIDHash :one
SELECT id, subject_type, subject_id, ip, user_agent, csrf_token, created_at, last_seen_at, absolute_expires_at
FROM sessions
WHERE id = ?;

-- name: TouchSession :exec
UPDATE sessions
SET last_seen_at = ?, ip = ?, user_agent = ?
WHERE id = ?;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = ?;

-- name: PurgeExpiredSessions :execrows
DELETE FROM sessions
WHERE absolute_expires_at < ?;
