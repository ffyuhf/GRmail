-- name: RecordLoginAttempt :execresult
INSERT INTO login_attempts (subject_key, ip, success, attempted_at)
VALUES (?, ?, ?, ?);

-- name: CountRecentFailedAttempts :one
SELECT COUNT(*)
FROM login_attempts
WHERE subject_key = ? AND success = 0 AND attempted_at > ?;

-- name: ClearLoginAttempts :exec
DELETE FROM login_attempts
WHERE subject_key = ?;

-- name: PurgeOldLoginAttempts :execrows
DELETE FROM login_attempts
WHERE attempted_at < ?;
