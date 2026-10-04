-- name: RecordLoginAttempt :execresult
INSERT INTO login_attempts (subject_key, ip, success, attempted_at)
VALUES ($1, $2, $3, $4);

-- name: CountRecentFailedAttempts :one
SELECT COUNT(*)
FROM login_attempts
WHERE subject_key = $1 AND success = false AND attempted_at > $2;

-- name: ClearLoginAttempts :exec
DELETE FROM login_attempts
WHERE subject_key = $1;

-- name: PurgeOldLoginAttempts :execrows
DELETE FROM login_attempts
WHERE attempted_at < $1;
