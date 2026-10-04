-- name: EnsureAdmin :execresult
INSERT IGNORE INTO users (username, password_hash, is_admin, created_at, updated_at)
VALUES (?, ?, 1, ?, ?);

-- name: GetUserByName :one
SELECT id, username, password_hash, is_admin, created_at, updated_at
FROM users
WHERE username = ?;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = ?, updated_at = ?
WHERE id = ?;
