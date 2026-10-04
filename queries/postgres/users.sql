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
