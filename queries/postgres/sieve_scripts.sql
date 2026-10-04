-- name: ListSieveScripts :many
SELECT id, mailbox_id, name, content, is_active
FROM sieve_scripts
WHERE mailbox_id = $1
ORDER BY name;

-- name: GetSieveScript :one
SELECT id, mailbox_id, name, content, is_active
FROM sieve_scripts
WHERE mailbox_id = $1 AND name = $2;

-- name: GetActiveSieveScript :one
SELECT id, mailbox_id, name, content, is_active
FROM sieve_scripts
WHERE mailbox_id = $1 AND is_active = true;

-- name: UpsertSieveScript :exec
INSERT INTO sieve_scripts (mailbox_id, name, content, is_active)
VALUES ($1, $2, $3, false)
ON CONFLICT (mailbox_id, name) DO UPDATE SET content = EXCLUDED.content;

-- name: ClearSieveActive :exec
UPDATE sieve_scripts
SET is_active = false
WHERE mailbox_id = $1 AND is_active = true;

-- name: ActivateSieveScript :execresult
UPDATE sieve_scripts
SET is_active = true
WHERE mailbox_id = $1 AND name = $2;

-- name: DeleteSieveScript :exec
DELETE FROM sieve_scripts
WHERE mailbox_id = $1 AND name = $2;
