-- name: ListSieveScripts :many
SELECT id, mailbox_id, name, content, is_active
FROM sieve_scripts
WHERE mailbox_id = ?
ORDER BY name;

-- name: GetSieveScript :one
SELECT id, mailbox_id, name, content, is_active
FROM sieve_scripts
WHERE mailbox_id = ? AND name = ?;

-- name: GetActiveSieveScript :one
SELECT id, mailbox_id, name, content, is_active
FROM sieve_scripts
WHERE mailbox_id = ? AND is_active = 1;

-- name: UpsertSieveScript :exec
INSERT INTO sieve_scripts (mailbox_id, name, content, is_active)
VALUES (?, ?, ?, 0)
ON CONFLICT(mailbox_id, name) DO UPDATE SET content = excluded.content;

-- name: ClearSieveActive :exec
UPDATE sieve_scripts
SET is_active = 0
WHERE mailbox_id = ? AND is_active = 1;

-- name: ActivateSieveScript :execresult
UPDATE sieve_scripts
SET is_active = 1
WHERE mailbox_id = ? AND name = ?;

-- name: DeleteSieveScript :exec
DELETE FROM sieve_scripts
WHERE mailbox_id = ? AND name = ?;
