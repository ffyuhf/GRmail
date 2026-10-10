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

-- name: CopySieveScript :execresult
-- F10/C21 (2026-10-10 C-debt batch): atomic RENAMESCRIPT support - copy row to
-- new name (carrying is_active); paired with DeleteSieveScript in one repo tx.
INSERT INTO sieve_scripts (mailbox_id, name, content, is_active)
SELECT s.mailbox_id, sqlc.arg(new_name), s.content, s.is_active
FROM sieve_scripts s
WHERE s.mailbox_id = sqlc.arg(mailbox_id) AND s.name = sqlc.arg(old_name);
