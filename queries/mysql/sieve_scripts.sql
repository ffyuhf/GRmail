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
ON DUPLICATE KEY UPDATE content = VALUES(content);

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

-- name: CopySieveScript :execresult
-- F10/C21 (2026-10-10 C-debt batch): atomic RENAMESCRIPT support - copy row to
-- new name (carrying is_active); paired with DeleteSieveScript in one repo tx.
INSERT INTO sieve_scripts (mailbox_id, name, content, is_active)
SELECT s.mailbox_id, sqlc.arg(new_name), s.content, s.is_active
FROM sieve_scripts s
WHERE s.mailbox_id = sqlc.arg(mailbox_id) AND s.name = sqlc.arg(old_name);
