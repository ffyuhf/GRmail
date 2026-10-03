-- name: InsertSystemFolders :exec
INSERT INTO folders (mailbox_id, name, kind, created_at)
VALUES
    (?, 'INBOX', 'inbox', ?),
    (?, 'Sent', 'sent', ?),
    (?, 'Drafts', 'drafts', ?),
    (?, 'Junk', 'junk', ?),
    (?, 'Trash', 'trash', ?);

-- name: InsertAggregateFolder :exec
-- U25: sixth system folder for postmaster mailboxes (kind=unregistered, the
-- FR-003 aggregate carry; UNIQUE(mailbox_id,name) keeps inserts idempotent)
INSERT INTO folders (mailbox_id, name, kind, created_at)
VALUES (?, 'Unregistered', 'unregistered', ?);

-- name: ListFoldersByMailbox :many
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE mailbox_id = ?
ORDER BY CASE kind
             WHEN 'inbox' THEN 0
             WHEN 'sent' THEN 1
             WHEN 'drafts' THEN 2
             WHEN 'junk' THEN 3
             WHEN 'trash' THEN 4
             WHEN 'unregistered' THEN 5
             ELSE 6
         END, name;

-- name: CreateCustomFolder :execresult
INSERT INTO folders (mailbox_id, name, kind, created_at)
VALUES (?, ?, 'custom', ?);

-- name: GetFolderByID :one
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE id = ?;

-- name: RenameCustomFolder :execrows
UPDATE folders
SET name = ?
WHERE id = ? AND kind = 'custom';

-- name: DeleteCustomFolder :execrows
DELETE FROM folders
WHERE id = ? AND kind = 'custom';

-- name: CountUnreadByFolder :many
SELECT folder_id, COUNT(*) AS unread_count
FROM mailbox_messages
WHERE mailbox_id = ? AND is_read = 0 AND status = 'normal'
GROUP BY folder_id;

-- name: GetSystemFolderByKind :one
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE mailbox_id = ? AND kind = ?;

-- name: GetFolderByName :one
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE mailbox_id = ? AND name = ?;
