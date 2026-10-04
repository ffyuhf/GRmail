-- name: InsertSystemFolders :exec
INSERT INTO folders (mailbox_id, name, kind, created_at)
VALUES
    ($1, 'INBOX', 'inbox', $2),
    ($3, 'Sent', 'sent', $4),
    ($5, 'Drafts', 'drafts', $6),
    ($7, 'Junk', 'junk', $8),
    ($9, 'Trash', 'trash', $10);

-- name: InsertAggregateFolder :exec
-- U25: sixth system folder for postmaster mailboxes (kind=unregistered, the
-- FR-003 aggregate carry; UNIQUE(mailbox_id,name) keeps inserts idempotent)
INSERT INTO folders (mailbox_id, name, kind, created_at)
VALUES ($1, 'Unregistered', 'unregistered', $2);

-- name: ListFoldersByMailbox :many
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE mailbox_id = $1
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
VALUES ($1, $2, 'custom', $3);

-- name: GetFolderByID :one
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE id = $1;

-- name: RenameCustomFolder :execrows
UPDATE folders
SET name = $1
WHERE id = $2 AND kind = 'custom';

-- name: DeleteCustomFolder :execrows
DELETE FROM folders
WHERE id = $1 AND kind = 'custom';

-- name: CountUnreadByFolder :many
SELECT folder_id, COUNT(*) AS unread_count
FROM mailbox_messages
WHERE mailbox_id = $1 AND is_read = false AND status = 'normal'
GROUP BY folder_id;

-- name: GetSystemFolderByKind :one
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE mailbox_id = $1 AND kind = $2;

-- name: GetFolderByName :one
SELECT id, mailbox_id, name, kind, created_at
FROM folders
WHERE mailbox_id = $1 AND name = $2;
