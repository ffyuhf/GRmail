-- name: InsertMessage :one
INSERT INTO messages (message_id, blob_key, raw_size, subject, from_addr, to_addrs, cc_addrs, body_cache, sent_at, spf_result, dkim_result, dmarc_result, arc_result, auth_results_header, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING id;

-- name: ListBodyCachePending :many
SELECT id, blob_key FROM messages WHERE body_cache IS NULL LIMIT $1;

-- name: FillBodyCache :execrows
UPDATE messages SET body_cache = $1 WHERE id = $2;

-- name: InsertMailboxMessage :execresult
INSERT INTO mailbox_messages (mailbox_id, message_id, folder_id, uid, is_read, is_flagged, status, created_at)
VALUES ($1, $2, $3, $4, false, false, 'normal', $5);

-- name: InsertMailboxMessageWithFlags :execresult
INSERT INTO mailbox_messages (mailbox_id, message_id, folder_id, uid, is_read, is_flagged, is_answered, is_draft, status, internal_date, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetMaxMailboxUID :one
SELECT COALESCE(MAX(uid), 0) FROM mailbox_messages WHERE mailbox_id = $1;

-- name: ListMessagesByFolderPage :many
SELECT
    mm.id AS mm_id,
    mm.uid AS mm_uid,
    mm.is_read AS mm_is_read,
    mm.is_flagged AS mm_is_flagged,
    mm.status AS mm_status,
    m.subject AS m_subject,
    m.from_addr AS m_from_addr,
    m.sent_at AS m_sent_at,
    m.blob_key AS m_blob_key,
    m.raw_size AS m_raw_size
FROM mailbox_messages mm
JOIN messages m ON m.id = mm.message_id
WHERE mm.mailbox_id = $1 AND mm.folder_id = $2
ORDER BY mm.uid DESC
LIMIT $3 OFFSET $4;

-- name: CountMessagesByFolder :one
SELECT COUNT(*) FROM mailbox_messages
WHERE mailbox_id = $1 AND folder_id = $2;

-- name: GetMailboxMessageDetail :one
SELECT
    mm.id AS mm_id,
    mm.uid AS mm_uid,
    mm.mailbox_id AS mm_mailbox_id,
    mm.folder_id AS mm_folder_id,
    mm.message_id AS mm_message_pk,
    mm.is_read AS mm_is_read,
    mm.is_flagged AS mm_is_flagged,
    mm.is_answered AS mm_is_answered,
    mm.is_draft AS mm_is_draft,
    mm.status AS mm_status,
    mm.internal_date AS mm_internal_date,
    mm.created_at AS mm_created_at,
    m.blob_key AS m_blob_key,
    m.subject AS m_subject,
    m.from_addr AS m_from_addr,
    m.to_addrs AS m_to_addrs,
    m.cc_addrs AS m_cc_addrs,
    m.sent_at AS m_sent_at,
    m.raw_size AS m_raw_size
FROM mailbox_messages mm
JOIN messages m ON m.id = mm.message_id
WHERE mm.mailbox_id = $1 AND mm.id = $2;

-- name: GetMailboxMessageFlags :one
SELECT id, mailbox_id, is_read, is_flagged, is_answered, is_draft, status
FROM mailbox_messages
WHERE id = $1;

-- name: UpdateMailboxMessageFlags :execrows
UPDATE mailbox_messages
SET is_read = $1, is_flagged = $2, is_answered = $3, is_draft = $4, status = $5
WHERE id = $6;

-- name: MoveMailboxMessage :execrows
UPDATE mailbox_messages
SET folder_id = $1
WHERE id = $2;

-- name: MarkMailboxMessagesDeleted :execrows
UPDATE mailbox_messages
SET status = 'deleted'
WHERE id = ANY(sqlc.slice('ids'));

-- name: DeleteMailboxMessages :execrows
DELETE FROM mailbox_messages
WHERE id = ANY(sqlc.slice('ids'));

-- name: DeleteOrphanMessages :execrows
DELETE FROM messages
WHERE NOT EXISTS (
    SELECT 1 FROM mailbox_messages mm WHERE mm.message_id = messages.id
);

-- name: ListFolderUIDsASC :many
SELECT uid FROM mailbox_messages
WHERE mailbox_id = $1 AND folder_id = $2
ORDER BY uid ASC;

-- D8 keyword storage (table mailbox_keywords, migration 00008)

-- name: InsertMailboxKeyword :exec
INSERT INTO mailbox_keywords (mailbox_message_id, keyword, created_at)
VALUES ($1, $2, $3);

-- name: ListMessageKeywords :many
SELECT keyword FROM mailbox_keywords
WHERE mailbox_message_id = $1
ORDER BY keyword;

-- name: DeleteKeywordsByMessageID :exec
DELETE FROM mailbox_keywords
WHERE mailbox_message_id = $1;

-- U25 shadow aggregate reachability (FR-003 carry expansion, S3-W Q1-B/Q4)

-- name: ListShadowBackfill :many
-- pending backfill: message ids archived in shadow mailboxes without an
-- aggregate copy yet (DISTINCT: one aggregate row per messages entity;
-- NOT EXISTS makes re-runs naturally idempotent)
SELECT DISTINCT mm.message_id
FROM mailbox_messages mm
JOIN mailboxes mb ON mb.id = mm.mailbox_id AND mb.status = 'shadow'
WHERE NOT EXISTS (
    SELECT 1
    FROM mailbox_messages agg
    JOIN folders af ON af.id = agg.folder_id AND af.kind = 'unregistered'
    WHERE agg.message_id = mm.message_id
)
ORDER BY mm.message_id
LIMIT $1;

-- U25 delete cascade (FR-003/Q2 directive): removing an aggregate-folder row also
-- removes every sibling mailbox_messages row of the same messages entity. Split
-- into single-table queries to sidestep sqlc engine JOIN+slice rewrite limits.

-- name: GetMailboxMessageRows :many
-- fetch row metadata (id, message_id, folder_id) for folder-membership decision
SELECT id, message_id, folder_id
FROM mailbox_messages
WHERE id = ANY(sqlc.slice('ids'));

-- name: ListAggregateFolderIDs :many
-- all aggregate folder ids (kind=unregistered, postmaster-owned)
SELECT id FROM folders WHERE kind = 'unregistered';

-- name: SelectIDsByMessageIDs :many
-- sibling row ids sharing the same messages entity (caller excludes originals)
SELECT DISTINCT id
FROM mailbox_messages
WHERE message_id = ANY(sqlc.slice('messageIDs'));

-- name: DeleteKeywordsByMessageIDs :execrows
DELETE FROM mailbox_keywords
WHERE mailbox_message_id = ANY(sqlc.slice('ids'));

-- name: GetMailboxMessageIDByUID :one
SELECT id FROM mailbox_messages
WHERE mailbox_id = $1 AND uid = $2;
