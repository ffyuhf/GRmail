-- name: InsertMessage :execresult
INSERT INTO messages (message_id, blob_key, raw_size, subject, from_addr, to_addrs, cc_addrs, body_cache, sent_at, spf_result, dkim_result, dmarc_result, arc_result, auth_results_header, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListBodyCachePending :many
SELECT id, blob_key FROM messages WHERE body_cache IS NULL LIMIT ?;

-- name: FillBodyCache :execrows
UPDATE messages SET body_cache = ? WHERE id = ?;

-- name: InsertMailboxMessage :execresult
INSERT INTO mailbox_messages (mailbox_id, message_id, folder_id, uid, is_read, is_flagged, status, created_at)
VALUES (?, ?, ?, ?, 0, 0, 'normal', ?);

-- name: InsertMailboxMessageWithFlags :execresult
INSERT INTO mailbox_messages (mailbox_id, message_id, folder_id, uid, is_read, is_flagged, is_answered, is_draft, status, internal_date, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetMaxMailboxUID :one
SELECT COALESCE(MAX(uid), 0) FROM mailbox_messages WHERE mailbox_id = ?;

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
WHERE mm.mailbox_id = ? AND mm.folder_id = ?
ORDER BY mm.uid DESC
LIMIT ? OFFSET ?;

-- name: CountMessagesByFolder :one
SELECT COUNT(*) FROM mailbox_messages
WHERE mailbox_id = ? AND folder_id = ?;

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
WHERE mm.mailbox_id = ? AND mm.id = ?;

-- name: GetMailboxMessageFlags :one
SELECT id, mailbox_id, is_read, is_flagged, is_answered, is_draft, status
FROM mailbox_messages
WHERE id = ?;

-- name: UpdateMailboxMessageFlags :execrows
-- F4 (B-C1, config-concurrency batch): the three-valued flag patch is
-- atomized into a single statement. Guard params (*_set) appear only inside
-- "IS NULL" so they map to nullable values (nil = leave column unchanged);
-- value params (*_val) live in the ELSE arm and map to the column type.
-- This closes the non-transactional read-modify-write race (lost updates on
-- concurrent flag writes) across all three dialects.
UPDATE mailbox_messages
SET is_read = CASE WHEN sqlc.narg('read_set') IS NULL THEN is_read ELSE sqlc.arg('read_val') END,
    is_flagged = CASE WHEN sqlc.narg('flagged_set') IS NULL THEN is_flagged ELSE sqlc.arg('flagged_val') END,
    is_answered = CASE WHEN sqlc.narg('answered_set') IS NULL THEN is_answered ELSE sqlc.arg('answered_val') END,
    is_draft = CASE WHEN sqlc.narg('draft_set') IS NULL THEN is_draft ELSE sqlc.arg('draft_val') END,
    status = CASE
        WHEN sqlc.narg('deleted_set') IS NULL THEN status
        WHEN sqlc.arg('deleted_flag') THEN 'deleted'
        ELSE 'normal'
    END
WHERE id = sqlc.arg('id');

-- name: MoveMailboxMessage :execrows
UPDATE mailbox_messages
SET folder_id = ?
WHERE id = ?;

-- name: MarkMailboxMessagesDeleted :execrows
UPDATE mailbox_messages
SET status = 'deleted'
WHERE id IN (sqlc.slice('ids'));

-- name: DeleteMailboxMessages :execrows
DELETE FROM mailbox_messages
WHERE id IN (sqlc.slice('ids'));

-- name: DeleteOrphanMessages :execrows
DELETE FROM messages
WHERE NOT EXISTS (
    SELECT 1 FROM mailbox_messages mm WHERE mm.message_id = messages.id
);

-- name: ListFolderUIDsASC :many
SELECT uid FROM mailbox_messages
WHERE mailbox_id = ? AND folder_id = ?
ORDER BY uid ASC;

-- D8 keyword storage (table mailbox_keywords, migration 00008)

-- name: InsertMailboxKeyword :exec
INSERT INTO mailbox_keywords (mailbox_message_id, keyword, created_at)
VALUES (?, ?, ?);

-- name: ListMessageKeywords :many
SELECT keyword FROM mailbox_keywords
WHERE mailbox_message_id = ?
ORDER BY keyword;

-- name: DeleteKeywordsByMessageID :exec
DELETE FROM mailbox_keywords
WHERE mailbox_message_id = ?;

-- name: DeleteKeywordsByMessageIDs :execrows
DELETE FROM mailbox_keywords
WHERE mailbox_message_id IN (sqlc.slice('ids'));

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
LIMIT ?;

-- U25 delete cascade (FR-003/Q2 directive): removing an aggregate-folder row also
-- removes every sibling mailbox_messages row of the same messages entity. Split
-- into single-table queries to sidestep sqlc engine JOIN+slice rewrite limits.

-- name: GetMailboxMessageRows :many
-- fetch row metadata (id, message_id, folder_id) for folder-membership decision
SELECT id, message_id, folder_id
FROM mailbox_messages
WHERE id IN (sqlc.slice('ids'));

-- name: ListAggregateFolderIDs :many
-- all aggregate folder ids (kind=unregistered, postmaster-owned)
SELECT id FROM folders WHERE kind = 'unregistered';

-- name: SelectIDsByMessageIDs :many
-- sibling row ids sharing the same messages entity (caller excludes originals)
SELECT DISTINCT id
FROM mailbox_messages
WHERE message_id IN (sqlc.slice('messageIDs'));

-- name: GetMailboxMessageIDByUID :one
SELECT id FROM mailbox_messages
WHERE mailbox_id = ? AND uid = ?;

-- Performance batch F2 (B-P3-1): aggregate STATUS counts in one query -
-- replaces full-folder row loading via PageList Limit 1<<30 (rfc9051 6.3.11
-- MESSAGES/UNSEEN/DELETED semantics unchanged; zero row load).
-- MySQL: SUM(int) returns DECIMAL - CAST AS SIGNED keeps int64 scan.

-- name: FolderStatusCounts :one
SELECT
    COUNT(*) AS total,
    COALESCE(CAST(SUM(CASE WHEN is_read = false THEN 1 ELSE 0 END) AS SIGNED), 0) AS unread,
    COALESCE(CAST(SUM(CASE WHEN status = 'deleted' THEN 1 ELSE 0 END) AS SIGNED), 0) AS deleted
FROM mailbox_messages
WHERE mailbox_id = ? AND folder_id = ?;

-- name: SumFolderRawSize :one
-- Performance batch F2 (B-P3-1): aggregate SIZE for STATUS (rfc9051 6.3.11 -
-- sum of RFC822.SIZE values, lower-bound guarantee preserved).
SELECT COALESCE(CAST(SUM(m.raw_size) AS SIGNED), 0)
FROM mailbox_messages mm
JOIN messages m ON m.id = mm.message_id
WHERE mm.mailbox_id = ? AND mm.folder_id = ?;

-- name: ListDetailsByIDs :many
-- Performance batch F4 (B-P3-3): batched detail fetch (mailbox-scoped) -
-- replaces per-message IMAPSearch+GetDetail N+1 in FETCH/STORE/Copy paths.
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
WHERE mm.mailbox_id = ? AND mm.id IN (sqlc.slice('ids'));

-- name: ListKeywordsByMessageIDs :many
-- Performance batch F4: batched keyword rows for detail assembly.
SELECT mailbox_message_id, keyword
FROM mailbox_keywords
WHERE mailbox_message_id IN (sqlc.slice('ids'));
