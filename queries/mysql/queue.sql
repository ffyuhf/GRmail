-- name: InsertQueueItem :execresult
INSERT INTO delivery_queue (message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, ret_full, created_at, updated_at)
VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?);

-- name: ClaimDueQueueItemsUpdate :execrows
UPDATE delivery_queue
SET status = 'in_flight', updated_at = ?
WHERE id IN (
    SELECT id FROM (
        SELECT due.id FROM delivery_queue AS due
        WHERE due.status IN ('pending', 'deferred') AND due.next_attempt_at <= ?
        ORDER BY due.next_attempt_at, due.id
        LIMIT ?
    ) AS t
);

-- name: SelectClaimedQueueItems :many
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full
FROM delivery_queue
WHERE status = 'in_flight' AND updated_at = ?;

-- name: MarkQueueResult :execresult
UPDATE delivery_queue
SET status = ?, attempts = ?, next_attempt_at = ?, last_smtp_code = ?, last_error = ?, updated_at = ?
WHERE id = ?;

-- name: ReclaimStaleQueueItems :execresult
UPDATE delivery_queue
SET status = 'pending', updated_at = ?
WHERE status = 'in_flight' AND updated_at < ?;

-- name: GetQueueItem :one
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full
FROM delivery_queue WHERE id = ?;
