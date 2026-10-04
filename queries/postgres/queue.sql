-- name: InsertQueueItem :execresult
INSERT INTO delivery_queue (message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, ret_full, created_at, updated_at)
VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8);

-- name: ClaimDueQueueItems :many
UPDATE delivery_queue
SET status = 'in_flight', updated_at = $1
WHERE id IN (
    SELECT due.id FROM delivery_queue AS due
    WHERE due.status IN ('pending', 'deferred') AND due.next_attempt_at <= $2
    ORDER BY due.next_attempt_at, due.id
    LIMIT $3
)
RETURNING id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full;

-- name: MarkQueueResult :execresult
UPDATE delivery_queue
SET status = $1, attempts = $2, next_attempt_at = $3, last_smtp_code = $4, last_error = $5, updated_at = $6
WHERE id = $7;

-- name: ReclaimStaleQueueItems :execresult
UPDATE delivery_queue
SET status = 'pending', updated_at = $1
WHERE status = 'in_flight' AND updated_at < $2;

-- name: GetQueueItem :one
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full
FROM delivery_queue WHERE id = $1;
