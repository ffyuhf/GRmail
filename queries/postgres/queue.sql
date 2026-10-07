-- name: InsertQueueItem :execresult
INSERT INTO delivery_queue (message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, ret_full, skip_tls_policy, created_at, updated_at)
VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8, $9);

-- name: ClaimDueQueueItems :many
-- F4 (queue batch 3): claim token + heartbeat written atomically with the
-- pending->in_flight transition; ReclaimStale judges staleness by
-- COALESCE(heartbeat_at, updated_at).
UPDATE delivery_queue
SET status = 'in_flight', claim_token = $1, heartbeat_at = $2, updated_at = $3
WHERE id IN (
    SELECT due.id FROM delivery_queue AS due
    WHERE due.status IN ('pending', 'deferred') AND due.next_attempt_at <= $4
    ORDER BY due.next_attempt_at, due.id
    LIMIT $5
)
RETURNING id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy;

-- name: MarkQueueResult :execresult
-- F1 (A-14-2): guarded by status='in_flight'; late writes affect zero rows.
UPDATE delivery_queue
SET status = $1, attempts = $2, next_attempt_at = $3, last_smtp_code = $4, last_error = $5, claim_token = NULL, heartbeat_at = NULL, updated_at = $6
WHERE id = $7 AND status = 'in_flight';

-- name: HeartbeatQueueClaim :execresult
-- F4 (A-14-1/D1): renew heartbeat before each MX attempt (token-guarded).
UPDATE delivery_queue
SET heartbeat_at = $1, updated_at = $2
WHERE claim_token = $3 AND status = 'in_flight';

-- name: ReclaimStaleQueueItems :execresult
-- F2 (A-14-3) + F4: reclaim resets next_attempt_at by the attempts-based
-- backoff ladder (t0..t6 absolute timestamps from the repo layer).
UPDATE delivery_queue
SET status = 'pending', claim_token = NULL, heartbeat_at = NULL, updated_at = $1,
    next_attempt_at = CASE attempts
        WHEN 0 THEN $2 WHEN 1 THEN $3 WHEN 2 THEN $4 WHEN 3 THEN $5
        WHEN 4 THEN $6 WHEN 5 THEN $7 ELSE $8 END
WHERE status = 'in_flight' AND COALESCE(heartbeat_at, updated_at) < $9;

-- name: MarkQueueDSNSent :execresult
-- F5 (B-R2): DSN-issued marker on the failed row (idempotent guard).
UPDATE delivery_queue
SET dsn_sent = TRUE, updated_at = $1
WHERE id = $2 AND status = 'failed' AND dsn_sent = FALSE;

-- name: ListFailedDSNPending :many
-- F5 (B-R2): rescan source for crashed-before-emitDSN failed rows.
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy
FROM delivery_queue
WHERE status = 'failed' AND dsn_sent = FALSE
ORDER BY id
LIMIT $1;

-- name: GetQueueItem :one
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy
FROM delivery_queue WHERE id = $1;
