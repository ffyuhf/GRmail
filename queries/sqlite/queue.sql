-- name: InsertQueueItem :execresult
INSERT INTO delivery_queue (message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, ret_full, skip_tls_policy, created_at, updated_at)
VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?);

-- name: ClaimDueQueueItems :many
-- F4 (queue batch 3): claim token + heartbeat written atomically with the
-- pending->in_flight transition; ReclaimStale judges staleness by
-- COALESCE(heartbeat_at, updated_at) so in-flight deliveries that keep
-- renewing the heartbeat are never reclaimed and re-delivered.
UPDATE delivery_queue
SET status = 'in_flight', claim_token = ?, heartbeat_at = ?, updated_at = ?
WHERE id IN (
    SELECT due.id FROM delivery_queue AS due
    WHERE due.status IN ('pending', 'deferred') AND due.next_attempt_at <= ?
    ORDER BY due.next_attempt_at, due.id
    LIMIT ?
)
RETURNING id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy;

-- name: MarkQueueResult :execresult
-- F1 (A-14-2): the write is guarded by status='in_flight' so a late result
-- arriving after a Stale reclaim (row already back to pending/deferred) can
-- never overwrite the newer state; RowsAffected==0 means stale write.
UPDATE delivery_queue
SET status = ?, attempts = ?, next_attempt_at = ?, last_smtp_code = ?, last_error = ?, claim_token = NULL, heartbeat_at = NULL, updated_at = ?
WHERE id = ? AND status = 'in_flight';

-- name: HeartbeatQueueClaim :execresult
-- F4 (A-14-1/D1): renew the heartbeat before each MX attempt; the token
-- guard keeps the renewal bound to the claiming worker only.
UPDATE delivery_queue
SET heartbeat_at = ?, updated_at = ?
WHERE claim_token = ? AND status = 'in_flight';

-- name: ReclaimStaleQueueItems :execresult
-- F2 (A-14-3) + F4: reclaim resets next_attempt_at by the attempts-based
-- backoff ladder (t0..t6 absolute timestamps supplied by the repo layer,
-- mirroring worker.backoffDelay default profile) so a crash-recovery batch
-- does not fire a thundering herd of immediate retries; claim bookkeeping
-- columns are cleared for the fresh pending state.
UPDATE delivery_queue
SET status = 'pending', claim_token = NULL, heartbeat_at = NULL, updated_at = ?,
    next_attempt_at = CASE attempts
        WHEN 0 THEN ? WHEN 1 THEN ? WHEN 2 THEN ? WHEN 3 THEN ?
        WHEN 4 THEN ? WHEN 5 THEN ? ELSE ? END
WHERE status = 'in_flight' AND COALESCE(heartbeat_at, updated_at) < ?;

-- name: MarkQueueDSNSent :execresult
-- F5 (B-R2): mark the failed row as DSN-issued after emitDSN succeeds;
-- guarded double-condition keeps the rescan idempotent.
UPDATE delivery_queue
SET dsn_sent = 1, updated_at = ?
WHERE id = ? AND status = 'failed' AND dsn_sent = 0;

-- name: ListFailedDSNPending :many
-- F5 (B-R2): rescan source -- failed rows whose DSN has not been issued
-- (process crashed after MarkResult but before emitDSN completed).
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy
FROM delivery_queue
WHERE status = 'failed' AND dsn_sent = 0
ORDER BY id
LIMIT ?;

-- name: GetQueueItem :one
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy
FROM delivery_queue WHERE id = ?;
