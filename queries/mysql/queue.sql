-- name: InsertQueueItem :execresult
INSERT INTO delivery_queue (message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, ret_full, skip_tls_policy, created_at, updated_at)
VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?);

-- name: ClaimDueQueueItemsUpdate :execrows
-- F3/F4 (A-14-4/D1): the claim token is written together with the
-- pending->in_flight transition; the follow-up read selects by token so the
-- historical updated_at=now same-value read-back race is eliminated.
UPDATE delivery_queue
SET status = 'in_flight', claim_token = ?, heartbeat_at = ?, updated_at = ?
WHERE id IN (
    SELECT id FROM (
        SELECT due.id FROM delivery_queue AS due
        WHERE due.status IN ('pending', 'deferred') AND due.next_attempt_at <= ?
        ORDER BY due.next_attempt_at, due.id
        LIMIT ?
    ) AS t
);

-- name: SelectClaimedQueueItems :many
-- F3: read back the claimed set by the unique claim token (not by
-- updated_at) -- concurrent claim batches can never cross-read rows.
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy
FROM delivery_queue
WHERE claim_token = ?;

-- name: MarkQueueResult :execresult
-- F1 (A-14-2): guarded by status='in_flight'; late writes after a Stale
-- reclaim affect zero rows and are dropped by the caller with a Warn.
UPDATE delivery_queue
SET status = ?, attempts = ?, next_attempt_at = ?, last_smtp_code = ?, last_error = ?, claim_token = NULL, heartbeat_at = NULL, updated_at = ?
WHERE id = ? AND status = 'in_flight';

-- name: HeartbeatQueueClaim :execrows
-- F4 (A-14-1/D1): renew heartbeat before each MX attempt (token-guarded).
UPDATE delivery_queue
SET heartbeat_at = ?, updated_at = ?
WHERE claim_token = ? AND status = 'in_flight';

-- name: ReclaimStaleQueueItems :execresult
-- F2 (A-14-3) + F4: reclaim resets next_attempt_at by the attempts-based
-- backoff ladder (t0..t6 absolute timestamps from the repo layer) and
-- judges staleness by COALESCE(heartbeat_at, updated_at).
UPDATE delivery_queue
SET status = 'pending', claim_token = NULL, heartbeat_at = NULL, updated_at = ?,
    next_attempt_at = CASE attempts
        WHEN 0 THEN ? WHEN 1 THEN ? WHEN 2 THEN ? WHEN 3 THEN ?
        WHEN 4 THEN ? WHEN 5 THEN ? ELSE ? END
WHERE status = 'in_flight' AND COALESCE(heartbeat_at, updated_at) < ?;

-- name: MarkQueueDSNSent :execresult
-- F5 (B-R2): DSN-issued marker on the failed row (idempotent guard).
UPDATE delivery_queue
SET dsn_sent = 1, updated_at = ?
WHERE id = ? AND status = 'failed' AND dsn_sent = 0;

-- name: ListFailedDSNPending :many
-- F5 (B-R2): rescan source for crashed-before-emitDSN failed rows.
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy
FROM delivery_queue
WHERE status = 'failed' AND dsn_sent = 0
ORDER BY id
LIMIT ?;

-- name: GetQueueItem :one
SELECT id, message_id, envelope_from, rcpt_to, status, attempts, next_attempt_at, last_smtp_code, last_error, created_at, updated_at, ret_full, claim_token, skip_tls_policy
FROM delivery_queue WHERE id = ?;
