// Package storage queue 域 PostgreSQL 实现（U11 Q2-A 三套生成；契约 2.1 四方法签名零变更）。
// 依据：U11 计划书 1.5④——PG 原生支持 UPDATE...RETURNING，ClaimDue 沿 SQLite 单语句语义；
// 队列防丢信收口批（G2 批准 2026-10-07 08:41:07）：F1 守卫/F2 退避阶梯/F4 token+心跳/
// F5 DSN 重扫——三库同构（sqlite 实现定义的哨兵/阶梯/令牌辅助共享）。
// 覆盖条目：FR-014（TC-014 queue 域 PostgreSQL 格）+NFR-007。
// 修改历史：
//
//	2026-09-20 05:36:00 | 新增 | U11 三库验收（计划书步骤 4）
//	2026-10-07 08:53:00 | 修正 | 队列防丢信收口批 F1/F2/F4/F5（迁移 00012）
//	2026-10-07 15:20:00 | 扩展 | 传输安全合规批 F1/A-9：SkipTLSPolicy 列写入/读回
//	（迁移 00013；G2 批准 2026-10-07 15:13:06；rfc8460 §5.3.1）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/postgres"
)

// 编译期断言：契约 2.1 接口实现锁定（PostgreSQL 形态）+ F4/F5 窄视图。
var (
	_ QueueRepo     = (*PostgresQueueRepo)(nil)
	_ QueueClaimOps = (*PostgresQueueRepo)(nil)
)

// PostgresQueueRepo QueueRepo 的 PostgreSQL 实现。
type PostgresQueueRepo struct {
	db *sql.DB
	q  *dbgen.Queries
	ck constraintChecker
}

// NewPostgresQueueRepo 构造投递队列仓储（PostgreSQL）。
// 参数：db 已迁移就绪的 PostgreSQL 连接。返回：仓储实例。
func NewPostgresQueueRepo(db *sql.DB) *PostgresQueueRepo {
	return &PostgresQueueRepo{db: db, q: dbgen.New(db), ck: pgChecker{}}
}

// Enqueue 单事务批量入队。
func (r *PostgresQueueRepo) Enqueue(ctx context.Context, items []*QueueItem) error {
	return withTxCompat(ctx, r.db, func(tx *sql.Tx) error {
		qtx := r.q.WithTx(tx)
		now := time.Now().UTC()
		for _, it := range items {
			if err := insertQueueRowPG(ctx, qtx, it, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// ClaimDue 认领到期项（单语句 UPDATE...RETURNING——与 SQLite 同语义；F4：token+heartbeat
// 原子写入）。
func (r *PostgresQueueRepo) ClaimDue(ctx context.Context, now time.Time, limit int) ([]*QueueItem, error) {
	token := newClaimToken()
	rows, err := r.q.ClaimDueQueueItems(ctx, dbgen.ClaimDueQueueItemsParams{
		ClaimToken:    sql.NullString{String: token, Valid: true},
		HeartbeatAt:   sql.NullTime{Time: now, Valid: true},
		UpdatedAt:     now,
		NextAttemptAt: now,
		Limit:         int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("认领到期队列: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueClaimRowToItemPG(&rows[i]))
	}
	return items, nil
}

// TouchClaim 心跳续期（F4：token+in_flight 双守卫）。
func (r *PostgresQueueRepo) TouchClaim(ctx context.Context, token string) error {
	now := time.Now().UTC()
	if _, err := r.q.HeartbeatQueueClaim(ctx, dbgen.HeartbeatQueueClaimParams{
		HeartbeatAt: sql.NullTime{Time: now, Valid: true},
		UpdatedAt:   now,
		ClaimToken:  sql.NullString{String: token, Valid: true},
	}); err != nil {
		return fmt.Errorf("续期投递心跳: %w", err)
	}
	return nil
}

// MarkResult 回写单次尝试结果（失败保持 in_flight 由 Stale 收敛；F1 守卫）。
func (r *PostgresQueueRepo) MarkResult(ctx context.Context, id int64, r2 AttemptResult) error {
	status := QueueDeferred
	switch r2.Status {
	case AttemptSent:
		status = QueueSent
	case AttemptFailed:
		status = QueueFailed
	}
	nextAt := r2.NextAttemptAt
	if nextAt.IsZero() {
		nextAt = time.Unix(1, 0).UTC() // 终态零值兜底（终态不参与调度——三库一致语义）
	}
	res, err := r.q.MarkQueueResult(ctx, dbgen.MarkQueueResultParams{
		Status:        string(status),
		Attempts:      int32(r2.Attempts),
		NextAttemptAt: nextAt,
		LastSmtpCode:  nullIfZeroInt32(r2.SMTPCode),
		LastError:     nullIfEmpty(r2.Error),
		UpdatedAt:     time.Now().UTC(),
		ID:            id,
	})
	if err != nil {
		return fmt.Errorf("回写投递结果: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrQueueStaleWrite // F1：迟到回写作废
	}
	return nil
}

// ReclaimStale 崩溃恢复（in_flight 超时→pending；F2 退避阶梯重置+F4 COALESCE 判据）。
func (r *PostgresQueueRepo) ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error) {
	now := time.Now().UTC()
	ladder := defaultReclaimBackoff()
	var caseAt [7]time.Time
	for i, d := range ladder {
		caseAt[i] = now.Add(d)
	}
	res, err := r.q.ReclaimStaleQueueItems(ctx, dbgen.ReclaimStaleQueueItemsParams{
		UpdatedAt:       now,
		NextAttemptAt:   caseAt[0],
		NextAttemptAt_2: caseAt[1],
		NextAttemptAt_3: caseAt[2],
		NextAttemptAt_4: caseAt[3],
		NextAttemptAt_5: caseAt[4],
		NextAttemptAt_6: caseAt[5],
		NextAttemptAt_7: caseAt[6],
		HeartbeatAt:     sql.NullTime{Time: now.Add(-olderThan), Valid: true}, // Stale 阈值
	})
	if err != nil {
		return 0, fmt.Errorf("回收崩溃残留队列: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkDSNSent 置位 DSN 回执（F5/B-R2：幂等守卫）。
func (r *PostgresQueueRepo) MarkDSNSent(ctx context.Context, id int64) error {
	if _, err := r.q.MarkQueueDSNSent(ctx, dbgen.MarkQueueDSNSentParams{
		UpdatedAt: time.Now().UTC(),
		ID:        id,
	}); err != nil {
		return fmt.Errorf("置位 DSN 回执: %w", err)
	}
	return nil
}

// ListFailedDSNPending 重扫批查（F5/B-R2：failed 且 DSN 未发行）。
func (r *PostgresQueueRepo) ListFailedDSNPending(ctx context.Context, limit int) ([]*QueueItem, error) {
	rows, err := r.q.ListFailedDSNPending(ctx, int32(limit))
	if err != nil {
		return nil, fmt.Errorf("批查 DSN 待发行: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueListRowToItemPG(&rows[i]))
	}
	return items, nil
}

// StoreSubmission 提交入队单事务。
func (r *PostgresQueueRepo) StoreSubmission(ctx context.Context, txmeta *SubmissionMeta) error {
	return withTxCompat(ctx, r.db, func(tx *sql.Tx) error {
		qtx := r.q.WithTx(tx)
		now := time.Now().UTC()
		msgPK, err := insertMessageRowPG(ctx, qtx, txmeta.Message, now)
		if err != nil {
			return err
		}
		for _, it := range txmeta.Items {
			it.MessageID = msgPK
			if err = insertQueueRowPG(ctx, qtx, it, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// ───────────────────────── PostgreSQL 辅助 ─────────────────────────

// insertQueueRowPG 插入 delivery_queue 行。
func insertQueueRowPG(ctx context.Context, qtx *dbgen.Queries, it *QueueItem, now time.Time) error {
	nextAt := it.NextAttemptAt
	if nextAt.IsZero() {
		nextAt = time.Now().UTC()
	}
	_, err := qtx.InsertQueueItem(ctx, dbgen.InsertQueueItemParams{
		MessageID:     it.MessageID,
		EnvelopeFrom:  it.EnvelopeFrom,
		RcptTo:        it.RcptTo,
		Status:        string(QueuePending),
		NextAttemptAt: nextAt,
		RetFull:       it.RetFull,       // F-L3：RET=FULL 持久化
		SkipTlsPolicy: it.SkipTLSPolicy, // F1/A-9：报告行豁免标记持久化（dbgen 驼峰字段名）
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		return fmt.Errorf("插入队列行: %w", err)
	}
	return nil
}

// queueClaimRowToItemPG ClaimDue RETURNING 行 → 域类型（F4：含 claim_token）。
func queueClaimRowToItemPG(row *dbgen.ClaimDueQueueItemsRow) *QueueItem {
	return &QueueItem{
		ID:            row.ID,
		MessageID:     row.MessageID,
		EnvelopeFrom:  row.EnvelopeFrom,
		RcptTo:        row.RcptTo,
		Status:        QueueStatus(row.Status),
		Attempts:      int(row.Attempts),
		NextAttemptAt: row.NextAttemptAt,
		LastSMTPCode:  int(row.LastSmtpCode.Int32),
		LastError:     row.LastError.String,
		RetFull:       row.RetFull,       // F-L3
		SkipTLSPolicy: row.SkipTlsPolicy, // F1/A-9：豁免标记读回（dbgen 驼峰字段名）
		ClaimToken:    row.ClaimToken.String,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}

// queueListRowToItemPG ListFailedDSNPending 行 → 域类型（F5）。
func queueListRowToItemPG(row *dbgen.ListFailedDSNPendingRow) *QueueItem {
	return &QueueItem{
		ID:            row.ID,
		MessageID:     row.MessageID,
		EnvelopeFrom:  row.EnvelopeFrom,
		RcptTo:        row.RcptTo,
		Status:        QueueStatus(row.Status),
		Attempts:      int(row.Attempts),
		NextAttemptAt: row.NextAttemptAt,
		LastSMTPCode:  int(row.LastSmtpCode.Int32),
		LastError:     row.LastError.String,
		RetFull:       row.RetFull,
		SkipTLSPolicy: row.SkipTlsPolicy, // F1/A-9：豁免标记读回（dbgen 驼峰字段名）
		ClaimToken:    row.ClaimToken.String,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}
