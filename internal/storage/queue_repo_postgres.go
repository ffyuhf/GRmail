// Package storage queue 域 PostgreSQL 实现（U11 Q2-A 三套生成；契约 2.1 四方法签名零变更）。
// 依据：U11 计划书 1.5④——PG 原生支持 UPDATE...RETURNING，ClaimDue 沿 SQLite 单语句语义。
// 覆盖条目：FR-014（TC-014 queue 域 PostgreSQL 格）。
// 修改历史：
//
//	2026-09-20 05:36:00 | 新增 | U11 三库验收（计划书步骤 4）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/postgres"
)

// 编译期断言：契约 2.1 接口实现锁定（PostgreSQL 形态）。
var _ QueueRepo = (*PostgresQueueRepo)(nil)

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

// ClaimDue 认领到期项（单语句 UPDATE...RETURNING——与 SQLite 同语义）。
func (r *PostgresQueueRepo) ClaimDue(ctx context.Context, now time.Time, limit int) ([]*QueueItem, error) {
	rows, err := r.q.ClaimDueQueueItems(ctx, dbgen.ClaimDueQueueItemsParams{
		UpdatedAt:     now,
		NextAttemptAt: now,
		Limit:         int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("认领到期队列: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueRowToItemPG(&rows[i]))
	}
	return items, nil
}

// MarkResult 回写单次尝试结果（失败保持 in_flight 由 Stale 收敛）。
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
		return fmt.Errorf("回写投递结果: 队列行 %d 不存在", id)
	}
	return nil
}

// ReclaimStale 崩溃恢复（in_flight 超时→pending）。
func (r *PostgresQueueRepo) ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error) {
	now := time.Now().UTC()
	res, err := r.q.ReclaimStaleQueueItems(ctx, dbgen.ReclaimStaleQueueItemsParams{
		UpdatedAt:   now,
		UpdatedAt_2: now.Add(-olderThan),
	})
	if err != nil {
		return 0, fmt.Errorf("回收崩溃残留队列: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
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
		RetFull:       it.RetFull, // F-L3：RET=FULL 持久化
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		return fmt.Errorf("插入队列行: %w", err)
	}
	return nil
}

// queueRowToItemPG PostgreSQL 行 → 域类型。
func queueRowToItemPG(row *dbgen.DeliveryQueue) *QueueItem {
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
		RetFull:       row.RetFull, // F-L3
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}
