// Package storage queue 域 MySQL 实现（U11 Q2-A 三套生成；契约 2.1 四方法签名零变更）。
// 依据：U11 计划书 1.5④——MySQL 无 UPDATE...RETURNING，ClaimDue 改事务两步：
// 派生表 UPDATE 置 in_flight → 同事务按更新标记（status+updated_at）回读认领集；
// 语义等价基准=关键流程设计 3.2 四不变量（claim 转移原子/不重叠/Stale 回收/回写失败保持态）。
// 覆盖条目：FR-014（TC-014 queue 域 MySQL 格；CON-004 四不变量实测锚点）。
// 修改历史：
//
//	2026-09-20 05:35:00 | 新增 | U11 三库验收（计划书步骤 4）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/mysql"
)

// 编译期断言：契约 2.1 接口实现锁定（MySQL 形态）。
var _ QueueRepo = (*MySQLQueueRepo)(nil)

// MySQLQueueRepo QueueRepo 的 MySQL 实现。
type MySQLQueueRepo struct {
	db *sql.DB
	q  *dbgen.Queries
	ck constraintChecker
}

// NewMySQLQueueRepo 构造投递队列仓储（MySQL）。
// 参数：db 已迁移就绪的 MySQL 连接。返回：仓储实例。
func NewMySQLQueueRepo(db *sql.DB) *MySQLQueueRepo {
	return &MySQLQueueRepo{db: db, q: dbgen.New(db), ck: mysqlChecker{}}
}

// Enqueue 单事务批量入队（语义同 SQLite 实现）。
func (r *MySQLQueueRepo) Enqueue(ctx context.Context, items []*QueueItem) error {
	return withTxCompat(ctx, r.db, func(tx *sql.Tx) error {
		qtx := r.q.WithTx(tx)
		now := time.Now().UTC()
		for _, it := range items {
			if err := insertQueueRowMySQL(ctx, qtx, it, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// ClaimDue 认领到期项：事务两步（1.5④）——UPDATE（派生表 LIMIT 截断批量）置 in_flight
// →同事务回读（status='in_flight' AND updated_at=认领标记）；两 worker 并发认领由
// UPDATE 的 IN 子查询天然互斥（行被首事务锁定）。
func (r *MySQLQueueRepo) ClaimDue(ctx context.Context, now time.Time, limit int) ([]*QueueItem, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("开启认领事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)

	if _, err = qtx.ClaimDueQueueItemsUpdate(ctx, dbgen.ClaimDueQueueItemsUpdateParams{
		UpdatedAt:     now,
		NextAttemptAt: now,
		Limit:         int32(limit),
	}); err != nil {
		return nil, fmt.Errorf("认领到期队列（更新）: %w", err)
	}
	rows, err := qtx.SelectClaimedQueueItems(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("回读认领队列: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交认领事务: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueRowToItemMySQL(&rows[i]))
	}
	return items, nil
}

// MarkResult 回写单次尝试结果（失败保持 in_flight 由 Stale 收敛——流程设计 3.2 不变量 4）。
func (r *MySQLQueueRepo) MarkResult(ctx context.Context, id int64, r2 AttemptResult) error {
	status := QueueDeferred
	switch r2.Status {
	case AttemptSent:
		status = QueueSent
	case AttemptFailed:
		status = QueueFailed
	}
	nextAt := r2.NextAttemptAt
	if nextAt.IsZero() {
		nextAt = time.Unix(1, 0).UTC() // 终态零值兜底（MySQL 严格模式拒 0000-00-00；终态不参与调度——语义无害）
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

// ReclaimStale 崩溃恢复（in_flight 超时→pending，幂等重试）。
func (r *MySQLQueueRepo) ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error) {
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

// StoreSubmission 提交入队单事务（messages 单行→queue 逐收件人多行；Blob 调用方先行）。
func (r *MySQLQueueRepo) StoreSubmission(ctx context.Context, txmeta *SubmissionMeta) error {
	return withTxCompat(ctx, r.db, func(tx *sql.Tx) error {
		qtx := r.q.WithTx(tx)
		now := time.Now().UTC()
		msgPK, err := insertMessageRowMySQL(ctx, qtx, txmeta.Message, now)
		if err != nil {
			return err
		}
		for _, it := range txmeta.Items {
			it.MessageID = msgPK
			if err = insertQueueRowMySQL(ctx, qtx, it, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// ───────────────────────── MySQL 辅助 ─────────────────────────

// insertQueueRowMySQL 插入 delivery_queue 行（入队与提交事务共用）。
func insertQueueRowMySQL(ctx context.Context, qtx *dbgen.Queries, it *QueueItem, now time.Time) error {
	nextAt := it.NextAttemptAt
	if nextAt.IsZero() {
		nextAt = time.Now().UTC() // 缺省立即可投递
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

// nullIfZeroInt32 零值 int → NULL（last_smtp_code 可空列——MySQL INT 生成 NullInt32）。
func nullIfZeroInt32(n int) sql.NullInt32 {
	return sql.NullInt32{Int32: int32(n), Valid: n != 0}
}

// queueRowToItemMySQL MySQL 行 → 域类型（时间直赋值）。
func queueRowToItemMySQL(row *dbgen.DeliveryQueue) *QueueItem {
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
