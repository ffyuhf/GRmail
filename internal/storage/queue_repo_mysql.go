// Package storage queue 域 MySQL 实现（U11 Q2-A 三套生成；契约 2.1 四方法签名零变更）。
// 依据：U11 计划书 1.5④——MySQL 无 UPDATE...RETURNING，ClaimDue 改事务两步；
// 队列防丢信收口批（G2 批准 2026-10-07 08:41:07）：
//   - F3（A-14④）：回读判据由 updated_at=now 改 claim_token=?——纳秒同值/时钟回拨
//     的理论竞态根治（token 唯一归属，并发批次互不串读）
//   - F1（A-14②）：MarkResult 受 in_flight 守卫——迟到回写 0 行返回 ErrQueueStaleWrite
//   - F2（A-14③）：ReclaimStale 退避阶梯重置（defaultReclaimBackoff——sqlite 实现定义共享）
//   - F4/F5：TouchClaim/MarkDSNSent/ListFailedDSNPending（QueueClaimOps 窄视图）
//
// 覆盖条目：FR-014（TC-014 queue 域 MySQL 格；CON-004 四不变量实测锚点）+NFR-007。
// 修改历史：
//
//	2026-09-20 05:35:00 | 新增 | U11 三库验收（计划书步骤 4）
//	2026-10-07 08:52:00 | 修正 | 队列防丢信收口批 F1/F2/F3/F4/F5（迁移 00012）
//	2026-10-07 15:20:00 | 扩展 | 传输安全合规批 F1/A-9：SkipTLSPolicy 列写入/读回
//	（迁移 00013；G2 批准 2026-10-07 15:13:06；rfc8460 §5.3.1）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/mysql"
)

// 编译期断言：契约 2.1 接口实现锁定（MySQL 形态）+ F4/F5 窄视图。
var (
	_ QueueRepo     = (*MySQLQueueRepo)(nil)
	_ QueueClaimOps = (*MySQLQueueRepo)(nil)
)

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
// 并写 claim_token+heartbeat_at → 同事务按 claim_token 回读认领集（F3：token 唯一
// 归属消除按时刻回读的同值竞态；两 worker 并发认领由 UPDATE 的 IN 子查询天然互斥）。
func (r *MySQLQueueRepo) ClaimDue(ctx context.Context, now time.Time, limit int) ([]*QueueItem, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("开启认领事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)

	token := newClaimToken()
	if _, err = qtx.ClaimDueQueueItemsUpdate(ctx, dbgen.ClaimDueQueueItemsUpdateParams{
		ClaimToken:    sql.NullString{String: token, Valid: true},
		HeartbeatAt:   sql.NullTime{Time: now, Valid: true},
		UpdatedAt:     now,
		NextAttemptAt: now,
		Limit:         int32(limit),
	}); err != nil {
		return nil, fmt.Errorf("认领到期队列（更新）: %w", err)
	}
	rows, err := qtx.SelectClaimedQueueItems(ctx, sql.NullString{String: token, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("回读认领队列: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交认领事务: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueClaimRowToItemMySQL(&rows[i]))
	}
	return items, nil
}

// TouchClaim 心跳续期（F4：token+in_flight 双守卫；0 行=行已回写/回收自然失效）。
func (r *MySQLQueueRepo) TouchClaim(ctx context.Context, token string) error {
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

// MarkResult 回写单次尝试结果（失败保持 in_flight 由 Stale 收敛——流程设计 3.2 不变量 4；
// F1 守卫：迟到回写返回 ErrQueueStaleWrite）。
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
		return ErrQueueStaleWrite // F1：迟到回写作废
	}
	return nil
}

// ReclaimStale 崩溃恢复（in_flight 超时→pending；F2 退避阶梯重置+F4 COALESCE 判据）。
func (r *MySQLQueueRepo) ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error) {
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
func (r *MySQLQueueRepo) MarkDSNSent(ctx context.Context, id int64) error {
	if _, err := r.q.MarkQueueDSNSent(ctx, dbgen.MarkQueueDSNSentParams{
		UpdatedAt: time.Now().UTC(),
		ID:        id,
	}); err != nil {
		return fmt.Errorf("置位 DSN 回执: %w", err)
	}
	return nil
}

// ListFailedDSNPending 重扫批查（F5/B-R2：failed 且 DSN 未发行）。
func (r *MySQLQueueRepo) ListFailedDSNPending(ctx context.Context, limit int) ([]*QueueItem, error) {
	rows, err := r.q.ListFailedDSNPending(ctx, int32(limit))
	if err != nil {
		return nil, fmt.Errorf("批查 DSN 待发行: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueListRowToItemMySQL(&rows[i]))
	}
	return items, nil
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

// nullIfZeroInt32 零值 int → NULL（last_smtp_code 可空列——MySQL INT 生成 NullInt32）。
func nullIfZeroInt32(n int) sql.NullInt32 {
	return sql.NullInt32{Int32: int32(n), Valid: n != 0}
}

// queueClaimRowToItemMySQL ClaimDue 回读行 → 域类型（F3/F4：含 claim_token）。
func queueClaimRowToItemMySQL(row *dbgen.SelectClaimedQueueItemsRow) *QueueItem {
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

// queueListRowToItemMySQL ListFailedDSNPending 行 → 域类型（F5）。
func queueListRowToItemMySQL(row *dbgen.ListFailedDSNPendingRow) *QueueItem {
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
