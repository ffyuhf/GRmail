// Package storage 追加投递队列仓储：QueueRepo 接口族与 SQLite 实现（出站防丢信路径）。
// 依据：模块接口契约 v1.2.0 第 2.1 节（QueueRepo 四方法签名逐字复刻；QueueItem/
// AttemptResult 为契约引用未定义类型的代码层补充定义——沿 v1.0.0 IncomingMail/Envelope
// 落位先例，U5 计划书 1.5⑬）；
// 数据库表结构 v1.0.0 第 3.7 节（delivery_queue 五态 CHECK 约束与调度主路径索引）＋
// 1.3 节（提交路径双写：Blob 先、messages+delivery_queue 单事务后——U5 计划书 1.5①）；
// 关键流程设计 v1.0.0 第三章 3.2（队列状态机：pending→in_flight→sent/deferred/failed；
// in_flight 崩溃回收 ReclaimStale；回写失败保持原态防重复投递——MarkResult 仅按 id
// 单行更新，失败即上层保留 in_flight 由 Stale 收敛）。
// 覆盖条目：FR-005（发信投递）/NFR-007/CON-004（出站防丢信）。
// 修改历史：
//
//	2026-09-17 11:52:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 5，G2 批准 2026-09-17 11:39:21）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// ───────────────────────── 域类型（数据模型 3.7 + 契约 2.1 引用补充） ─────────────────────────

// QueueStatus 队列状态机五态（流程设计 3.2；delivery_queue.status CHECK 值域）。
type QueueStatus string

const (
	QueuePending  QueueStatus = "pending"   // 待投递（Enqueue 初始态）
	QueueInFlight QueueStatus = "in_flight" // worker 已认领（投递进行中）
	QueueDeferred QueueStatus = "deferred"  // 临时失败退避等待（next_attempt_at 到期回认领）
	QueueSent     QueueStatus = "sent"      // 对端 250 终态
	QueueFailed   QueueStatus = "failed"    // 5xx 永久拒绝或超重试上限（必产生 DSN）
)

// AttemptStatus 单次投递尝试结果分类（MarkResult 语义；对应流程设计 3.2 三条出边）。
type AttemptStatus string

const (
	AttemptSent     AttemptStatus = "sent"     // 对端 250
	AttemptDeferred AttemptStatus = "deferred" // 4xx 或网络/超时/TLS 失败（可重试）
	AttemptFailed   AttemptStatus = "failed"   // 5xx 永久拒绝或超重试上限
)

// QueueItem 投递队列行（契约 2.1 QueueRepo/2.3 OutboundSender 的输入载体；
// 一收件人一队列项——数据模型 3.7 rcpt_to 列语义）。
type QueueItem struct {
	ID            int64       // 行主键
	MessageID     int64       // FK→messages（出站邮件元数据）
	EnvelopeFrom  string      // 信封发件人（DSN 场景可为 "<>" 字面量，Q4-A）
	RcptTo        string      // 单收件人地址（小写规范化）
	Status        QueueStatus // 五态
	Attempts      int         // 已尝试次数
	NextAttemptAt time.Time   // 退避调度时间
	LastSMTPCode  int         // 末次对端应答码（4xx/5xx 分类依据；网络失败为 0）
	LastError     string      // 末次错误描述
	RetFull       bool        // F-L3：rfc3461 §5.2.10 RET=FULL 持久化（MAIL 级参数经提交链传递——worker DSN 构造消费）
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AttemptResult 单次投递尝试结果（MarkResult 入参；SMTPCode 网络失败为 0；
// Attempts/NextAttemptAt 为回写伴随字段——MarkResult 契约签名保持单结果入参，
// 退避计算由调用方（mail 域 worker）完成后随本结构传入）。
type AttemptResult struct {
	Status        AttemptStatus
	SMTPCode      int       // 末次对端应答码（网络失败为 0）
	Error         string    // 末次错误描述
	Attempts      int       // 回写后的尝试计数（当前次数+1，由 worker 计算）
	NextAttemptAt time.Time // deferred 时的下次尝试时刻（终态零值）
}

// SubmissionMeta 单次提交入队事务的完整输入（U5 计划书 1.5①：messages 单行+
// delivery_queue 逐收件人多行，单事务原子提交；调用方须先完成 Blob 写入）。
type SubmissionMeta struct {
	Message MessageMeta  // 出站邮件元数据（签名/补头后的最终字节解析产物）
	Items   []*QueueItem // 逐收件人队列行输入（Status=QueuePending；ID 由插入回填）
}

// ───────────────────────── 接口族（契约 2.1 逐字） ─────────────────────────

// QueueRepo 投递队列仓储（防丢信）。
type QueueRepo interface {
	// Enqueue 批量入队（逐收件人一行；单事务原子）。
	Enqueue(ctx context.Context, items []*QueueItem) error
	// ClaimDue 认领到期项（pending→in_flight 原子转移；UPDATE...RETURNING）。
	ClaimDue(ctx context.Context, now time.Time, limit int) ([]*QueueItem, error)
	// MarkResult 回写单次尝试结果（sent/deferred/failed；失败保持 in_flight 由 Stale 收敛）。
	MarkResult(ctx context.Context, id int64, r AttemptResult) error
	// ReclaimStale 崩溃恢复（in_flight 超时→pending，幂等重试）。
	ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error)
}

// 编译期断言：契约 2.1 QueueRepo 接口实现锁定。
var _ QueueRepo = (*SQLiteQueueRepo)(nil)

// ───────────────────────── SQLite 实现 ─────────────────────────

// SQLiteQueueRepo QueueRepo 的 SQLite 实现。
type SQLiteQueueRepo struct {
	db *sql.DB
	q  *dbgen.Queries
}

// NewSQLiteQueueRepo 构造投递队列仓储。
// 参数：db 已迁移就绪的数据库连接（storage.Open 产物）。返回：仓储实例。
func NewSQLiteQueueRepo(db *sql.DB) *SQLiteQueueRepo {
	return &SQLiteQueueRepo{db: db, q: dbgen.New(db)}
}

// Enqueue 单事务批量入队（部分失败整体回滚——调用方按 ErrRetryable 语义应答）。
// 参数：ctx 上下文；items 队列行输入（ID 忽略，由插入回填）。
func (r *SQLiteQueueRepo) Enqueue(ctx context.Context, items []*QueueItem) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启入队事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)
	now := formatTimestamp(time.Now().UTC())
	for _, it := range items {
		if err = insertQueueRow(ctx, qtx, it, now); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交入队事务: %w", err)
	}
	return nil
}

// ClaimDue 认领到期项：单条 UPDATE 原子完成 pending→in_flight 转移并返回认领行集
// （SQLite UPDATE...RETURNING；子查询 LIMIT 截断批量——两 worker 并发认领不重叠）。
// 参数：ctx 上下文；now 当前时刻（与 next_attempt_at 比较）；limit 批量上限。
// 返回：本次认领的队列项（已置 in_flight）。
func (r *SQLiteQueueRepo) ClaimDue(ctx context.Context, now time.Time, limit int) ([]*QueueItem, error) {
	rows, err := r.q.ClaimDueQueueItems(ctx, dbgen.ClaimDueQueueItemsParams{
		UpdatedAt:     formatTimestamp(now),
		NextAttemptAt: formatTimestamp(now),
		Limit:         int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("认领到期队列: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueRowToItem(&rows[i]))
	}
	return items, nil
}

// MarkResult 回写单次尝试结果：按 r.Status 三态落库（sent/failed 终态；deferred
// 携带 r.NextAttemptAt 退避调度）——退避计算口径归调用方（config.DeliveryConf
// 快照在 mail 域 worker，U5 计划书 1.5⑩）。写失败时上层保留 in_flight，由
// ReclaimStale 幂等收敛（不重复投递判定的存储侧锚点，TC-021 判定②）。
// 参数：ctx 上下文；id 队列行；r 尝试结果（含 Attempts/NextAttemptAt 伴随字段）。
func (r *SQLiteQueueRepo) MarkResult(ctx context.Context, id int64, r2 AttemptResult) error {
	status := QueueDeferred
	switch r2.Status {
	case AttemptSent:
		status = QueueSent
	case AttemptFailed:
		status = QueueFailed
	}
	res, err := r.q.MarkQueueResult(ctx, dbgen.MarkQueueResultParams{
		Status:        string(status),
		Attempts:      int64(r2.Attempts),
		NextAttemptAt: formatTimestamp(r2.NextAttemptAt),
		LastSmtpCode:  nullIfZeroInt(r2.SMTPCode),
		LastError:     nullIfEmpty(r2.Error),
		UpdatedAt:     formatTimestamp(time.Now().UTC()),
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

// ReclaimStale 崩溃恢复：in_flight 且 updated_at 早于阈值 → pending（重启即调用；
// 幂等由 blob 去重+对端 Message-ID 去重兜底，流程设计 3.2 不变量 1）。
// 参数：ctx 上下文；olderThan 判定超时（U5 计划书 1.5⑦：10min）。返回：恢复行数。
func (r *SQLiteQueueRepo) ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error) {
	now := time.Now().UTC()
	res, err := r.q.ReclaimStaleQueueItems(ctx, dbgen.ReclaimStaleQueueItemsParams{
		UpdatedAt:   formatTimestamp(now),
		UpdatedAt_2: formatTimestamp(now.Add(-olderThan)),
	})
	if err != nil {
		return 0, fmt.Errorf("回收崩溃残留队列: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// StoreSubmission 提交入队单事务（U5 计划书 1.5①）：messages 单行 → delivery_queue
// 逐收件人多行；Blob 写入由调用方先行完成（数据模型 1.3 双写顺序——DB 失败仅产生
// 孤儿 Blob 由对账清理，不产生无字节队列行）。
// 参数：ctx 上下文；txmeta 提交落库输入。返回：事务失败原因（调用方按 451 应答）。
func (r *SQLiteQueueRepo) StoreSubmission(ctx context.Context, txmeta *SubmissionMeta) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启提交事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)
	now := formatTimestamp(time.Now().UTC())

	msgPK, err := insertMessageRow(ctx, qtx, txmeta.Message, now) // 复用 U4 收信路径行插入
	if err != nil {
		return err
	}
	for _, it := range txmeta.Items {
		it.MessageID = msgPK // 回填外键（供调用方 DSN 追溯）
		if err = insertQueueRow(ctx, qtx, it, now); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交入队事务: %w", err)
	}
	return nil
}

// ───────────────────────── 事务内辅助 ─────────────────────────

// insertQueueRow 插入 delivery_queue 行（入队与提交事务共用）。
func insertQueueRow(ctx context.Context, qtx *dbgen.Queries, it *QueueItem, now string) error {
	nextAt := it.NextAttemptAt
	if nextAt.IsZero() {
		nextAt = time.Now().UTC() // 缺省立即可投递（pending 首次尝试）
	}
	_, err := qtx.InsertQueueItem(ctx, dbgen.InsertQueueItemParams{
		MessageID:     it.MessageID,
		EnvelopeFrom:  it.EnvelopeFrom,
		RcptTo:        it.RcptTo,
		Status:        string(QueuePending),
		NextAttemptAt: formatTimestamp(nextAt),
		RetFull:       it.RetFull, // F-L3：RET=FULL 持久化（缺省 false=HDRS/未指定口径）
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		return fmt.Errorf("插入队列行: %w", err)
	}
	return nil
}

// queueRowToItem sqlc 行 → 域类型（时间列经 parseTimestamp 统一，错误按零值容错）。
func queueRowToItem(row *dbgen.DeliveryQueue) *QueueItem {
	return &QueueItem{
		ID:            row.ID,
		MessageID:     row.MessageID,
		EnvelopeFrom:  row.EnvelopeFrom,
		RcptTo:        row.RcptTo,
		Status:        QueueStatus(row.Status),
		Attempts:      int(row.Attempts),
		NextAttemptAt: mustParseTimestamp(row.NextAttemptAt),
		LastSMTPCode:  int(row.LastSmtpCode.Int64),
		LastError:     row.LastError.String,
		RetFull:       row.RetFull, // F-L3
		CreatedAt:     mustParseTimestamp(row.CreatedAt),
		UpdatedAt:     mustParseTimestamp(row.UpdatedAt),
	}
}

// mustParseTimestamp parseTimestamp 的单值形态（时间列恒为库内 formatTimestamp
// 产物；异常输入按零值容错并保留可观测性——队列行时间戳仅用于调度展示）。
func mustParseTimestamp(s string) time.Time {
	t, err := parseTimestamp(s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// nullIfZeroInt 零值 int → NULL（last_smtp_code 可空列口径——网络失败无应答码）。
func nullIfZeroInt(n int) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(n), Valid: n != 0}
}
