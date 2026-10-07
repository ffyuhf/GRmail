// Package storage 追加投递队列仓储：QueueRepo 接口族与 SQLite 实现（出站防丢信路径）。
// 依据：模块接口契约 v1.2.0 第 2.1 节（QueueRepo 四方法签名逐字复刻；QueueItem/
// AttemptResult 为契约引用未定义类型的代码层补充定义——沿 v1.0.0 IncomingMail/Envelope
// 落位先例，U5 计划书 1.5⑬）；
// 数据库表结构 v2.0.0 第 3.7 节（delivery_queue 五态 CHECK 约束与调度主路径索引＋
// v2.0.0 三列增量 claim_token/heartbeat_at/dsn_sent——迁移 00012）；
// 关键流程设计第三章 3.2（队列状态机：pending→in_flight→sent/deferred/failed；
// in_flight 崩溃回收 ReclaimStale；回写失败保持原态防重复投递）。
// 覆盖条目：FR-005（发信投递）/NFR-007/CON-004（出站防丢信）。
// 传输安全合规批（F1/A-9）：QueueItem 增 SkipTLSPolicy 字段+迁移 00013 列写入/读回
//   - rfc8460 §5.3.1 L1050-1051「when sending failure reports via SMTP, Sending MTAs
//     MUST NOT honor MTA-STS or DANE TLSA failures」——TLS-RPT 报告行投递链豁免承载
//   - 之前：
//
// 队列防丢信收口批（F1/F2/F4/F5）：
//   - F1（A-14②）：MarkResult 受 status='in_flight' 守卫——迟到回写（Stale 回收重投后
//     旧 worker 的结果）0 行受影响，返回 ErrQueueStaleWrite 由调用方 Warn 丢弃
//   - F2（A-14③）：ReclaimStale 重置 next_attempt_at=now+退避(attempts)——崩溃批量恢复
//     防重投突发（退避阶梯 t0..t6 与 worker.backoffDelay 缺省档镜像；repo 层缺省函数
//     承载——接口签名守恒，config 非缺省档时梯度近似无害）
//   - F4（A-14①④/D1）：ClaimDue 原子写 claim_token+heartbeat_at；TouchClaim 每 MX
//     尝试前续期；Stale 判据改 COALESCE(heartbeat_at, updated_at)——在途投递持续续期
//     不再被误回收重投
//   - F5（B-R2）：MarkDSNSent/ListFailedDSNPending——failed 必产 DSN 的强保证重扫判据
//
// 修改历史：
//
//	2026-09-17 11:52:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 5，G2 批准 2026-09-17 11:39:21）
//	2026-10-07 08:50:00 | 修正 | 队列防丢信收口批 F1/F2/F4/F5（G2 批准 2026-10-07 08:41:07；
//	评审报告 7.2 批 3+复核修正口径；迁移 00012；契约 v1.32.0 注记级升版）
//	2026-10-07 15:20:00 | 扩展 | 传输安全合规批 F1/A-9：SkipTLSPolicy 字段+迁移 00013
//	列写入/读回（G2 批准 2026-10-07 15:13:06；rfc8460 §5.3.1 MUST NOT honor）
package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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

// ErrQueueStaleWrite 迟到回写哨兵（F1）：MarkResult 时行已不在 in_flight（被 Stale
// 回收或不存在）——结果自然作废，调用方 Warn 丢弃；非错误（防丢信语义：该次投递的
// 结果已由回收重投链承载）。
var ErrQueueStaleWrite = errors.New("队列行已不在投递中（迟到回写按作废丢弃）")

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
	// SkipTLSPolicy F1/A-9：TLS-RPT 报告行豁免标记（true=投递链跳过 MTA-STS/DANE
	// 策略判定——rfc8460 §5.3.1 MUST NOT honor；TLS 本身仍机会升级；迁移 00013 持久列
	// ——入队/重启/重试周期全程保持；普通邮件恒 false 既有判定零变化）
	SkipTLSPolicy bool
	ClaimToken    string // F4：本次认领令牌（ClaimDue 写入；TouchClaim 归属校验；回写/回收清空）
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

// ───────────────────────── 认领/心跳/DSN 重扫窄视图（F4/F5——具体类型方法族） ─────────────────────────

// QueueClaimOps 队列防丢信收口批扩展操作窄视图（F4/F5；mail 域 worker 消费——
// 具体类型方法族的接口视图，沿 StoreSubmission 不入 QueueRepo 契约的先例：
// 契约 v1.32.0 注记级承载，四方法签名零变更保持）。
type QueueClaimOps interface {
	// TouchClaim 心跳续期（每 MX 尝试前调用；token 归属校验——仅认领者可续）。
	TouchClaim(ctx context.Context, token string) error
	// MarkDSNSent 置位 DSN 回执（emitDSN 成功后调用；幂等守卫）。
	MarkDSNSent(ctx context.Context, id int64) error
	// ListFailedDSNPending 重扫批查（failed 且 DSN 未发——启动+周期补发源）。
	ListFailedDSNPending(ctx context.Context, limit int) ([]*QueueItem, error)
}

// 编译期断言：SQLite 实现同时满足窄视图。
var _ QueueClaimOps = (*SQLiteQueueRepo)(nil)

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

// newClaimToken 生成认领令牌（F4：CSPRNG 16B→32 位 hex；单批次共用一令牌——
// 同批多行归属一致，回写时随守卫一并清空）。
func newClaimToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// CSPRNG 失败不可静默：以时间熵兜底并保留可观测性（极罕见路径）
		return fmt.Sprintf("fallback-%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// ClaimDue 认领到期项：单条 UPDATE 原子完成 pending→in_flight 转移并返回认领行集
// （SQLite UPDATE...RETURNING；子查询 LIMIT 截断批量——两 worker 并发认领不重叠）。
// F4：转移同时写入 claim_token（CSPRNG）+heartbeat_at（=updated_at 起搏）——Stale
// 判据 COALESCE(heartbeat_at, updated_at)，在途投递经 TouchClaim 持续续期不被误回收。
// 参数：ctx 上下文；now 当前时刻（与 next_attempt_at 比较）；limit 批量上限。
// 返回：本次认领的队列项（已置 in_flight，含 ClaimToken）。
func (r *SQLiteQueueRepo) ClaimDue(ctx context.Context, now time.Time, limit int) ([]*QueueItem, error) {
	token := newClaimToken()
	rows, err := r.q.ClaimDueQueueItems(ctx, dbgen.ClaimDueQueueItemsParams{
		ClaimToken:    token,
		HeartbeatAt:   formatTimestamp(now),
		UpdatedAt:     formatTimestamp(now),
		NextAttemptAt: formatTimestamp(now),
		Limit:         int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("认领到期队列: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueClaimRowToItem(&rows[i]))
	}
	return items, nil
}

// TouchClaim 心跳续期（F4：token+in_flight 双守卫——仅认领者且行仍在途时续期；
// 0 行=行已被回写/回收，续期自然失效无需报错）。
// 参数：ctx 上下文；token 认领令牌（ClaimDue 写入的批次令牌）。
func (r *SQLiteQueueRepo) TouchClaim(ctx context.Context, token string) error {
	now := time.Now().UTC()
	if _, err := r.q.HeartbeatQueueClaim(ctx, dbgen.HeartbeatQueueClaimParams{
		HeartbeatAt: formatTimestamp(now),
		UpdatedAt:   formatTimestamp(now),
		ClaimToken:  token,
	}); err != nil {
		return fmt.Errorf("续期投递心跳: %w", err)
	}
	return nil
}

// MarkResult 回写单次尝试结果：按 r.Status 三态落库（sent/failed 终态；deferred
// 携带 r.NextAttemptAt 退避调度）——退避计算口径归调用方（config.DeliveryConf
// 快照在 mail 域 worker，U5 计划书 1.5⑩）。写失败时上层保留 in_flight，由
// ReclaimStale 幂等收敛（不重复投递判定的存储侧锚点，TC-021 判定②）。
// F1（A-14②）：WHERE 受 status='in_flight' 守卫——迟到回写 0 行受影响返回
// ErrQueueStaleWrite（调用方 Warn 丢弃，禁止覆盖回收后的新状态）。
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
		return ErrQueueStaleWrite // F1：行已不在 in_flight（回收/不存在）——迟到回写作废
	}
	return nil
}

// defaultReclaimBackoff 回收重置退避阶梯（F2：与 worker.backoffDelay 缺省档
// base=60s/factor=2/cap=3600s 镜像的 storage 侧纯函数——接口签名守恒的代价：
// config 自定义非缺省档时梯度近似〔重置目的为防突发，近似无害——CHANGE5 登记〕）。
// 返回：attempts 0..5 及 6+（cap 档）共 7 档延迟。
func defaultReclaimBackoff() [7]time.Duration {
	ladder := [7]time.Duration{}
	delay := 60 * time.Second
	for i := 0; i < len(ladder); i++ {
		if delay >= 3600*time.Second {
			delay = 3600 * time.Second
		}
		ladder[i] = delay
		delay *= 2
	}
	return ladder
}

// ReclaimStale 崩溃恢复：in_flight 且 COALESCE(heartbeat_at, updated_at) 早于阈值
// → pending（重启即调用；幂等由 blob 去重+对端 Message-ID 去重兜底，流程设计 3.2
// 不变量 1）。F2（A-14③）：回收同时按 attempts 退避阶梯重置 next_attempt_at——
// 崩溃批量恢复的行错峰到期，不形成立即重投突发；F4：认领/心跳簿记列同清。
// 参数：ctx 上下文；olderThan 判定超时（U5 计划书 1.5⑦：10min）。返回：恢复行数。
func (r *SQLiteQueueRepo) ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error) {
	now := time.Now().UTC()
	ladder := defaultReclaimBackoff()
	var caseAt [7]string
	for i, d := range ladder {
		caseAt[i] = formatTimestamp(now.Add(d))
	}
	res, err := r.q.ReclaimStaleQueueItems(ctx, dbgen.ReclaimStaleQueueItemsParams{
		UpdatedAt:       formatTimestamp(now),
		NextAttemptAt:   caseAt[0],
		NextAttemptAt_2: caseAt[1],
		NextAttemptAt_3: caseAt[2],
		NextAttemptAt_4: caseAt[3],
		NextAttemptAt_5: caseAt[4],
		NextAttemptAt_6: caseAt[5],
		NextAttemptAt_7: caseAt[6],
		HeartbeatAt:     formatTimestamp(now.Add(-olderThan)), // Stale 阈值（COALESCE 判据参数）
	})
	if err != nil {
		return 0, fmt.Errorf("回收崩溃残留队列: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkDSNSent 置位 DSN 回执（F5/B-R2：emitDSN 成功后调用；failed+未置位双守卫幂等）。
// 参数：ctx 上下文；id 队列行。
func (r *SQLiteQueueRepo) MarkDSNSent(ctx context.Context, id int64) error {
	if _, err := r.q.MarkQueueDSNSent(ctx, dbgen.MarkQueueDSNSentParams{
		UpdatedAt: formatTimestamp(time.Now().UTC()),
		ID:        id,
	}); err != nil {
		return fmt.Errorf("置位 DSN 回执: %w", err)
	}
	return nil
}

// ListFailedDSNPending 重扫批查（F5/B-R2：failed 且 dsn_sent=0——进程在 MarkResult
// 成功后、emitDSN 完成前崩溃的行；启动+周期补发源，逐行补发后 MarkDSNSent 收口）。
// 参数：ctx 上下文；limit 批量上限。返回：待补发 DSN 的队列行。
func (r *SQLiteQueueRepo) ListFailedDSNPending(ctx context.Context, limit int) ([]*QueueItem, error) {
	rows, err := r.q.ListFailedDSNPending(ctx, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("批查 DSN 待发行: %w", err)
	}
	items := make([]*QueueItem, 0, len(rows))
	for i := range rows {
		items = append(items, queueListRowToItem(&rows[i]))
	}
	return items, nil
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
		RetFull:       it.RetFull,                    // F-L3：RET=FULL 持久化（缺省 false=HDRS/未指定口径）
		SkipTlsPolicy: boolToInt64(it.SkipTLSPolicy), // F1/A-9：报告行豁免标记持久化（SQLite INTEGER 列 sqlc 推断 int64——bool 转换）
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		return fmt.Errorf("插入队列行: %w", err)
	}
	return nil
}

// queueClaimRowToItem ClaimDue RETURNING 行 → 域类型（F4：含 claim_token 列读）。
func queueClaimRowToItem(row *dbgen.ClaimDueQueueItemsRow) *QueueItem {
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
		RetFull:       row.RetFull,            // F-L3
		SkipTLSPolicy: row.SkipTlsPolicy != 0, // F1/A-9：豁免标记读回（SQLite INTEGER→bool）
		ClaimToken:    stringOfAny(row.ClaimToken),
		CreatedAt:     mustParseTimestamp(row.CreatedAt),
		UpdatedAt:     mustParseTimestamp(row.UpdatedAt),
	}
}

// queueListRowToItem ListFailedDSNPending 行 → 域类型（F5：重扫消费）。
func queueListRowToItem(row *dbgen.ListFailedDSNPendingRow) *QueueItem {
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
		RetFull:       row.RetFull,
		SkipTLSPolicy: row.SkipTlsPolicy != 0, // F1/A-9：豁免标记读回（SQLite INTEGER→bool）
		ClaimToken:    stringOfAny(row.ClaimToken),
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

//（boolToInt64 复用 session_repo.go 既有定义——SQLite 布尔列 int64 转换先例）
