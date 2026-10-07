// storage 域投递队列仓储集成单测（NFR-015：临时 SQLite 库独立驱动，零网络端点）。
// 覆盖锚点：流程设计 3.2（ClaimDue 原子认领不重叠/MarkResult 三态/ReclaimStale 崩溃
// 恢复）、数据模型 1.3+U5 计划书 1.5①（StoreSubmission 单事务：messages+queue 原子）、
// Q4-A（envelope_from "<>" 字面量 NOT NULL 兼容）。
// 修改历史：
//
//	2026-09-17 11:55:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 5 检查点）
//	2026-10-07 09:14:00 | 适配 | 队列防丢信收口批 F4：TestReclaimStale 回拨
//	增 heartbeat_at 列（Stale 判据改 COALESCE(heartbeat_at, updated_at)——仅回拨
//	updated_at 不再触发回收，心跳续期防误回收语义的正向体现；G2 批准 2026-10-07
//	01:03:52；断言语义保持——超时→pending 恢复链不变）
package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
)

// newQueueRepo 临时库迁移后构造队列仓储。
func newQueueRepo(t *testing.T) *SQLiteQueueRepo {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u5test.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return NewSQLiteQueueRepo(db)
}

// TestStoreSubmissionAtomic 提交入队单事务：messages 单行+逐收件人队列行；
// 队列行外键回填（DSN 追溯口径）。
func TestStoreSubmissionAtomic(t *testing.T) {
	repo := newQueueRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	meta := &SubmissionMeta{
		Message: sampleMeta("2222222222222222222222222222222222222222222222222222222222222222"),
		Items: []*QueueItem{
			{EnvelopeFrom: "a@t.io", RcptTo: "x@ext.io", Status: QueuePending, NextAttemptAt: now},
			{EnvelopeFrom: "a@t.io", RcptTo: "y@ext.io", Status: QueuePending, NextAttemptAt: now},
		},
	}
	if err := repo.StoreSubmission(ctx, meta); err != nil {
		t.Fatalf("StoreSubmission: %v", err)
	}
	var msgRows, queueRows int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&msgRows); err != nil || msgRows != 1 {
		t.Fatalf("messages 行数应 1: n=%d err=%v", msgRows, err)
	}
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM delivery_queue WHERE status='pending'`).Scan(&queueRows); err != nil || queueRows != 2 {
		t.Fatalf("pending 队列行数应 2: n=%d err=%v", queueRows, err)
	}
	for _, it := range meta.Items {
		if it.MessageID == 0 {
			t.Fatal("队列行 MessageID 外键应回填")
		}
	}
}

// TestClaimDueAtomicAndLimit 认领原子性：到期项 pending→in_flight、limit 截断、
// 未到期不认领；两次认领不重叠（两 worker 并发安全锚点）。
func TestClaimDueAtomicAndLimit(t *testing.T) {
	repo := newQueueRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	meta := &SubmissionMeta{
		Message: sampleMeta("3333333333333333333333333333333333333333333333333333333333333333"),
		Items: []*QueueItem{
			{EnvelopeFrom: "a@t.io", RcptTo: "r1@ext.io", NextAttemptAt: now},
			{EnvelopeFrom: "a@t.io", RcptTo: "r2@ext.io", NextAttemptAt: now},
			{EnvelopeFrom: "a@t.io", RcptTo: "late@ext.io", NextAttemptAt: now.Add(time.Hour)}, // 未到期
		},
	}
	if err := repo.StoreSubmission(ctx, meta); err != nil {
		t.Fatalf("入队: %v", err)
	}
	batch1, err := repo.ClaimDue(ctx, now, 1)
	if err != nil {
		t.Fatalf("第一批认领: %v", err)
	}
	if len(batch1) != 1 || batch1[0].Status != QueueInFlight {
		t.Fatalf("第一批应认领 1 项 in_flight: %+v", batch1)
	}
	batch2, err := repo.ClaimDue(ctx, now, 10)
	if err != nil {
		t.Fatalf("第二批认领: %v", err)
	}
	if len(batch2) != 1 { // 仅剩另一到期项（late 未到期不应认领）
		t.Fatalf("第二批应认领 1 项: %d", len(batch2))
	}
	if batch2[0].RcptTo == batch1[0].RcptTo {
		t.Fatalf("两次认领重叠: %s", batch1[0].RcptTo)
	}
	if batch2[0].RcptTo == "late@ext.io" {
		t.Fatal("未到期项不应被认领")
	}
}

// TestMarkResultThreeStates 结果三态回写：sent 终态/deferred 退避字段/failed 终态
func TestMarkResultThreeStates(t *testing.T) {
	repo := newQueueRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	meta := &SubmissionMeta{
		Message: sampleMeta("4444444444444444444444444444444444444444444444444444444444444444"),
		Items:   []*QueueItem{{EnvelopeFrom: "a@t.io", RcptTo: "r@ext.io", NextAttemptAt: now}},
	}
	if err := repo.StoreSubmission(ctx, meta); err != nil {
		t.Fatalf("入队: %v", err)
	}
	items, err := repo.ClaimDue(ctx, now, 5)
	if err != nil || len(items) != 1 {
		t.Fatalf("认领: %v %d", err, len(items))
	}
	next := now.Add(2 * time.Minute)
	if err = repo.MarkResult(ctx, items[0].ID, AttemptResult{
		Status: AttemptDeferred, SMTPCode: 451, Error: "temp fail",
		Attempts: 1, NextAttemptAt: next,
	}); err != nil {
		t.Fatalf("回写 deferred: %v", err)
	}
	row, err := repo.q.GetQueueItem(ctx, items[0].ID)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if row.Status != string(QueueDeferred) || row.Attempts != 1 || row.LastSmtpCode.Int64 != 451 {
		t.Fatalf("deferred 行不符: %+v", row)
	}
	if got := mustParseTimestamp(row.NextAttemptAt); !got.Equal(next.Truncate(time.Second)) {
		t.Fatalf("退避时刻不符: %v != %v", got, next) // formatTimestamp RFC3339 秒级精度，按截断比对
	}
	// deferred 到期后再认领→sent 终态
	final, err := repo.ClaimDue(ctx, next.Add(time.Second), 5)
	if err != nil || len(final) != 1 {
		t.Fatalf("退避到期认领: %v %d", err, len(final))
	}
	if err = repo.MarkResult(ctx, final[0].ID, AttemptResult{Status: AttemptSent, Attempts: 2}); err != nil {
		t.Fatalf("回写 sent: %v", err)
	}
	row, _ = repo.q.GetQueueItem(ctx, final[0].ID)
	if row.Status != string(QueueSent) {
		t.Fatalf("sent 终态不符: %s", row.Status)
	}
	// failed 路径（`<>` 发件人字面量兼容，Q4-A）
	meta2 := &SubmissionMeta{
		Message: sampleMeta("5555555555555555555555555555555555555555555555555555555555555555"),
		Items:   []*QueueItem{{EnvelopeFrom: "<>", RcptTo: "z@t.io", NextAttemptAt: now}},
	}
	if err = repo.StoreSubmission(ctx, meta2); err != nil {
		t.Fatalf("null sender 入队: %v", err)
	}
	f2, err := repo.ClaimDue(ctx, now, 5)
	if err != nil || len(f2) != 1 || f2[0].EnvelopeFrom != "<>" {
		t.Fatalf("null sender 认领: %v %+v", err, f2)
	}
	if err = repo.MarkResult(ctx, f2[0].ID, AttemptResult{Status: AttemptFailed, SMTPCode: 550, Error: "no such user", Attempts: 9}); err != nil {
		t.Fatalf("回写 failed: %v", err)
	}
	row, _ = repo.q.GetQueueItem(ctx, f2[0].ID)
	if row.Status != string(QueueFailed) {
		t.Fatalf("failed 终态不符: %s", row.Status)
	}
}

// TestReclaimStale 崩溃恢复：in_flight 超时→pending；未超时不动
func TestReclaimStale(t *testing.T) {
	repo := newQueueRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	meta := &SubmissionMeta{
		Message: sampleMeta("6666666666666666666666666666666666666666666666666666666666666666"),
		Items:   []*QueueItem{{EnvelopeFrom: "a@t.io", RcptTo: "r@ext.io", NextAttemptAt: now}},
	}
	if err := repo.StoreSubmission(ctx, meta); err != nil {
		t.Fatalf("入队: %v", err)
	}
	if _, err := repo.ClaimDue(ctx, now, 5); err != nil {
		t.Fatalf("认领: %v", err)
	}
	// 未超时（阈值 10min，刚认领）：恢复 0 行
	n, err := repo.ReclaimStale(ctx, 10*time.Minute)
	if err != nil || n != 0 {
		t.Fatalf("未超时应恢复 0 行: n=%d err=%v", n, err)
	}
	// 人工回拨 updated_at/heartbeat_at 至 11 分钟前（模拟崩溃残留）
	// 队列防丢信收口批 F4 适配：Stale 判据改 COALESCE(heartbeat_at, updated_at)
	// ——认领时 heartbeat_at 非空成为判据主位，回拨须两列同步（仅回拨 updated_at
	// 不再触发回收，即「在途投递持续续期不被误回收」语义的正向体现）
	if _, err = repo.db.Exec(`UPDATE delivery_queue SET updated_at = ?, heartbeat_at = ?`,
		formatTimestamp(now.Add(-11*time.Minute)), formatTimestamp(now.Add(-11*time.Minute))); err != nil {
		t.Fatalf("回拨时间: %v", err)
	}
	n, err = repo.ReclaimStale(ctx, 10*time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("超时应恢复 1 行: n=%d err=%v", n, err)
	}
	row, _ := repo.q.GetQueueItem(ctx, meta.Items[0].MessageID) // 以外键行主键再查
	_ = row
	var status string
	if err = repo.db.QueryRow(`SELECT status FROM delivery_queue`).Scan(&status); err != nil || status != string(QueuePending) {
		t.Fatalf("恢复后应回 pending: %s err=%v", status, err)
	}
}

// TestEnqueueBatchAtomic Enqueue 批量原子性：单事务多行
func TestEnqueueBatchAtomic(t *testing.T) {
	repo := newQueueRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// 先造 messages 行供外键
	meta := &SubmissionMeta{
		Message: sampleMeta("7777777777777777777777777777777777777777777777777777777777777777"),
		Items:   []*QueueItem{{EnvelopeFrom: "a@t.io", RcptTo: "keep@ext.io", NextAttemptAt: now}},
	}
	if err := repo.StoreSubmission(ctx, meta); err != nil {
		t.Fatalf("入队: %v", err)
	}
	items := []*QueueItem{
		{MessageID: meta.Items[0].MessageID, EnvelopeFrom: "a@t.io", RcptTo: "b1@ext.io"},
		{MessageID: meta.Items[0].MessageID, EnvelopeFrom: "a@t.io", RcptTo: "b2@ext.io"},
	}
	if err := repo.Enqueue(ctx, items); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	var n int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM delivery_queue WHERE rcpt_to LIKE 'b%'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("批量行数应 2: n=%d err=%v", n, err)
	}
}
