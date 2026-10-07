// storage 域队列防丢信收口批单测（F1/F2/F4/F5——NFR-015：临时 SQLite 库全离线）。
// 覆盖锚点：F1 MarkResult in_flight 守卫（迟到回写 ErrQueueStaleWrite）/F2 回收退避
// 阶梯重置（defaultReclaimBackoff 镜像断言）/F4 claim_token 往返与心跳续期防误回收/
// F5 failed 必产 DSN 重扫判据（ListFailedDSNPending/MarkDSNSent 幂等）。
// SRS 条目：NFR-007（4.5 判定②）/CON-004；TC-021 判定②存储侧锚。
// 修改历史：
//
//	2026-10-07 09:07:00 | 新建 | 队列防丢信收口批（计划书 2.3 新增测试①；
//	G2 批准 2026-10-07 01:03:52）
package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
)

// newQueueGuardRepo 临时库+迁移+队列仓储（沿 u18 测试库形态）。
// 返回：仓储；原始 db 连接（预置行/直改列的测试辅助位）。
func newQueueGuardRepo(t *testing.T) (*SQLiteQueueRepo, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: DriverSQLite, DSN: filepath.Join(t.TempDir(), "qguard.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return NewSQLiteQueueRepo(db), db
}

// seedQueueRow 预置一行可认领队列（messages 最小行+pending 队列行，next_attempt_at 已到期）。
// 返回：队列行主键。
func seedQueueRow(t *testing.T, db *sql.DB, rcpt string) int64 {
	t.Helper()
	now := formatTimestamp(time.Now().UTC())
	res, err := db.Exec("INSERT INTO messages (blob_key, raw_size, created_at) VALUES ('seed-key', 1, ?)", now)
	if err != nil {
		t.Fatalf("预置 messages 行: %v", err)
	}
	msgID, _ := res.LastInsertId()
	qr, err := db.Exec(
		"INSERT INTO delivery_queue (message_id, envelope_from, rcpt_to, status, next_attempt_at, created_at, updated_at)"+
			" VALUES (?, 'a@t.io', ?, 'pending', '2000-01-01T00:00:00Z', ?, ?)", msgID, rcpt, now, now)
	if err != nil {
		t.Fatalf("预置队列行: %v", err)
	}
	qid, _ := qr.LastInsertId()
	return qid
}

// staleHeartbeat 直改行心跳为旧值（模拟认领后投递停滞超窗——回收判据触发位）。
func staleHeartbeat(t *testing.T, db *sql.DB, id int64) {
	t.Helper()
	if _, err := db.Exec("UPDATE delivery_queue SET heartbeat_at = '2000-01-01T00:00:00Z' WHERE id = ?", id); err != nil {
		t.Fatalf("置旧心跳: %v", err)
	}
}

// queueStatusOf 直查行状态（断言辅助）。
func queueStatusOf(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	var st string
	if err := db.QueryRow("SELECT status FROM delivery_queue WHERE id = ?", id).Scan(&st); err != nil {
		t.Fatalf("查询行状态: %v", err)
	}
	return st
}

// TestQueueGuardMarkResultStaleWrite F1：sent 终态后的再次回写=迟到回写——
// in_flight 守卫命中 0 行，返回 ErrQueueStaleWrite（不覆盖终态）。
func TestQueueGuardMarkResultStaleWrite(t *testing.T) {
	ctx := context.Background()
	repo, db := newQueueGuardRepo(t)
	qid := seedQueueRow(t, db, "x@ext.io")

	items, err := repo.ClaimDue(ctx, time.Now().UTC(), 10)
	if err != nil || len(items) != 1 || items[0].ID != qid {
		t.Fatalf("认领应命中预置行: n=%d err=%v", len(items), err)
	}
	if items[0].ClaimToken == "" {
		t.Fatalf("认领行应携带 claim_token（F4）")
	}
	// 正常回写（in_flight→sent）
	if err = repo.MarkResult(ctx, qid, AttemptResult{Status: AttemptSent, Attempts: 1}); err != nil {
		t.Fatalf("正常回写应成功: %v", err)
	}
	// 迟到回写（行已 sent 非 in_flight）——F1 哨兵
	if err = repo.MarkResult(ctx, qid, AttemptResult{Status: AttemptSent, Attempts: 2}); err != ErrQueueStaleWrite {
		t.Fatalf("迟到回写应返回 ErrQueueStaleWrite: %v", err)
	}
	if st := queueStatusOf(t, db, qid); st != "sent" {
		t.Fatalf("终态不应被覆盖: %s", st)
	}
}

// TestQueueGuardStaleAfterReclaim F1 核心语义：Stale 回收后的旧 worker 回写作废——
// 回收将行转回 pending（新投递周期），旧结果 0 行受影响不覆盖新状态。
func TestQueueGuardStaleAfterReclaim(t *testing.T) {
	ctx := context.Background()
	repo, db := newQueueGuardRepo(t)
	qid := seedQueueRow(t, db, "x@ext.io")

	items, _ := repo.ClaimDue(ctx, time.Now().UTC(), 10)
	if len(items) != 1 {
		t.Fatalf("认领失败")
	}
	staleHeartbeat(t, db, qid) // 投递停滞超窗
	n, err := repo.ReclaimStale(ctx, 10*time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("应回收 1 行: n=%d err=%v", n, err)
	}
	if st := queueStatusOf(t, db, qid); st != "pending" {
		t.Fatalf("回收后应回 pending: %s", st)
	}
	// 旧 worker 的结果回写——F1：作废丢弃
	if err = repo.MarkResult(ctx, qid, AttemptResult{Status: AttemptSent, Attempts: 1}); err != ErrQueueStaleWrite {
		t.Fatalf("回收后回写应作废: %v", err)
	}
}

// TestQueueClaimHeartbeatPreventsReclaim F4：TouchClaim 续期后行不被 Stale 回收——
// 在途投递（每 MX 尝试前续期）持续刷新判据，多 MX 长尾不再被误回收重投。
func TestQueueClaimHeartbeatPreventsReclaim(t *testing.T) {
	ctx := context.Background()
	repo, db := newQueueGuardRepo(t)
	qid := seedQueueRow(t, db, "x@ext.io")

	items, _ := repo.ClaimDue(ctx, time.Now().UTC(), 10)
	if len(items) != 1 || items[0].ClaimToken == "" {
		t.Fatalf("认领失败或令牌缺失")
	}
	token := items[0].ClaimToken

	// 模拟认领后时间流逝（心跳变旧）→ 续期（F4：token 归属校验通过，心跳刷新）
	staleHeartbeat(t, db, qid)
	if err := repo.TouchClaim(ctx, token); err != nil {
		t.Fatalf("心跳续期: %v", err)
	}
	n, err := repo.ReclaimStale(ctx, 10*time.Minute)
	if err != nil || n != 0 {
		t.Fatalf("已续期行不应被回收: n=%d err=%v", n, err)
	}
	// 对照：心跳过期未续期 → 回收
	staleHeartbeat(t, db, qid)
	n, err = repo.ReclaimStale(ctx, 10*time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("过期未续期行应被回收: n=%d err=%v", n, err)
	}
}

// TestQueueReclaimBackoffLadder F2：回收按 attempts 退避阶梯重置 next_attempt_at——
// 崩溃批量恢复的行错峰到期（0→+60s/1→+120s/2→+240s/8→cap+3600s）。
func TestQueueReclaimBackoffLadder(t *testing.T) {
	ctx := context.Background()
	repo, db := newQueueGuardRepo(t)

	attempts := []int{0, 1, 2, 8}
	for i, att := range attempts {
		qid := seedQueueRow(t, db, "u"+string(rune('0'+i))+"@ext.io")
		if _, err := db.Exec(
			"UPDATE delivery_queue SET attempts = ?, status = 'in_flight', heartbeat_at = '2000-01-01T00:00:00Z' WHERE id = ?",
			att, qid); err != nil {
			t.Fatalf("预置第 %d 行: %v", i, err)
		}
	}
	before := time.Now().UTC()
	if _, err := repo.ReclaimStale(ctx, 10*time.Minute); err != nil {
		t.Fatalf("回收: %v", err)
	}
	want := []time.Duration{60 * time.Second, 120 * time.Second, 240 * time.Second, 3600 * time.Second}
	rows, err := db.Query("SELECT rcpt_to, next_attempt_at FROM delivery_queue WHERE status = 'pending' ORDER BY id")
	if err != nil {
		t.Fatalf("查询回收行: %v", err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var rcpt, next string
		if err = rows.Scan(&rcpt, &next); err != nil {
			t.Fatalf("扫描: %v", err)
		}
		at, perr := time.Parse(time.RFC3339, next)
		if perr != nil {
			t.Fatalf("时间解析 %q: %v", next, perr)
		}
		got := at.Sub(before)
		if got < want[i]-30*time.Second || got > want[i]+30*time.Second {
			t.Fatalf("行 %s（attempts=%d）退避应≈%v 实得 %v", rcpt, attempts[i], want[i], got)
		}
		i++
	}
	if i != len(want) {
		t.Fatalf("应回收 %d 行实得 %d", len(want), i)
	}
}

// TestQueueDSNRescanLifecycle F5：failed 且 DSN 未发行→重扫命中→置位→不再命中
// （幂等闭环）；pending 行不入重扫面。
func TestQueueDSNRescanLifecycle(t *testing.T) {
	ctx := context.Background()
	repo, db := newQueueGuardRepo(t)
	qid := seedQueueRow(t, db, "x@ext.io")
	pendingID := seedQueueRow(t, db, "still-pending@ext.io") // 对照行（未到期不认领；非 failed 不入重扫）
	if _, err := db.Exec("UPDATE delivery_queue SET next_attempt_at = '2999-01-01T00:00:00Z' WHERE id = ?", pendingID); err != nil {
		t.Fatalf("置对照行未到期: %v", err)
	}

	items, _ := repo.ClaimDue(ctx, time.Now().UTC(), 10)
	if len(items) != 1 {
		t.Fatalf("认领应仅命中到期行")
	}
	if err := repo.MarkResult(ctx, qid, AttemptResult{Status: AttemptFailed, SMTPCode: 550, Error: "no such user"}); err != nil {
		t.Fatalf("回写 failed: %v", err)
	}
	pending, err := repo.ListFailedDSNPending(ctx, 100)
	if err != nil || len(pending) != 1 || pending[0].ID != qid {
		t.Fatalf("重扫应恰命中 failed 未发行行: n=%d err=%v", len(pending), err)
	}
	if err = repo.MarkDSNSent(ctx, qid); err != nil {
		t.Fatalf("置位 DSN 回执: %v", err)
	}
	pending, _ = repo.ListFailedDSNPending(ctx, 100)
	if len(pending) != 0 {
		t.Fatalf("置位后不应再命中: %d", len(pending))
	}
}
