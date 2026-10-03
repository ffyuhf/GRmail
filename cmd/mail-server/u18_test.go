// U18 清理循环单测（sessions/login_attempts——U14b 登记项①收口；NFR-015 全离线：
// 临时 SQLite 库+短周期注入，沿 U14b main_test.go 形态）。
// 覆盖锚点：runSessionPurgeLoop（过期会话清/未过期保留）/runLoginAttemptPurgeLoop
// （30d 窗口外行清/窗口内行保留——限流计数功能零影响验证）。
// SRS 条目：FR-001（3.1）会话承载运维关联；OWASP Session Expiration；TC-001 关联锚。
// 修改历史：
//
//	2026-09-26 16:10:00 | 新建 | U18 登记项收尾（计划书步骤 2/1.5⑦，G2 批准 2026-09-26 15:25:47）
package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// newU18PurgeRepos 临时库迁移后构造会话与登录尝试仓储（沿 newPurgeTokenRepo 形态）。
func newU18PurgeRepos(t *testing.T) (storage.SessionRepo, storage.LoginAttemptRepo) {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u18test.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return storage.NewSQLiteSessionRepo(db), storage.NewSQLiteLoginAttemptRepo(db)
}

// waitSessionGone 轮询等待会话行被清理（至多 2s——异步 goroutine 完成判定）。
func waitSessionGone(t *testing.T, r storage.SessionRepo, idHash string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		_, err := r.Find(context.Background(), idHash)
		if err == storage.ErrSessionNotFound {
			return
		}
		if err != nil {
			t.Fatalf("查询会话: %v", err)
		}
		select {
		case <-deadline:
			t.Fatalf("等待过期会话 %s 清理超时", idHash)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestU18RunSessionPurgeLoop 会话清理循环：过期行清/未过期行保留。
func TestU18RunSessionPurgeLoop(t *testing.T) {
	r, _ := newU18PurgeRepos(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// 预置两会话：绝对超时已过（1 小时前）/未过期（1 小时后）
	expired := &storage.Session{
		ID: hash64ForMain("u18-exp"), SubjectType: storage.SubjectTypeMailbox, SubjectID: 1,
		CreatedAt: now.Add(-2 * time.Hour), LastSeenAt: now.Add(-2 * time.Hour), AbsoluteExpiresAt: now.Add(-time.Hour),
	}
	alive := &storage.Session{
		ID: hash64ForMain("u18-alive"), SubjectType: storage.SubjectTypeMailbox, SubjectID: 1,
		CreatedAt: now, LastSeenAt: now, AbsoluteExpiresAt: now.Add(time.Hour),
	}
	for _, s := range []*storage.Session{expired, alive} {
		if err := r.Create(ctx, s); err != nil {
			t.Fatalf("预置会话 %s: %v", s.ID, err)
		}
	}

	loopCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runSessionPurgeLoop(loopCtx, r, 10*time.Millisecond, slog.Default())
		close(done)
	}()

	waitSessionGone(t, r, expired.ID) // 过期行已被清理（首轮立即语义锚）
	if _, err := r.Find(ctx, alive.ID); err != nil {
		t.Fatalf("未过期会话不应被清理: %v", err) // OWASP 会话语义——误删即违规
	}
	cancel()
	<-done
}

// TestU18RunLoginAttemptPurgeLoop 登录尝试清理循环：30d 窗口外行清/窗口内行保留。
func TestU18RunLoginAttemptPurgeLoop(t *testing.T) {
	_, r := newU18PurgeRepos(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// 预置四行：两行 31d 前（窗口外——清）/两行当前（窗口内——留）
	for i, at := range []time.Time{now.Add(-31 * 24 * time.Hour), now.Add(-32 * 24 * time.Hour)} {
		if err := r.RecordAttempt(ctx, "mailbox:old@t.io", "203.0.113.9", false, at); err != nil {
			t.Fatalf("预置旧行 %d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := r.RecordAttempt(ctx, "mailbox:new@t.io", "203.0.113.9", false, now); err != nil {
			t.Fatalf("预置新行 %d: %v", i, err)
		}
	}

	loopCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runLoginAttemptPurgeLoop(loopCtx, r, 10*time.Millisecond, slog.Default())
		close(done)
	}()

	// 轮询等待旧行清空（两主体计数归零）/新行保留（CountRecentFails since=零值纪元——全量计数）
	deadline := time.After(2 * time.Second)
	for {
		oldN, err := r.CountRecentFails(ctx, "mailbox:old@t.io", time.Time{})
		if err != nil {
			t.Fatalf("旧行计数: %v", err)
		}
		newN, err := r.CountRecentFails(ctx, "mailbox:new@t.io", time.Time{})
		if err != nil {
			t.Fatalf("新行计数: %v", err)
		}
		if oldN == 0 && newN == 2 {
			break // 窗口外全清+窗口内计数功能零影响锚
		}
		select {
		case <-deadline:
			t.Fatalf("等待清理超时: old=%d new=%d（应 old=0 new=2）", oldN, newN)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}
