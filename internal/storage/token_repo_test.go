// storage 域 Token 仓储集成单测（NFR-015：临时 SQLite 库独立驱动，零网络端点）。
// 覆盖锚点：契约 v1.10.0 2.1 TokenRepo 六方法；数据模型 v1.2.0 3.11
// （expires_at NULL=永久/last_used_at Q2-B/UNIQUE(token_hash)）；
// U14 计划书 1.5②（IP 绑定判定归调用方——行数据回读断言）。
// 修改历史：
//
//	2026-09-24 02:46:00 | 新建 | U14 API Token 管理（计划书步骤 3）
package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"GRmail/internal/config"
)

// hash64 测试用 64 字符哈希（char 重复 64 次——CHAR(64) 形态）。
func hash64(char string) string { return strings.Repeat(char, 64) }

// newTokenRepo 临时库迁移后构造 Token 仓储。
func newTokenRepo(t *testing.T) *SQLiteTokenRepo {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u14test.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return NewSQLiteTokenRepo(db)
}

// TestU14TokenLifecycle 六方法往返：创建→有效查询→列表→TouchLastUsed→双条件撤销。
func TestU14TokenLifecycle(t *testing.T) {
	r := newTokenRepo(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second) // SQLite 文本列秒级往返

	tok := &ApiToken{UserID: 1, TokenHash: hash64("a"), CreatedAt: now}
	if err := r.Create(ctx, tok); err != nil {
		t.Fatalf("创建 Token: %v", err)
	}

	// 有效查询（expires_at NULL=永久——零值映射）
	got, err := r.FindValidByHash(ctx, hash64("a"), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("查询有效 Token: %v", err)
	}
	if got.UserID != 1 || got.ClientIP != "" || !got.ExpiresAt.IsZero() || !got.LastUsedAt.IsZero() {
		t.Fatalf("回读字段异常: %+v", got)
	}

	// 唯一冲突
	if err := r.Create(ctx, &ApiToken{UserID: 1, TokenHash: hash64("a"), CreatedAt: now}); err != ErrTokenExists {
		t.Fatalf("期望 ErrTokenExists，得到 %v", err)
	}

	// TouchLastUsed（Q2-B）
	lu := now.Add(time.Minute)
	if err := r.TouchLastUsed(ctx, got.ID, lu); err != nil {
		t.Fatalf("刷新使用时刻: %v", err)
	}
	got2, err := r.FindValidByHash(ctx, hash64("a"), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("复查: %v", err)
	}
	if got2.LastUsedAt.Unix() != lu.Unix() {
		t.Fatalf("last_used_at 未生效: %v vs %v", got2.LastUsedAt, lu)
	}

	// 列表（created_at DESC）
	if err := r.Create(ctx, &ApiToken{UserID: 1, TokenHash: hash64("b"), CreatedAt: now.Add(time.Second), ClientIP: "10.0.0.1"}); err != nil {
		t.Fatalf("创建第二枚: %v", err)
	}
	list, err := r.ListByUser(ctx, 1)
	if err != nil || len(list) != 2 {
		t.Fatalf("列表: %v %d", err, len(list))
	}
	if list[0].TokenHash != hash64("b") || list[0].ClientIP != "10.0.0.1" {
		t.Fatalf("排序/ClientIP 回读异常: %+v", list[0])
	}

	// 双条件撤销：错误 userID 未命中（行保留），正确双条件命中
	if err := r.Delete(ctx, got2.ID, 999); err != nil {
		t.Fatalf("撤销调用: %v", err)
	}
	if _, err := r.FindValidByHash(ctx, hash64("b"), now); err != nil {
		t.Fatalf("错误 userID 撤销不应删除行: %v", err)
	}
	if err := r.Delete(ctx, list[0].ID, 1); err != nil {
		t.Fatalf("正确撤销: %v", err)
	}
	if _, err := r.FindValidByHash(ctx, hash64("b"), now); err != ErrTokenNotFound {
		t.Fatalf("撤销后应不可查: %v", err)
	}
}

// TestU14TokenExpiryBoundary 过期边界：永久（NULL）/未来过期命中/已过期拒（PurgeExpired 清理）。
func TestU14TokenExpiryBoundary(t *testing.T) {
	r := newTokenRepo(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	future := &ApiToken{UserID: 2, TokenHash: hash64("c"), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	past := &ApiToken{UserID: 2, TokenHash: hash64("d"), ExpiresAt: now.Add(-time.Hour), CreatedAt: now}
	for _, tk := range []*ApiToken{future, past} {
		if err := r.Create(ctx, tk); err != nil {
			t.Fatalf("创建: %v", err)
		}
	}

	if _, err := r.FindValidByHash(ctx, hash64("c"), now); err != nil {
		t.Fatalf("未来过期应命中: %v", err)
	}
	if _, err := r.FindValidByHash(ctx, hash64("d"), now); err != ErrTokenNotFound {
		t.Fatalf("已过期应拒: %v", err)
	}

	// PurgeExpired：仅清理已过期行（d），永久/未来保留
	n, err := r.PurgeExpired(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("清理计数: %v %d", err, n)
	}
	if _, err := r.FindValidByHash(ctx, hash64("c"), now); err != nil {
		t.Fatalf("未来过期被误删: %v", err)
	}
	list, err := r.ListByUser(ctx, 2)
	if err != nil || len(list) != 1 {
		t.Fatalf("清理后列表: %v %d", err, len(list))
	}
}
