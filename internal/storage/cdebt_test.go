// C级债务收尾批 storage 域测试（F10——2026-10-10，G2 批准 15:45:40）。
// 覆盖：RenameScript 单事务原子改名（激活态迁移+旧名删除+不存在哨兵）。
// 修改历史：
//
//	2026-10-10 16:15:00 | 新建 | C级债务收尾批（计划书步骤 8）
package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"GRmail/internal/config"
)

// newCDebtSieveRepo 临时 SQLite 库→迁移→Sieve 脚本仓储。
func newCDebtSieveRepo(t *testing.T) *SQLiteSieveScriptRepo {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "cdebt.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	return NewSQLiteSieveScriptRepo(db)
}

// TestCDebtRenameScriptAtomic F10/C21：原子改名——新名行存在且激活态迁移、
// 旧名行消失、激活脚本指针随迁、旧名不存在哨兵。
func TestCDebtRenameScriptAtomic(t *testing.T) {
	r := newCDebtSieveRepo(t)
	ctx := context.Background()
	const mbox int64 = 1

	if err := r.PutScript(ctx, &SieveScript{MailboxID: mbox, Name: "old", Content: "keep;"}); err != nil {
		t.Fatalf("建脚本: %v", err)
	}
	if err := r.SetActive(ctx, mbox, "old"); err != nil {
		t.Fatalf("激活: %v", err)
	}

	if err := r.RenameScript(ctx, mbox, "old", "new"); err != nil {
		t.Fatalf("原子改名: %v", err)
	}
	got, err := r.GetScript(ctx, mbox, "new")
	if err != nil {
		t.Fatalf("新名查询: %v", err)
	}
	if got.Content != "keep;" || !got.IsActive {
		t.Fatalf("新名行应携带内容与激活态: %+v", got)
	}
	if _, err := r.GetScript(ctx, mbox, "old"); !errors.Is(err, ErrSieveScriptNotFound) {
		t.Fatalf("旧名行应已删除: %v", err)
	}
	act, err := r.GetActiveScript(ctx, mbox)
	if err != nil || act.Name != "new" {
		t.Fatalf("激活指针应随迁至新名: %v %q", err, act.Name)
	}

	// 旧名不存在哨兵
	if err := r.RenameScript(ctx, mbox, "ghost", "x"); !errors.Is(err, ErrSieveScriptNotFound) {
		t.Fatalf("不存在旧名应 ErrSieveScriptNotFound: %v", err)
	}
}
