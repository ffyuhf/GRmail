// storage 域安全原子性批单测（NFR-015：临时 SQLite 库独立驱动；三库同构语义以
// SQLite 真库验证——MySQL/PG 同构 SQL 经 sqlc 生成物一致性保证）。
// 覆盖锚点：安全原子性批计划书 v1.0.1 F1/F2/F3/F4（G2 批准 2026-10-06 18:12:59）；
// SRS FR-001（隔离/凭据）/FR-014（三库一致）/FR-018（TC-027 判定③/TC-028 判定①）。
// 修改历史：
//
//	2026-10-06 18:45:00 | 新建 | 安全原子性批（评审修复批次 1/8）
package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"GRmail/internal/config"
)

// newAtomicRepo 安全原子性测试环境（临时库全量迁移）。
func newAtomicRepo(t *testing.T) (*SQLiteMailboxRepo, *SQLiteUserRepo) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "atomic.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return NewSQLiteMailboxRepo(db), NewSQLiteUserRepo(db)
}

// TestAtomicSetCredentialsDisabledRejected F2：disabled 邮箱改密被拒（不静默复活），
// active/shadow 正常（影子激活=原地继承语义保持）。
func TestAtomicSetCredentialsDisabledRejected(t *testing.T) {
	mbRepo, _ := newAtomicRepo(t)
	ctx := context.Background()

	mk := func(addr string, status MailboxStatus) *Mailbox {
		m := &Mailbox{LocalPart: strings.Split(addr, "@")[0], Domain: "t.io", Address: addr, Status: status}
		if err := mbRepo.Create(ctx, m); err != nil {
			t.Fatalf("建邮箱 %s: %v", addr, err)
		}
		return m
	}

	active := mk("a@t.io", MailboxStatusActive)
	shadow := mk("s@t.io", MailboxStatusShadow)
	disabled := mk("d@t.io", MailboxStatusDisabled)

	if err := mbRepo.SetCredentials(ctx, active.ID, "h1", nil); err != nil { // SCRAM认证批签名适配（nil=测试形态——断言面零变化）
		t.Fatalf("active 改密应成功: %v", err)
	}
	if err := mbRepo.SetCredentials(ctx, shadow.ID, "h2", nil); err != nil {
		t.Fatalf("shadow 激活应成功: %v", err)
	}
	if err := mbRepo.SetCredentials(ctx, disabled.ID, "h3", nil); !errors.Is(err, ErrMailboxStatusConflict) {
		t.Fatalf("disabled 改密应 ErrMailboxStatusConflict: %v", err)
	}
	// 复活防线的终态断言：disabled 行状态保持
	got, err := mbRepo.FindMailboxByID(ctx, disabled.ID)
	if err != nil || got.Status != MailboxStatusDisabled {
		t.Fatalf("disabled 状态应保持: st=%s err=%v", got.Status, err)
	}
}

// TestAtomicMarkTOTPStepGuard F3：条件守卫——回退步/同窗步拒绝（ErrTOTPStepConflict）、
// 更大步成功；并发同窗双请求恰一成功（rfc6238 §5.2 L343-347 MUST）。
func TestAtomicMarkTOTPStepGuard(t *testing.T) {
	mbRepo, _ := newAtomicRepo(t)
	ctx := context.Background()
	m := &Mailbox{LocalPart: "u", Domain: "t.io", Address: "u@t.io", Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, m); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}

	if err := mbRepo.MarkTOTPStep(ctx, m.ID, 100); err != nil {
		t.Fatalf("首步（NULL 基线）应成功: %v", err)
	}
	if err := mbRepo.MarkTOTPStep(ctx, m.ID, 100); !errors.Is(err, ErrTOTPStepConflict) {
		t.Fatalf("同窗重放应 ErrTOTPStepConflict: %v", err)
	}
	if err := mbRepo.MarkTOTPStep(ctx, m.ID, 99); !errors.Is(err, ErrTOTPStepConflict) {
		t.Fatalf("回退步应 ErrTOTPStepConflict: %v", err)
	}
	if err := mbRepo.MarkTOTPStep(ctx, m.ID, 101); err != nil {
		t.Fatalf("严格更大步应成功: %v", err)
	}

	// 并发同窗双请求恰一成功（mailbox 侧）
	var okCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mbRepo.MarkTOTPStep(ctx, m.ID, 200); err == nil {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := okCount.Load(); got != 1 {
		t.Fatalf("并发同窗应恰一成功: %d", got)
	}
}

// TestAtomicConsumeRecoveryCodeSingleUse F4：逐枚一次性——顺序双用第二回 false；
// 并发双 goroutine 同码恰一 true（TC-028 判定①）。
func TestAtomicConsumeRecoveryCodeSingleUse(t *testing.T) {
	mbRepo, _ := newAtomicRepo(t)
	ctx := context.Background()
	m := &Mailbox{LocalPart: "u", Domain: "t.io", Address: "u@t.io", Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, m); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	hashes := []string{"h-aaa", "h-bbb"}
	if err := mbRepo.ConfirmTwoFactor(ctx, m.ID, hashes); err != nil {
		t.Fatalf("写恢复码集: %v", err)
	}

	// 顺序双用：第二回拒绝（重放）
	if hit, err := mbRepo.ConsumeRecoveryCode(ctx, m.ID, "h-aaa"); err != nil || !hit {
		t.Fatalf("首用应命中: hit=%v err=%v", hit, err)
	}
	if hit, err := mbRepo.ConsumeRecoveryCode(ctx, m.ID, "h-aaa"); err != nil || hit {
		t.Fatalf("重放应拒绝: hit=%v err=%v", hit, err)
	}

	// 并发双用同码恰一 true
	var trueCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hit, err := mbRepo.ConsumeRecoveryCode(ctx, m.ID, "h-bbb")
			if err != nil {
				t.Errorf("并发消耗不应硬错误: %v", err)
				return
			}
			if hit {
				trueCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := trueCount.Load(); got != 1 {
		t.Fatalf("并发双用同码应恰一 true: %d", got)
	}
}

// TestAtomicSearchFourColumnsAllDialects F1：MySQL/PG 搜索 SQL 含 body_cache 第四列
// （三库四列一致——消除 MySQL/PG 正文检索静默失效分叉）。
func TestAtomicSearchFourColumnsAllDialects(t *testing.T) {
	ctx := context.Background()
	q := SearchQuery{MailboxID: 1, Keyword: "kw"}
	for name, build := range map[string]func(context.Context, SearchQuery) (string, []any, error){
		"mysql": buildWebmailSearchPageSQLMySQL,
		"pg":    buildWebmailSearchPageSQLPG,
	} {
		sqlText, _, err := build(ctx, q)
		if err != nil {
			t.Fatalf("%s 构建: %v", name, err)
		}
		if !strings.Contains(sqlText, "body_cache") {
			t.Fatalf("%s 搜索 SQL 缺 body_cache 第四列: %s", name, sqlText)
		}
	}
}

// TestAtomicAdminTOTPStepGuard F3 admin 通道：users 表同构守卫（/login 二步承载）。
func TestAtomicAdminTOTPStepGuard(t *testing.T) {
	_, uRepo := newAtomicRepo(t)
	ctx := context.Background()
	u := &User{Username: "admin", PasswordHash: "x", IsAdmin: true}
	if err := uRepo.EnsureAdmin(ctx, u); err != nil {
		t.Fatalf("建管理员: %v", err)
	}
	// EnsureAdmin 不保证回填 ID——FindByName 取回真实主键（MarkTOTPStep 按行寻址）
	stored, err := uRepo.FindByName(ctx, "admin")
	if err != nil {
		t.Fatalf("取回管理员: %v", err)
	}
	if err := uRepo.MarkTOTPStep(ctx, stored.ID, 50); err != nil {
		t.Fatalf("首步应成功: %v", err)
	}
	if err := uRepo.MarkTOTPStep(ctx, stored.ID, 50); !errors.Is(err, ErrTOTPStepConflict) {
		t.Fatalf("admin 同窗重放应 ErrTOTPStepConflict: %v", err)
	}
	_ = time.Now // 保持 time 引用（并发用例扩展位）
}
