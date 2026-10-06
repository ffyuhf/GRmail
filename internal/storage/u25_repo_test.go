// storage 域 U25 影子邮箱聚合可达集成单测（NFR-015：临时 SQLite 库独立驱动）。
// 覆盖锚点：SRS FR-003（聚合文件夹承载）/S3-W Q1-B（管道层副本）/Q2-B1（第六系统
// 文件夹+删除级联附加指示）/Q4（存量回填）；契约 v1.22.0 2.1 两新方法。
// 修改历史：
//
//	2026-10-03 06:40:00 | 新建 | U25影子邮箱聚合可达批次（G2 批准 2026-10-02 19:41:00）
package storage

import (
	"context"
	"path/filepath"
	"testing"

	"GRmail/internal/config"
)

// newU25Repo U25 测试环境（临时库全量迁移+三仓储）。
func newU25Repo(t *testing.T) (*SQLiteMessageRepo, *SQLiteMailboxRepo, *SQLiteFolderRepo) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u25test.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return NewSQLiteMessageRepo(db), NewSQLiteMailboxRepo(db), NewSQLiteFolderRepo(db)
}

// u25FolderCount 指定 kind 的文件夹行数（直查断言辅助）。
func u25FolderCount(t *testing.T, repo *SQLiteMessageRepo, mailboxID int64, kind FolderKind) int {
	t.Helper()
	var n int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM folders WHERE mailbox_id = ? AND kind = ?`,
		mailboxID, string(kind)).Scan(&n); err != nil {
		t.Fatalf("统计 %s 文件夹: %v", kind, err)
	}
	return n
}

// TestU25PostmasterSixFolders postmaster 邮箱初始化六系统文件夹、普通邮箱保持五类
// （S3-W Q2-B1——仅 postmaster 附加 unregistered）。
func TestU25PostmasterSixFolders(t *testing.T) {
	repo, mbRepo, folderRepo := newU25Repo(t)
	ctx := context.Background()

	pm := &Mailbox{LocalPart: "postmaster", Domain: "t.io", Address: "postmaster@t.io", Status: MailboxStatusShadow}
	if err := mbRepo.Create(ctx, pm); err != nil {
		t.Fatalf("建 postmaster: %v", err)
	}
	if got := u25FolderCount(t, repo, pm.ID, FolderKindUnregistered); got != 1 {
		t.Fatalf("postmaster unregistered 文件夹应 1: %d", got)
	}
	folders, err := folderRepo.List(ctx, pm.ID)
	if err != nil || len(folders) != 6 {
		t.Fatalf("postmaster 文件夹应 6: n=%d err=%v", len(folders), err)
	}

	plain := &Mailbox{LocalPart: "u", Domain: "t.io", Address: "u@t.io", Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, plain); err != nil {
		t.Fatalf("建普通邮箱: %v", err)
	}
	if got := u25FolderCount(t, repo, plain.ID, FolderKindUnregistered); got != 0 {
		t.Fatalf("普通邮箱 unregistered 文件夹应 0: %d", got)
	}

	// EnsureAggregateFolder 幂等：重复调用零错误零重复行（防御路径）
	if err := folderRepo.EnsureAggregateFolder(ctx, pm.ID); err != nil {
		t.Fatalf("EnsureAggregateFolder: %v", err)
	}
	if err := folderRepo.EnsureAggregateFolder(ctx, pm.ID); err != nil {
		t.Fatalf("EnsureAggregateFolder 重入: %v", err)
	}
	if got := u25FolderCount(t, repo, pm.ID, FolderKindUnregistered); got != 1 {
		t.Fatalf("幂等后应保持 1: %d", got)
	}
}

// TestU25BackfillAndCopy 存量回填链（S3-W Q4）：批查命中→副本补写→重查清零（NOT
// EXISTS 幂等）→聚合行与影子原行同 message_id（blob/messages 复用语义）。
func TestU25BackfillAndCopy(t *testing.T) {
	repo, mbRepo, _ := newU25Repo(t)
	ctx := context.Background()

	pm := &Mailbox{LocalPart: "postmaster", Domain: "t.io", Address: "postmaster@t.io", Status: MailboxStatusShadow}
	shadow := &Mailbox{LocalPart: "ghost", Domain: "t.io", Address: "ghost@t.io", Status: MailboxStatusShadow}
	if err := mbRepo.Create(ctx, pm); err != nil {
		t.Fatalf("建 postmaster: %v", err)
	}
	if err := mbRepo.Create(ctx, shadow); err != nil {
		t.Fatalf("建影子: %v", err)
	}
	// 影子归档两封（模拟批次前存量——不经聚合 target 直插）
	for i, key := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		if err := repo.StoreInbound(ctx, &InboundMeta{
			Message:    sampleMeta(key),
			Recipients: []RecipientTarget{{MailboxID: shadow.ID, Address: shadow.Address}},
		}); err != nil {
			t.Fatalf("存量归档 %d: %v", i, err)
		}
	}

	ids, err := repo.ListShadowBackfill(ctx, 10)
	if err != nil || len(ids) != 2 {
		t.Fatalf("回填批查应命中 2: n=%d err=%v", len(ids), err)
	}
	for _, mid := range ids {
		if err := repo.CopyToAggregateFolder(ctx, pm.ID, mid); err != nil {
			t.Fatalf("副本补写 %d: %v", mid, err)
		}
	}
	// 幂等：重查清零；重写零重复
	if ids, err = repo.ListShadowBackfill(ctx, 10); err != nil || len(ids) != 0 {
		t.Fatalf("补写后批查应清零: n=%d err=%v", len(ids), err)
	}
	var aggRows int
	if err := repo.db.QueryRow(
		`SELECT COUNT(*) FROM mailbox_messages mm JOIN folders f ON f.id = mm.folder_id
		 WHERE mm.mailbox_id = ? AND f.kind = 'unregistered'`, pm.ID).Scan(&aggRows); err != nil || aggRows != 2 {
		t.Fatalf("聚合副本行应 2: n=%d err=%v", aggRows, err)
	}
}

// TestU25HardDeleteCascade 删除级联三态（S3-W Q2 附加指示）：①聚合行删除→影子原行
// 同删+messages 孤儿清理②影子原行删除→聚合行保留（反向不级联）③普通行删除零级联。
func TestU25HardDeleteCascade(t *testing.T) {
	repo, mbRepo, _ := newU25Repo(t)
	ctx := context.Background()

	pm := &Mailbox{LocalPart: "postmaster", Domain: "t.io", Address: "postmaster@t.io", Status: MailboxStatusShadow}
	active := &Mailbox{LocalPart: "u", Domain: "t.io", Address: "u@t.io", Status: MailboxStatusActive}
	for _, m := range []*Mailbox{pm, active} {
		if err := mbRepo.Create(ctx, m); err != nil {
			t.Fatalf("建邮箱 %s: %v", m.Address, err)
		}
	}
	key := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := repo.StoreInbound(ctx, &InboundMeta{
		Message: sampleMeta(key),
		Recipients: []RecipientTarget{
			{MailboxID: active.ID, Address: active.Address},
			{MailboxID: pm.ID, Address: pm.Address, FolderName: "Unregistered", Aggregate: true},
		},
	}); err != nil {
		t.Fatalf("归档（active+聚合副本）: %v", err)
	}

	var aggRowID, activeRowID, msgID int64
	if err := repo.db.QueryRow(
		`SELECT mm.id, mm.message_id FROM mailbox_messages mm JOIN folders f ON f.id = mm.folder_id
		 WHERE mm.mailbox_id = ? AND f.kind = 'unregistered'`, pm.ID).Scan(&aggRowID, &msgID); err != nil {
		t.Fatalf("聚合行定位: %v", err)
	}
	if err := repo.db.QueryRow(`SELECT id FROM mailbox_messages WHERE mailbox_id = ?`, active.ID).Scan(&activeRowID); err != nil {
		t.Fatalf("active 行定位: %v", err)
	}

	// ②先证反向不级联：删 active 原行→聚合行保留
	if err := repo.HardDelete(ctx, []int64{activeRowID}); err != nil {
		t.Fatalf("active 行硬删: %v", err)
	}
	var n int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM mailbox_messages WHERE id = ?`, aggRowID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("反向不级联失效：聚合行应保留: n=%d err=%v", n, err)
	}

	// ①聚合行删除→自身删除+messages 孤儿清理（同 message 无他行）
	if err := repo.HardDelete(ctx, []int64{aggRowID}); err != nil {
		t.Fatalf("聚合行硬删: %v", err)
	}
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM mailbox_messages`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("级联后关联行应清零: n=%d err=%v", n, err)
	}
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE id = ?`, msgID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("messages 孤儿应清理: n=%d err=%v", n, err)
	}
}

// TestU25CascadeMultiShadow 同信多影：聚合副本一份+级联删多行（DISTINCT+同 message
// 全同胞语义）。
func TestU25CascadeMultiShadow(t *testing.T) {
	repo, mbRepo, _ := newU25Repo(t)
	ctx := context.Background()

	pm := &Mailbox{LocalPart: "postmaster", Domain: "t.io", Address: "postmaster@t.io", Status: MailboxStatusShadow}
	s1 := &Mailbox{LocalPart: "s1", Domain: "t.io", Address: "s1@t.io", Status: MailboxStatusShadow}
	s2 := &Mailbox{LocalPart: "s2", Domain: "t.io", Address: "s2@t.io", Status: MailboxStatusShadow}
	for _, m := range []*Mailbox{pm, s1, s2} {
		if err := mbRepo.Create(ctx, m); err != nil {
			t.Fatalf("建邮箱 %s: %v", m.Address, err)
		}
	}
	key := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := repo.StoreInbound(ctx, &InboundMeta{
		Message: sampleMeta(key),
		Recipients: []RecipientTarget{
			{MailboxID: s1.ID, Address: s1.Address},
			{MailboxID: s2.ID, Address: s2.Address},
			{MailboxID: pm.ID, Address: pm.Address, FolderName: "Unregistered", Aggregate: true},
		},
	}); err != nil {
		t.Fatalf("多影归档: %v", err)
	}

	// 回填幂等语义验证路径：已有聚合副本→ListShadowBackfill 零命中
	if ids, err := repo.ListShadowBackfill(ctx, 10); err != nil || len(ids) != 0 {
		t.Fatalf("已有聚合副本批查应零命中: n=%d err=%v", len(ids), err)
	}

	var aggRowID int64
	if err := repo.db.QueryRow(
		`SELECT mm.id FROM mailbox_messages mm JOIN folders f ON f.id = mm.folder_id
		 WHERE mm.mailbox_id = ? AND f.kind = 'unregistered'`, pm.ID).Scan(&aggRowID); err != nil {
		t.Fatalf("聚合行定位: %v", err)
	}
	if err := repo.HardDelete(ctx, []int64{aggRowID}); err != nil {
		t.Fatalf("聚合行硬删: %v", err)
	}
	var n int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM mailbox_messages`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("多影级联后应全清（聚合1+s1+s2=3 行）: n=%d err=%v", n, err)
	}
}

// TestU25MigrationRoundTrip 迁移 00010 往返（沿 u18 先例形态——Down 单步/再 Up）：
// v9 态建 postmaster+存量→Up 至 00010（CHECK 扩展+补建）→Down（聚合清除+CHECK 收回
// +数据无损）→再 Up（恢复）。
func TestU25MigrationRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u25rt.db")})
	if err != nil {
		t.Fatalf("打开往返库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移至末版: %v", err)
	}

	// 回退至 00009（U25 前）预置 postmaster 邮箱与存量归档（迁移演进后末版本=00011
	// 〔管理员主体增强批次〕——两步回退对齐 U25 断言面；沿 U24 加入 00009 时适配先例）
	if err = u18MigrateDownOne(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Down 至 00010: %v", err)
	}
	if err = u18MigrateDownOne(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Down 至 00009: %v", err)
	}
	if _, err = db.ExecContext(ctx,
		`INSERT INTO mailboxes (local_part, domain, address, password_hash, status, created_at, updated_at)
		 VALUES ('postmaster', 't.io', 'postmaster@t.io', NULL, 'shadow', ?, ?)`,
		"2026-10-02T00:00:00Z", "2026-10-02T00:00:00Z"); err != nil {
		t.Fatalf("预置 postmaster: %v", err)
	}

	// Up 至 00010：CHECK 扩展+存量 postmaster 补建聚合文件夹（迁移 ② 段生效）
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("再 Up 至 00010: %v", err)
	}
	var n int
	if err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM folders f JOIN mailboxes m ON m.id = f.mailbox_id
		 WHERE m.address = 'postmaster@t.io' AND f.kind = 'unregistered'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("Up 后聚合文件夹应 1: n=%d err=%v", n, err)
	}

	// Down 两步（00011→00010→00009——末版本演进适配）：聚合文件夹消除+postmaster 邮箱无损
	if err = u18MigrateDownOne(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Down 00011: %v", err)
	}
	if err = u18MigrateDownOne(ctx, db, "sqlite"); err != nil {
		t.Fatalf("Down 00010: %v", err)
	}
	if err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM folders WHERE kind = 'unregistered'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("Down 后聚合文件夹应清零: n=%d err=%v", n, err)
	}
	if err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mailboxes WHERE address = 'postmaster@t.io'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("Down 后 postmaster 邮箱应无损: n=%d err=%v", n, err)
	}

	// 再 Up：可重放恢复
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("再 Up 恢复: %v", err)
	}
	if err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM folders WHERE kind = 'unregistered'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("再 Up 后聚合文件夹应恢复 1: n=%d err=%v", n, err)
	}
}
