// account 域服务集成单测（NFR-015：脱离网络端点，临时 SQLite 文件库独立驱动）。
// 覆盖条目：FR-001（创建/凭据三入口域基础）、FR-002（状态管理）、FR-003（影子列举）、
// FR-004（影子状态机全流程：建影子→归档→激活继承→可登录，TC-004 判定①②锚点）、
// FR-012（单层文件夹约束，TC-012 存储层锚点）。
// 修改历史：
//
//	2026-09-17 01:47:00 | 新建 | U2 account 模块（计划书步骤 6，G2 批准 2026-09-17 01:31:40）
package account

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// newTestService 建立临时 SQLite 库（t.TempDir 生命周期）→ 迁移 → 组装 repo+service。
// 返回：服务实例与原始连接（构造历史邮件行用）。
func newTestService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{
		Driver: "sqlite",
		DSN:    filepath.Join(t.TempDir(), "u2test.db"),
	})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return NewService(storage.NewSQLiteMailboxRepo(db), storage.NewSQLiteFolderRepo(db)), db
}

// insertMessage 直插一行 messages + mailbox_messages（构造历史邮件/未读计数场景；绕过 U4 收信管道）
func insertMessage(t *testing.T, db *sql.DB, mailboxID, folderID int64, uid int64, isRead bool, mmStatus string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.Exec(
		`INSERT INTO messages (blob_key, raw_size, created_at) VALUES (?, ?, ?)`,
		strings.Repeat("ab", 32), 100, now,
	)
	if err != nil {
		t.Fatalf("插入 messages: %v", err)
	}
	msgID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("取 messages ID: %v", err)
	}
	read := 0
	if isRead {
		read = 1
	}
	if _, err := db.Exec(
		`INSERT INTO mailbox_messages (mailbox_id, message_id, folder_id, uid, is_read, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		mailboxID, msgID, folderID, uid, read, mmStatus, now,
	); err != nil {
		t.Fatalf("插入 mailbox_messages: %v", err)
	}
}

// folderByName 从列表中取指定名文件夹（不存在时 t.Fatal）
func folderByName(t *testing.T, folders []*storage.Folder, name string) *storage.Folder {
	t.Helper()
	for _, f := range folders {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("文件夹 %q 不存在", name)
	return nil
}

// ───────────────────────── 地址规范化 ─────────────────────────

// TestNormalizeAddress 表驱动：合法输入统一小写/去空白；非法输入拒绝（数据模型 3.2 口径）
func TestNormalizeAddress(t *testing.T) {
	valid := []struct{ in, local, domain string }{
		{"Alice@Example.COM", "alice", "example.com"},                                      // 大小写规范化
		{"  Bob@example.com  ", "bob", "example.com"},                                      // 首尾空白
		{"a@localhost", "a", "localhost"},                                                  // 无点域名（默认配置场景）
		{strings.Repeat("a", 64) + "@example.com", strings.Repeat("a", 64), "example.com"}, // local 上限
	}
	for _, c := range valid {
		local, domain, err := NormalizeAddress(c.in)
		if err != nil || local != c.local || domain != c.domain {
			t.Errorf("NormalizeAddress(%q) = (%q,%q,%v), want (%q,%q,nil)",
				c.in, local, domain, err, c.local, c.domain)
		}
	}
	invalid := []string{
		"",                                       // 空
		"no-at-sign",                             // 无 @
		"@example.com",                           // local 空
		"alice@",                                 // domain 空
		"a b@example.com",                        // local 含空白
		strings.Repeat("a", 65) + "@example.com", // local 超长
		"alice@" + strings.Repeat("d", 256),      // domain 超长
		"a@" + strings.Repeat("d", 320),          // 整体超 320
	}
	for _, in := range invalid {
		if _, _, err := NormalizeAddress(in); err == nil {
			t.Errorf("NormalizeAddress(%q) 应拒绝", in)
		}
	}
}

// ───────────────────────── 邮箱创建与往返 ─────────────────────────

// TestCreateMailboxRoundTrip 创建回填/查询一致/五系统文件夹/重复拒绝（FR-001 + 数据模型 3.3）
func TestCreateMailboxRoundTrip(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	m, err := svc.CreateMailbox(ctx, "Alice@Example.COM", "s3cret-PW")
	if err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}
	if m.ID == 0 || m.Status != storage.MailboxStatusActive || m.PasswordHash == "" {
		t.Fatalf("创建回填异常: %+v", m)
	}
	if m.Address != "alice@example.com" {
		t.Fatalf("地址未规范化: %q", m.Address)
	}
	got, err := svc.GetMailbox(ctx, "ALICE@example.com") // 查询侧同样小写化
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	if got.ID != m.ID || got.LocalPart != "alice" || got.Domain != "example.com" {
		t.Fatalf("往返不一致: %+v", got)
	}
	// 五系统文件夹：数量与固定序（REQ-021 侧边栏序）
	folders, err := svc.ListFolders(ctx, m.ID)
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	wantOrder := []string{"INBOX", "Sent", "Drafts", "Junk", "Trash"}
	if len(folders) != len(wantOrder) {
		t.Fatalf("系统文件夹数量 %d ≠ %d", len(folders), len(wantOrder))
	}
	for i, name := range wantOrder {
		if folders[i].Name != name {
			t.Errorf("文件夹序 %d 位为 %q，want %q", i, folders[i].Name, name)
		}
	}
	// 重复创建（大小写变体同地址）
	if _, err := svc.CreateMailbox(ctx, "alice@EXAMPLE.com", "x"); !errors.Is(err, storage.ErrMailboxExists) {
		t.Fatalf("重复创建应 ErrMailboxExists，got %v", err)
	}
}

// ───────────────────────── 影子邮箱状态机（FR-004 全流程，TC-004 ①②） ─────────────────────────

// TestShadowMailboxLifecycle 影子建立→历史归档→不可登录→激活继承→可登录（REQ-020 原地继承核心语义）
func TestShadowMailboxLifecycle(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()

	// ① 影子建立（模拟 U4 未注册来信触发）
	sm, err := svc.CreateShadowMailbox(ctx, "Shadow@Test.com")
	if err != nil {
		t.Fatalf("CreateShadowMailbox: %v", err)
	}
	if sm.Status != storage.MailboxStatusShadow || sm.PasswordHash != "" {
		t.Fatalf("影子初始态异常: %+v", sm)
	}
	// 影子态不可登录（FR-004：无凭据不可登录）
	if _, err := svc.VerifyCredentials(ctx, sm.Address, "any"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("影子登录应统一拒绝，got %v", err)
	}
	// ② 历史邮件归档至影子邮箱 INBOX
	folders, _ := svc.ListFolders(ctx, sm.ID)
	inbox := folderByName(t, folders, "INBOX")
	insertMessage(t, db, sm.ID, inbox.ID, 1, false, "normal")
	// ③ 注册激活（原地继承）
	if err := svc.ActivateMailbox(ctx, sm.Address, "new-PW-123"); err != nil {
		t.Fatalf("ActivateMailbox: %v", err)
	}
	am, err := svc.GetMailbox(ctx, sm.Address)
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	if am.Status != storage.MailboxStatusActive || am.PasswordHash == "" {
		t.Fatalf("激活后状态异常: %+v", am)
	}
	// ④ 激活后可登录（FR-004 判定②：可登录且邮件可见）
	if _, err := svc.VerifyCredentials(ctx, sm.Address, "new-PW-123"); err != nil {
		t.Fatalf("激活后登录失败: %v", err)
	}
	// ⑤ 历史邮件保留（判定②：计数不减）
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM mailbox_messages WHERE mailbox_id = ?`, sm.ID).Scan(&count); err != nil {
		t.Fatalf("计数历史邮件: %v", err)
	}
	if count != 1 {
		t.Fatalf("历史邮件计数 %d ≠ 1（激活触碰了历史行）", count)
	}
}

// TestActivateUnknownMailbox 激活不存在的地址：ErrMailboxNotFound
func TestActivateUnknownMailbox(t *testing.T) {
	svc, _ := newTestService(t)
	err := svc.ActivateMailbox(context.Background(), "ghost@example.com", "pw")
	if !errors.Is(err, storage.ErrMailboxNotFound) {
		t.Fatalf("应 ErrMailboxNotFound，got %v", err)
	}
}

// ───────────────────────── 凭据校验三态（FR-001） ─────────────────────────

// TestVerifyCredentialsRejectsBadInput 错密码/禁用/不存在统一 ErrInvalidCredentials（防枚举口径）
func TestVerifyCredentialsRejectsBadInput(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.CreateMailbox(ctx, "u1@example.com", "right"); err != nil {
		t.Fatalf("建号: %v", err)
	}
	// 错误密码
	if _, err := svc.VerifyCredentials(ctx, "u1@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("错密码应拒绝，got %v", err)
	}
	// 不存在地址（与错密码同错：防枚举）
	if _, err := svc.VerifyCredentials(ctx, "nobody@example.com", "right"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("不存在地址应同拒绝语义，got %v", err)
	}
	// 禁用后拒绝（FR-002 禁用语义在登录侧生效）
	if err := svc.SetMailboxStatus(ctx, "u1@example.com", storage.MailboxStatusDisabled); err != nil {
		t.Fatalf("禁用: %v", err)
	}
	if _, err := svc.VerifyCredentials(ctx, "u1@example.com", "right"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("禁用邮箱登录应拒绝，got %v", err)
	}
	// 重新激活后恢复
	if err := svc.SetMailboxStatus(ctx, "u1@example.com", storage.MailboxStatusActive); err != nil {
		t.Fatalf("恢复: %v", err)
	}
	if _, err := svc.VerifyCredentials(ctx, "u1@example.com", "right"); err != nil {
		t.Fatalf("恢复后登录失败: %v", err)
	}
}

// TestSetMailboxStatusRejectsShadow SetMailboxStatus 禁止直接置 shadow（影子只能经来信自动建立，FR-004）
func TestSetMailboxStatusRejectsShadow(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateMailbox(ctx, "u2@example.com", "pw"); err != nil {
		t.Fatalf("建号: %v", err)
	}
	if err := svc.SetMailboxStatus(ctx, "u2@example.com", storage.MailboxStatusShadow); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("置 shadow 应 ErrInvalidStatus，got %v", err)
	}
}

// TestListShadowMailboxes catch-all 聚合支撑查询：只列 shadow（FR-003 数据源）
func TestListShadowMailboxes(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	for _, addr := range []string{"s1@ex.com", "s2@ex.com"} {
		if _, err := svc.CreateShadowMailbox(ctx, addr); err != nil {
			t.Fatalf("建影子 %s: %v", addr, err)
		}
	}
	if _, err := svc.CreateMailbox(ctx, "a@ex.com", "pw"); err != nil {
		t.Fatalf("建 active: %v", err)
	}
	shadows, err := svc.ListShadowMailboxes(ctx)
	if err != nil {
		t.Fatalf("ListShadowMailboxes: %v", err)
	}
	if len(shadows) != 2 {
		t.Fatalf("影子数 %d ≠ 2", len(shadows))
	}
	for _, m := range shadows {
		if m.Status != storage.MailboxStatusShadow {
			t.Fatalf("混入非影子邮箱: %+v", m)
		}
	}
}

// ───────────────────────── 文件夹管理（FR-012 / TC-012 存储层） ─────────────────────────

// TestFolderCRUDAndGuards 自定义增删改名 + 系统文件夹保护 + 重名/非空约束
func TestFolderCRUDAndGuards(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()
	m, err := svc.CreateMailbox(ctx, "folders@ex.com", "pw")
	if err != nil {
		t.Fatalf("建号: %v", err)
	}

	// 创建 + 重名拒绝 + 空名拒绝
	if err := svc.CreateFolder(ctx, m.ID, "Projects"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if err := svc.CreateFolder(ctx, m.ID, "Projects"); !errors.Is(err, storage.ErrFolderExists) {
		t.Fatalf("重名应 ErrFolderExists，got %v", err)
	}
	if err := svc.CreateFolder(ctx, m.ID, "   "); !errors.Is(err, ErrEmptyFolderName) {
		t.Fatalf("空白名应拒绝，got %v", err)
	}
	if err := svc.CreateFolder(ctx, m.ID, strings.Repeat("n", folderNameMaxLen+1)); !errors.Is(err, ErrEmptyFolderName) {
		t.Fatalf("超长名应拒绝，got %v", err)
	}

	// 改名（含同名他夹冲突）
	folders, _ := svc.ListFolders(ctx, m.ID)
	proj := folderByName(t, folders, "Projects")
	if err := svc.RenameFolder(ctx, proj.ID, "Archived"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}
	if err := svc.CreateFolder(ctx, m.ID, "Other"); err != nil {
		t.Fatalf("CreateFolder Other: %v", err)
	}
	folders, _ = svc.ListFolders(ctx, m.ID)
	other := folderByName(t, folders, "Other")
	if err := svc.RenameFolder(ctx, other.ID, "INBOX"); !errors.Is(err, storage.ErrFolderExists) {
		t.Fatalf("改名撞系统文件夹名应 ErrFolderExists，got %v", err)
	}

	// 系统文件夹保护：改名将拒、删除将拒（TC-012：系统文件夹不可删）
	inbox := folderByName(t, folders, "INBOX")
	if err := svc.RenameFolder(ctx, inbox.ID, "X"); !errors.Is(err, storage.ErrFolderIsSystem) {
		t.Fatalf("系统文件夹改名应拒，got %v", err)
	}
	if err := svc.DeleteFolder(ctx, inbox.ID); !errors.Is(err, storage.ErrFolderIsSystem) {
		t.Fatalf("系统文件夹删除应拒，got %v", err)
	}
	// 不存在的文件夹
	if err := svc.RenameFolder(ctx, 99999, "X"); !errors.Is(err, storage.ErrFolderNotFound) {
		t.Fatalf("不存在改名应 ErrFolderNotFound，got %v", err)
	}
	if err := svc.DeleteFolder(ctx, 99999); !errors.Is(err, storage.ErrFolderNotFound) {
		t.Fatalf("不存在删除应 ErrFolderNotFound，got %v", err)
	}

	// 空自定义文件夹删除成功；非空删除被 FK 拒绝（ErrFolderNotEmpty）
	if err := svc.DeleteFolder(ctx, other.ID); err != nil {
		t.Fatalf("空文件夹删除: %v", err)
	}
	archived := folderByName(t, folders, "Archived")
	insertMessage(t, db, m.ID, archived.ID, 1, false, "normal")
	if err := svc.DeleteFolder(ctx, archived.ID); !errors.Is(err, storage.ErrFolderNotEmpty) {
		t.Fatalf("非空文件夹删除应 ErrFolderNotEmpty，got %v", err)
	}
}

// ───────────────────────── 未读计数（REQ-021 侧边栏数据源） ─────────────────────────

// TestUnreadCounts 计数口径：is_read=0 AND status='normal'（已读/软删除行排除）
func TestUnreadCounts(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()
	m, err := svc.CreateMailbox(ctx, "unread@ex.com", "pw")
	if err != nil {
		t.Fatalf("建号: %v", err)
	}
	folders, _ := svc.ListFolders(ctx, m.ID)
	inbox, junk := folderByName(t, folders, "INBOX"), folderByName(t, folders, "Junk")

	insertMessage(t, db, m.ID, inbox.ID, 1, false, "normal")  // 未读计 1
	insertMessage(t, db, m.ID, inbox.ID, 2, true, "normal")   // 已读不计
	insertMessage(t, db, m.ID, inbox.ID, 3, false, "deleted") // 软删不计
	insertMessage(t, db, m.ID, junk.ID, 4, false, "normal")   // junk 未读 1

	counts, err := svc.UnreadCounts(ctx, m.ID)
	if err != nil {
		t.Fatalf("UnreadCounts: %v", err)
	}
	if got := counts[inbox.ID]; got != 1 {
		t.Errorf("INBOX 未读 %d ≠ 1", got)
	}
	if got := counts[junk.ID]; got != 1 {
		t.Errorf("Junk 未读 %d ≠ 1", got)
	}
	if _, exists := counts[folderByName(t, folders, "Sent").ID]; exists {
		t.Error("空文件夹不应出现在计数 map")
	}
}

// ───────────────────────── 事务原子性（数据模型 3.3） ─────────────────────────

// TestCreateMailboxAtomicAddressConflict 地址冲突时不得残留半截邮箱/文件夹（事务原子性）
func TestCreateMailboxAtomicAddressConflict(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateMailbox(ctx, "dup@ex.com", "pw"); err != nil {
		t.Fatalf("首建: %v", err)
	}
	if _, err := svc.CreateMailbox(ctx, "dup@ex.com", "pw2"); !errors.Is(err, storage.ErrMailboxExists) {
		t.Fatalf("重复应 ErrMailboxExists，got %v", err)
	}
	// 全库仅一行该地址邮箱；文件夹数 = 5（无第二次事务残留）
	var mailboxCount, folderCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM mailboxes WHERE address = 'dup@ex.com'`).Scan(&mailboxCount); err != nil {
		t.Fatalf("计数 mailboxes: %v", err)
	}
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE address = 'dup@ex.com')`,
	).Scan(&folderCount); err != nil {
		t.Fatalf("计数 folders: %v", err)
	}
	if mailboxCount != 1 || folderCount != 5 {
		t.Fatalf("事务残留：mailboxes=%d（want 1）folders=%d（want 5）", mailboxCount, folderCount)
	}
}
