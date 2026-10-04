// storage 域邮件仓储集成单测（NFR-015：临时 SQLite 库独立驱动，零网络端点）。
// 覆盖锚点：流程设计第一章要点 4（多收件人同事务单 messages 行）、Q4-A（通知邮件行
// 同事务）、CON-004/NFR-007（事务原子性——失败回滚零残留）、数据字典（UID 单调递增）。
// 修改历史：
//
//	2026-09-17 04:20:00 | 新建 | U4 SMTP 收信（计划书步骤 11）
package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
)

// newMessageRepo 临时库迁移后构造邮件仓储与邮箱工厂。
func newMessageRepo(t *testing.T) (*SQLiteMessageRepo, *SQLiteMailboxRepo) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u4test.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return NewSQLiteMessageRepo(db), NewSQLiteMailboxRepo(db)
}

// sampleMeta 测试用 messages 行输入。
func sampleMeta(blobKey string) MessageMeta {
	return MessageMeta{
		MessageID: "<t@example.com>", BlobKey: blobKey, RawSize: 42,
		Subject: "主题", FromAddr: "a@example.com",
		ToAddrs: `["b@test.example"]`, SentAt: time.Now().UTC(),
		SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass", ARCResult: "none",
		AuthResultsHeader: "Authentication-Results: mx.test; spf=pass",
	}
}

// TestStoreInboundMultiRecipientAtomic 多收件人同事务：单 messages 行+多关联行+UID 递增。
func TestStoreInboundMultiRecipientAtomic(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	m1 := &Mailbox{LocalPart: "a", Domain: "t.io", Address: "a@t.io", Status: MailboxStatusActive}
	m2 := &Mailbox{LocalPart: "b", Domain: "t.io", Address: "b@t.io", Status: MailboxStatusShadow}
	if err := mbRepo.Create(ctx, m1); err != nil {
		t.Fatalf("建邮箱 1: %v", err)
	}
	if err := mbRepo.Create(ctx, m2); err != nil {
		t.Fatalf("建邮箱 2: %v", err)
	}

	err := repo.StoreInbound(ctx, &InboundMeta{
		Message:    sampleMeta("1111111111111111111111111111111111111111111111111111111111111111"),
		Recipients: []RecipientTarget{{MailboxID: m1.ID}, {MailboxID: m2.ID}},
	})
	if err != nil {
		t.Fatalf("StoreInbound: %v", err)
	}

	// 单 messages 行（两收件人共享）
	var msgRows int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE blob_key = ?`,
		"1111111111111111111111111111111111111111111111111111111111111111").Scan(&msgRows); err != nil || msgRows != 1 {
		t.Fatalf("messages 行数应 1: n=%d err=%v", msgRows, err)
	}
	// 两 mailbox_messages 行，各自邮箱 UID=1（rfc9051：mailbox 内从 1 起）
	var uid1, uid2 int64
	if err := repo.db.QueryRow(`SELECT uid FROM mailbox_messages WHERE mailbox_id = ?`, m1.ID).Scan(&uid1); err != nil {
		t.Fatalf("查关联行 1: %v", err)
	}
	if err := repo.db.QueryRow(`SELECT uid FROM mailbox_messages WHERE mailbox_id = ?`, m2.ID).Scan(&uid2); err != nil {
		t.Fatalf("查关联行 2: %v", err)
	}
	if uid1 != 1 || uid2 != 1 {
		t.Fatalf("首信 UID 应 1: uid1=%d uid2=%d", uid1, uid2)
	}
}

// TestStoreInboundNoticeSameTx 通知邮件与来信同事务（Q4-A：全有或全无）。
func TestStoreInboundNoticeSameTx(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	pm := &Mailbox{LocalPart: "postmaster", Domain: "t.io", Address: "postmaster@t.io", Status: MailboxStatusShadow}
	if err := mbRepo.Create(ctx, pm); err != nil {
		t.Fatalf("建 postmaster: %v", err)
	}
	target := &Mailbox{LocalPart: "x", Domain: "t.io", Address: "x@t.io", Status: MailboxStatusShadow}
	if err := mbRepo.Create(ctx, target); err != nil {
		t.Fatalf("建影子目标: %v", err)
	}

	noticeBlob := "2222222222222222222222222222222222222222222222222222222222222222"
	if err := repo.StoreInbound(ctx, &InboundMeta{
		Message:    sampleMeta("3333333333333333333333333333333333333333333333333333333333333333"),
		Recipients: []RecipientTarget{{MailboxID: target.ID}},
		Notice: &NoticeMeta{
			Message:   MessageMeta{MessageID: "<n@t.io>", BlobKey: noticeBlob, RawSize: 10, Subject: "通知"},
			MailboxID: pm.ID,
		},
	}); err != nil {
		t.Fatalf("StoreInbound: %v", err)
	}

	var pmRows int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM mailbox_messages mm
		JOIN messages m ON m.id = mm.message_id WHERE m.blob_key = ?`, noticeBlob).Scan(&pmRows); err != nil || pmRows != 1 {
		t.Fatalf("通知邮件应归档 1 行: n=%d err=%v", pmRows, err)
	}
}

// TestStoreInboundRollbackOnFailure 事务原子性：不存在的邮箱→FK 拒绝→整体回滚零残留
// （CON-004：调用方据此 451，禁止半截数据）。
func TestStoreInboundRollbackOnFailure(t *testing.T) {
	repo, _ := newMessageRepo(t)
	err := repo.StoreInbound(context.Background(), &InboundMeta{
		Message:    sampleMeta("4444444444444444444444444444444444444444444444444444444444444444"),
		Recipients: []RecipientTarget{{MailboxID: 9999}}, // 不存在邮箱
	})
	if err == nil {
		t.Fatal("FK 违规应报错")
	}
	var rows int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("回滚后 messages 应零行: n=%d err=%v", rows, err)
	}
}

// TestNextUIDMonotonic UID 单调递增（数据字典：mailbox 内 1..2^32-1）。
func TestNextUIDMonotonic(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	m := &Mailbox{LocalPart: "uid", Domain: "t.io", Address: "uid@t.io", Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, m); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	for want := int64(1); want <= 3; want++ {
		got, err := repo.NextUID(ctx, m.ID)
		if err != nil || got != want {
			t.Fatalf("NextUID 第 %d 次应为 %d: got=%d err=%v", want, want, got, err)
		}
		if err = repo.StoreInbound(ctx, &InboundMeta{
			Message:    sampleMeta(string(rune('0'+want)) + "5555555555555555555555555555555555555555555555555555555555555"),
			Recipients: []RecipientTarget{{MailboxID: m.ID}},
		}); err != nil {
			t.Fatalf("第 %d 次落库: %v", want, err)
		}
	}
}
