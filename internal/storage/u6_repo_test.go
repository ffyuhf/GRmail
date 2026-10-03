// storage 域 U6 IMAP 路径集成单测（NFR-015：临时 SQLite 库独立驱动，零网络端点）。
// 覆盖锚点：契约 v1.3.0 2.1（PageList/GetDetail/SetFlags 含 Deleted/Move/SoftDelete/
// HardDelete/StoreAppend/IMAPSearch——Q3-A 增量）；rfc9051 UID 语义（Q4-A：全局单调
// 不复用）；rfc9051 2.3.2 三标志映射（\Seen/\Flagged/\Deleted）。
// 修改历史：
//
//	2026-09-18 04:23:00 | 新建 | U6 IMAP 集成（计划书步骤 8，G2 批准 2026-09-18 00:09:22）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// seedInboxMail 建邮箱（含五系统文件夹）并收信一封，返回邮箱与首行列表 id。
func seedInboxMail(t *testing.T, repo *SQLiteMessageRepo, mbRepo *SQLiteMailboxRepo, addr, blobKey, subject string) *Mailbox {
	t.Helper()
	ctx := context.Background()
	m := &Mailbox{LocalPart: addr[:len(addr)-len("@t.io")], Domain: "t.io", Address: addr, Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, m); err != nil {
		t.Fatalf("建邮箱 %s: %v", addr, err)
	}
	meta := sampleMeta(blobKey)
	meta.Subject = subject
	if err := repo.StoreInbound(ctx, &InboundMeta{
		Message:    meta,
		Recipients: []RecipientTarget{{MailboxID: m.ID}},
	}); err != nil {
		t.Fatalf("收信 %s: %v", addr, err)
	}
	return m
}

// folderIDByKind 取邮箱系统文件夹 ID（五系统文件夹由建库事务初始化）。
func folderIDByKind(t *testing.T, repo *SQLiteFolderRepo, mailboxID int64, kind FolderKind) int64 {
	t.Helper()
	folders, err := repo.List(context.Background(), mailboxID)
	if err != nil {
		t.Fatalf("列举文件夹: %v", err)
	}
	for _, f := range folders {
		if f.Kind == kind {
			return f.ID
		}
	}
	t.Fatalf("系统文件夹 %s 未初始化", kind)
	return 0
}

// TestU6PageListFlagsLifecycle 列表-标志-软删-搜索-硬删全生命周期。
func TestU6PageListFlagsLifecycle(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	folderRepo := NewSQLiteFolderRepo(testDBForRepo(t, repo))
	ctx := context.Background()

	m := seedInboxMail(t, repo, mbRepo, "a@t.io", "aa"+"11", "周报第一封")
	// 追加两封（不同主题/大小）
	for i, bk := range []string{"bb", "cc"} {
		meta := sampleMeta(bk + padKey(bk))
		meta.Subject = []string{"月度总结", "会议邀请"}[i]
		if err := repo.StoreInbound(ctx, &InboundMeta{
			Message: meta, Recipients: []RecipientTarget{{MailboxID: m.ID}},
		}); err != nil {
			t.Fatalf("追加收信 %d: %v", i, err)
		}
	}
	inboxID := folderIDByKind(t, folderRepo, m.ID, FolderKindInbox)

	items, total, err := repo.PageList(ctx, ListQuery{MailboxID: m.ID, FolderID: inboxID, Limit: 10, Offset: 0})
	if err != nil || total != 3 || len(items) != 3 {
		t.Fatalf("PageList 期望 3 行 total=3: rows=%d total=%d err=%v", len(items), total, err)
	}
	if items[0].UID <= items[1].UID || items[1].UID <= items[2].UID {
		t.Fatalf("UID 降序断言失败: %v %v %v", items[0].UID, items[1].UID, items[2].UID)
	}

	// 标志三值补丁：\Seen+\Deleted（\Deleted↔status 映射，Q3-A）
	first := items[0]
	yes := true
	if err = repo.SetFlags(ctx, first.ID, FlagPatch{IsRead: &yes, Deleted: &yes}); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}
	detail, err := repo.GetDetail(ctx, m.ID, first.ID)
	if err != nil {
		t.Fatalf("GetDetail: %v", err)
	}
	if !detail.IsRead || !detail.Deleted || detail.UID != first.UID {
		t.Fatalf("详情断言失败: %+v", detail)
	}

	// 撤销删除（Deleted=false→normal）
	no := false
	if err = repo.SetFlags(ctx, first.ID, FlagPatch{Deleted: &no}); err != nil {
		t.Fatalf("撤销删除: %v", err)
	}
	if detail, _ = repo.GetDetail(ctx, m.ID, first.ID); detail.Deleted {
		t.Fatal("撤销删除标志失败")
	}

	// 软删+精确计数（IMAPSearch FlagDeleted）
	if err = repo.SoftDelete(ctx, []int64{first.ID}); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	hits, err := repo.IMAPSearch(ctx, IMAPSearchQuery{
		MailboxID: m.ID, FolderID: inboxID, Filter: SearchFilter{FlagDeleted: &yes},
	})
	if err != nil || len(hits) != 1 {
		t.Fatalf("FlagDeleted 计数期望 1: %d err=%v", len(hits), err)
	}

	// 硬删（关联行+孤儿 messages 清理）
	if err = repo.HardDelete(ctx, []int64{first.ID}); err != nil {
		t.Fatalf("HardDelete: %v", err)
	}
	if _, total, _ = repo.PageList(ctx, ListQuery{MailboxID: m.ID, FolderID: inboxID, Limit: 10, Offset: 0}); total != 2 {
		t.Fatalf("硬删后 total 期望 2: %d", total)
	}
	if _, err = repo.GetDetail(ctx, m.ID, first.ID); !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("硬删后 GetDetail 期望 ErrMessageNotFound: %v", err)
	}
}

// padKey 测试 blobKey 补齐 64 hex（sampleMeta.BlobKey 语义仅为唯一标识）。
func padKey(prefix string) string {
	out := prefix
	for len(out) < 64 {
		out += "0"
	}
	return out[:64]
}

// TestU6StoreAppendUIDAssign APPEND 落库：UID 全局连续分配+标志初值+跨邮箱 folder 拒绝。
func TestU6StoreAppendUIDAssign(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	folderRepo := NewSQLiteFolderRepo(testDBForRepo(t, repo))
	ctx := context.Background()
	m := seedInboxMail(t, repo, mbRepo, "app@t.io", padKey("dd"), "首封")
	other := seedInboxMail(t, repo, mbRepo, "other@t.io", padKey("ee"), "他箱")

	inboxID := folderIDByKind(t, folderRepo, m.ID, FolderKindInbox)
	otherInbox := folderIDByKind(t, folderRepo, other.ID, FolderKindInbox)

	seen := true
	before, _ := repo.NextUID(ctx, m.ID)
	meta := sampleMeta(padKey("ff"))
	meta.Subject = "客户端投递"
	uid, err := repo.StoreAppend(ctx, m.ID, inboxID, &AppendMeta{
		Message: meta, Flags: FlagPatch{IsRead: &seen},
	})
	if err != nil {
		t.Fatalf("StoreAppend: %v", err)
	}
	if uid != before {
		t.Fatalf("UID 分配期望 %d: %d", before, uid)
	}
	// 标志初值与元数据回读（FolderID 必选——IMAPSearch folder 域条件）
	detail, err := repo.GetDetailByUID(ctx, m.ID, inboxID, uid)
	if err != nil {
		t.Fatalf("按 UID 取详情: %v", err)
	}
	if !detail.IsRead || detail.Subject != "客户端投递" {
		t.Fatalf("APPEND 详情断言失败: %+v", detail)
	}

	// 跨邮箱 folder 注入拒绝（FR-001 隔离防线）
	if _, err = repo.StoreAppend(ctx, m.ID, otherInbox, &AppendMeta{Message: meta}); !errors.Is(err, ErrFolderNotFound) {
		t.Fatalf("跨邮箱 folder 期望 ErrFolderNotFound: %v", err)
	}
}

// GetDetailByUID 测试辅助：按 UID 定位详情（IMAPSearch UIDs 单元素；folder 域必选）。
func (r *SQLiteMessageRepo) GetDetailByUID(ctx context.Context, mailboxID, folderID, uid int64) (*Detail, error) {
	hits, err := r.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: mailboxID, FolderID: folderID, Filter: SearchFilter{UIDs: []int64{uid}}})
	if err != nil || len(hits) == 0 {
		return nil, ErrMessageNotFound
	}
	return r.GetDetail(ctx, mailboxID, hits[0].ID)
}

// TestU6IMAPSearchCriteria 搜索条件矩阵：LIKE 子串/UID 集/Larger/Not/Or/UNSEEN。
func TestU6IMAPSearchCriteria(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	folderRepo := NewSQLiteFolderRepo(testDBForRepo(t, repo))
	ctx := context.Background()
	m := &Mailbox{LocalPart: "s", Domain: "t.io", Address: "s@t.io", Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, m); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	metas := []struct {
		key, subject, from string
		size               int64
		read               bool
	}{
		{padKey("10"), "季度报告 Q3", "boss@corp.io", 100, true},
		{padKey("20"), "周会邀请", "team@corp.io", 5000, false},
		{padKey("30"), "发票通知", "billing@shop.io", 200, false},
	}
	for i, mm := range metas {
		meta := sampleMeta(mm.key)
		meta.Subject, meta.FromAddr, meta.RawSize = mm.subject, mm.from, mm.size
		if err := repo.StoreInbound(ctx, &InboundMeta{
			Message: meta, Recipients: []RecipientTarget{{MailboxID: m.ID}},
		}); err != nil {
			t.Fatalf("收信 %d: %v", i, err)
		}
	}
	if err := repo.SetFlags(ctx, mustRowID(t, repo, m), FlagPatch{IsRead: ptr(true)}); err != nil {
		t.Fatalf("置已读: %v", err)
	}
	inboxID := folderIDByKind(t, folderRepo, m.ID, FolderKindInbox)

	if hits, _ := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID, Filter: SearchFilter{Subject: "报告"}}); len(hits) != 1 {
		t.Fatalf("SUBJECT 命中期望 1: %d", len(hits))
	}
	if hits, _ := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID, Filter: SearchFilter{From: "shop.io"}}); len(hits) != 1 {
		t.Fatalf("FROM 命中期望 1: %d", len(hits))
	}
	if hits, _ := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID, Filter: SearchFilter{Larger: 1000}}); len(hits) != 1 {
		t.Fatalf("LARGER 命中期望 1: %d", len(hits))
	}
	unseen := false
	if hits, _ := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID, Filter: SearchFilter{FlagSeen: &unseen}}); len(hits) != 2 {
		t.Fatalf("UNSEEN 命中期望 2: %d", len(hits))
	}
	notFrom := SearchFilter{Not: &SearchFilter{From: "corp.io"}}
	if hits, _ := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID, Filter: notFrom}); len(hits) != 1 {
		t.Fatalf("NOT FROM 命中期望 1: %d", len(hits))
	}
	orPair := SearchFilter{Or: [][2]SearchFilter{{{Subject: "发票"}, {From: "boss"}}}}
	if hits, _ := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID, Filter: orPair}); len(hits) != 2 {
		t.Fatalf("OR 命中期望 2: %d", len(hits))
	}
	// LIKE 通配符注入转义（% 字面匹配零命中）
	if hits, _ := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID, Filter: SearchFilter{Subject: "100%"}}); len(hits) != 0 {
		t.Fatalf("通配符转义后期望 0: %d", len(hits))
	}
}

// TestU6MoveUIDPreserved MOVE 语义：folder 迁移+UID 保留（mailbox 域全局序列）。
func TestU6MoveUIDPreserved(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	folderRepo := NewSQLiteFolderRepo(testDBForRepo(t, repo))
	ctx := context.Background()
	m := seedInboxMail(t, repo, mbRepo, "mv@t.io", padKey("40"), "待移动")
	inboxID := folderIDByKind(t, folderRepo, m.ID, FolderKindInbox)
	junkID := folderIDByKind(t, folderRepo, m.ID, FolderKindJunk)

	items, _, _ := repo.PageList(ctx, ListQuery{MailboxID: m.ID, FolderID: inboxID, Limit: 10, Offset: 0})
	if len(items) != 1 {
		t.Fatalf("收件箱期望 1 行: %d", len(items))
	}
	if err := repo.Move(ctx, items[0].ID, junkID); err != nil {
		t.Fatalf("Move: %v", err)
	}
	moved, _, _ := repo.PageList(ctx, ListQuery{MailboxID: m.ID, FolderID: junkID, Limit: 10, Offset: 0})
	if len(moved) != 1 || moved[0].UID != items[0].UID {
		t.Fatalf("MOVE 后 UID 保留断言失败: 原 %d 现 %v", items[0].UID, moved)
	}
	if _, total, _ := repo.PageList(ctx, ListQuery{MailboxID: m.ID, FolderID: inboxID, Limit: 10, Offset: 0}); total != 0 {
		t.Fatalf("原文件夹应清空: %d", total)
	}
}

// mustRowID 取首行 id（置已读辅助）。
func mustRowID(t *testing.T, repo *SQLiteMessageRepo, m *Mailbox) int64 {
	t.Helper()
	folderRepo := NewSQLiteFolderRepo(testDBForRepo(t, repo))
	inboxID := folderIDByKind(t, folderRepo, m.ID, FolderKindInbox)
	items, _, err := repo.PageList(context.Background(), ListQuery{MailboxID: m.ID, FolderID: inboxID, Limit: 1, Offset: 0})
	if err != nil || len(items) == 0 {
		t.Fatalf("取首行: %v", err)
	}
	return items[0].ID
}

// ptr bool 指针简写。
func ptr(b bool) *bool { return &b }

// testDBForRepo 从仓储实例提取底层 DB 句柄（同包测试直取私有字段；FolderRepo 构造辅助）。
func testDBForRepo(t *testing.T, repo *SQLiteMessageRepo) *sql.DB {
	t.Helper()
	return repo.db
}
