// Webmail 列表过滤与关键词搜索路径测试（U9 计划书步骤 3 检查点）。
// 覆盖：PageList 分流语义（零值=U6 全量含 \Deleted / 任一过滤位=normal 基线）+
// 未读/星标过滤 + Search 三缓存列命中 + LIKE 通配符转义（Q6-A 安全语义）。
// 修改历史：
//
//	2026-09-19 10:14:00 | 新建 | U9 Webmail 核心（计划书步骤 3，G2 批准 2026-09-19 10:00:41）
package storage

import (
	"context"
	"testing"
)

// seedThreeMails 灌三封信至指定邮箱收件箱（不同主题/发件人，UID 1..3），返回 inbox folderID。
func seedThreeMails(t *testing.T, repo *SQLiteMessageRepo, mbRepo *SQLiteMailboxRepo, mailboxID int64) int64 {
	t.Helper()
	ctx := context.Background()
	for i, blob := range []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333333333333333333333333333",
	} {
		meta := sampleMeta(blob)
		meta.Subject = []string{"季度报告 100%", "会议通知", "发票提醒"}[i]
		meta.FromAddr = []string{"boss@corp.example", "alice@team.example", "billing@shop.example"}[i]
		if err := repo.StoreInbound(ctx, &InboundMeta{
			Message:    meta,
			Recipients: []RecipientTarget{{MailboxID: mailboxID}},
		}); err != nil {
			t.Fatalf("灌入第 %d 信: %v", i+1, err)
		}
	}
	var folderID int64
	if err := repo.db.QueryRow(`SELECT id FROM folders WHERE mailbox_id = ? AND kind = 'inbox'`,
		mailboxID).Scan(&folderID); err != nil {
		t.Fatalf("查询收件箱 folder: %v", err)
	}
	return folderID
}

// TestPageListWebmailFilterPaths 分流四态：零值全量（含 \Deleted）与三过滤位 normal 基线。
func TestPageListWebmailFilterPaths(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	mb := &Mailbox{LocalPart: "u9", Domain: "t.io", Address: "u9@t.io", Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, mb); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	folderID := seedThreeMails(t, repo, mbRepo, mb.ID)

	// 取三行 id（UID 降序=最新在前）
	items, total, err := repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 10})
	if err != nil || total != 3 || len(items) != 3 {
		t.Fatalf("零值路径应全量 3 行: n=%d total=%d err=%v", len(items), total, err)
	}
	idNewest, idOldest := items[0].ID, items[2].ID

	// 零值路径：置 \Deleted 后仍返回（U6 IMAP 语义不变）
	if err = repo.SetFlags(ctx, idNewest, FlagPatch{Deleted: boolPtr(true)}); err != nil {
		t.Fatalf("软删: %v", err)
	}
	items, total, err = repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 10})
	if err != nil || total != 3 {
		t.Fatalf("零值路径应仍 3 行（IMAP 全量）: total=%d err=%v", total, err)
	}
	if !items[0].Deleted {
		t.Fatalf("零值路径 ListItem.Deleted 应为真（状态可视化）")
	}

	// Webmail 路径（ExcludeDeleted）：\Deleted 行隐藏，total=2
	items, total, err = repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 10, ExcludeDeleted: true})
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("Webmail 路径应 2 行: n=%d total=%d err=%v", len(items), total, err)
	}
	for _, it := range items {
		if it.Deleted {
			t.Fatalf("Webmail 路径不应出现 deleted 行")
		}
	}

	// UnreadOnly：软删行已出基线，最旧行置已读 → 未读仅剩中位行 1 封
	if err = repo.SetFlags(ctx, idOldest, FlagPatch{IsRead: boolPtr(true)}); err != nil {
		t.Fatalf("置已读: %v", err)
	}
	_, total, err = repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 10, ExcludeDeleted: true, UnreadOnly: true})
	if err != nil || total != 1 {
		t.Fatalf("未读过滤应 1（基线 2 行中已读 1 封）: total=%d err=%v", total, err)
	}

	// FlaggedOnly：仅星标行
	if err = repo.SetFlags(ctx, idOldest, FlagPatch{IsFlagged: boolPtr(true)}); err != nil {
		t.Fatalf("置星标: %v", err)
	}
	items, total, err = repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 10, ExcludeDeleted: true, FlaggedOnly: true})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != idOldest {
		t.Fatalf("星标过滤应仅最旧行: n=%d total=%d err=%v", len(items), total, err)
	}
}

// TestSearchKeywordColumnsAndEscape 三缓存列命中+LIKE 通配符转义+空关键词（Q6-A）。
func TestSearchKeywordColumnsAndEscape(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	mb := &Mailbox{LocalPart: "s9", Domain: "t.io", Address: "s9@t.io", Status: MailboxStatusActive}
	if err := mbRepo.Create(ctx, mb); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	seedThreeMails(t, repo, mbRepo, mb.ID)

	cases := []struct {
		name    string
		keyword string
		want    int64
	}{
		{"subject 命中", "季度", 1},
		{"from 命中", "alice", 1},
		{"to 缓存列命中（sampleMeta to=b@test.example，三信共享）", "b@test.example", 3},
		{"% 字面命中（转义后不通配）", "100%", 1},
		{"_ 字面不误配（转义后非单字通配）", "10_", 0},
		{"无命中", "不存在的关键词", 0},
	}
	for _, tc := range cases {
		items, total, err := repo.Search(ctx, SearchQuery{MailboxID: mb.ID, Keyword: tc.keyword, Limit: 10})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want || int64(len(items)) != tc.want {
			t.Fatalf("%s: 期望 %d 命中，实得 total=%d rows=%d", tc.name, tc.want, total, len(items))
		}
	}

	// 空白关键词：空结果零错误
	items, total, err := repo.Search(ctx, SearchQuery{MailboxID: mb.ID, Keyword: "   ", Limit: 10})
	if err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("空白关键词应空结果: total=%d n=%d err=%v", total, len(items), err)
	}

	// mailbox 隔离：另一邮箱搜索零命中（FR-001）
	other := &Mailbox{LocalPart: "o9", Domain: "t.io", Address: "o9@t.io", Status: MailboxStatusActive}
	if err = mbRepo.Create(ctx, other); err != nil {
		t.Fatalf("建另一邮箱: %v", err)
	}
	_, total, err = repo.Search(ctx, SearchQuery{MailboxID: other.ID, Keyword: "季度", Limit: 10})
	if err != nil || total != 0 {
		t.Fatalf("跨邮箱应零命中: total=%d err=%v", total, err)
	}
}

// boolPtr 布尔取址辅助（FlagPatch 三值补丁输入）。
func boolPtr(b bool) *bool { return &b }
