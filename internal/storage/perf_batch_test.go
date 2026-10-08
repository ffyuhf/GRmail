// 性能批 F2/F4（B-P3①③，评审修复批次 7）验收测试：聚合计数与批量详情等价性。
// 依据：性能批_计划_20261008_10-08-00_v1.0.0 步骤 3/5（G2 批准 2026-10-08 10:13:49）；
// rfc9051 §6.3.11 STATUS 各项语义不变（聚合 vs 全量对照锚）。
package storage

import (
	"context"
	"testing"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// perfSeedExtra 追加灌信辅助（seedInboxMail 每次调用建邮箱——同地址仅可首调；
// 后续来信经 StoreInbound 直投同邮箱收件箱）。
func perfSeedExtra(t *testing.T, repo *SQLiteMessageRepo, mailboxID int64, blobKey, subject string) {
	t.Helper()
	err := repo.StoreInbound(context.Background(), &InboundMeta{
		Message:    MessageMeta{BlobKey: blobKey, Subject: subject},
		Recipients: []RecipientTarget{{MailboxID: mailboxID}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// perfFolderInboxID 测试辅助：邮箱收件箱 folder id（GetSystemFolderByKind 同包直取）。
func perfFolderInboxID(t *testing.T, repo *SQLiteMessageRepo, mailboxID int64) int64 {
	t.Helper()
	f, err := repo.q.GetSystemFolderByKind(context.Background(), dbgen.GetSystemFolderByKindParams{
		MailboxID: mailboxID, Kind: string(FolderKindInbox),
	})
	if err != nil {
		t.Fatal(err)
	}
	return f.ID
}

// TestFolderStatusCountsMatchesFullScan F2 聚合计数与全量行计数一致（等价性锚：
// Total 含 \Deleted 全量、Unread 为 is_read 假值、Deleted 为 status='deleted'）。
func TestFolderStatusCountsMatchesFullScan(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	mb := seedInboxMail(t, repo, mbRepo, "agg@t.local", "bk1", "首封")
	perfSeedExtra(t, repo, mb.ID, "bk2", "次封")
	perfSeedExtra(t, repo, mb.ID, "bk3", "三封")
	folderID := perfFolderInboxID(t, repo, mb.ID)

	// 置态：第一封已读、第二封软删除
	items, _, err := repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("前置应 3 封, got %d", len(items))
	}
	read := true
	if err = repo.SetFlags(ctx, items[0].ID, FlagPatch{IsRead: &read}); err != nil {
		t.Fatal(err)
	}
	if err = repo.SoftDelete(ctx, []int64{items[1].ID}); err != nil {
		t.Fatal(err)
	}

	counts, err := repo.FolderStatusCounts(ctx, mb.ID, folderID)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Total != 3 {
		t.Fatalf("Total 应 3（含 \\Deleted）, got %d", counts.Total)
	}
	if counts.Unread != 2 {
		t.Fatalf("Unread 应 2（一封已读）, got %d", counts.Unread)
	}
	if counts.Deleted != 1 {
		t.Fatalf("Deleted 应 1, got %d", counts.Deleted)
	}

	// 全量对照（F2 改造前的原路径语义——PageList 零过滤全量含 deleted）
	full, _, err := repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var wantUnread, wantDeleted int64
	for _, it := range full {
		if !it.IsRead {
			wantUnread++
		}
		if it.Deleted {
			wantDeleted++
		}
	}
	if int64(len(full)) != counts.Total || wantUnread != counts.Unread || wantDeleted != counts.Deleted {
		t.Fatalf("聚合与全量不一致: agg=%+v full(len=%d unread=%d deleted=%d)",
			counts, len(full), wantUnread, wantDeleted)
	}
}

// TestSumFolderRawSizeMatchesDetails F2 SIZE 聚合与逐封详情求和一致（rfc9051
// §6.3.11 下限保证语义等价锚）。
func TestSumFolderRawSizeMatchesDetails(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	mb := seedInboxMail(t, repo, mbRepo, "size@t.local", "sz1", "a")
	perfSeedExtra(t, repo, mb.ID, "sz2", "b")
	folderID := perfFolderInboxID(t, repo, mb.ID)

	items, _, err := repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var want int64
	for _, it := range items {
		d, derr := repo.GetDetail(ctx, mb.ID, it.ID)
		if derr != nil {
			t.Fatal(derr)
		}
		want += d.RawSize
	}
	got, err := repo.SumFolderRawSize(ctx, mb.ID, folderID)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("SUM 聚合 %d 与逐封求和 %d 不一致", got, want)
	}
}

// TestListDetailsByIDsMatchesGetDetail F4 批量详情与逐行 GetDetail 逐字段等价
// （FETCH/STORE/Copy 批量化路径的行为等价锚）。
func TestListDetailsByIDsMatchesGetDetail(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	mb := seedInboxMail(t, repo, mbRepo, "batch@t.local", "bd1", "甲")
	perfSeedExtra(t, repo, mb.ID, "bd2", "乙")
	perfSeedExtra(t, repo, mb.ID, "bd3", "丙")
	folderID := perfFolderInboxID(t, repo, mb.ID)

	items, _, err := repo.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: folderID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	// keyword 伴随填充断言：首封置两枚 keyword
	if err = repo.SetKeywords(ctx, ids[0], []string{"$label1", "nonjunk"}); err != nil {
		t.Fatal(err)
	}

	batch, err := repo.ListDetailsByIDs(ctx, mb.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != len(ids) {
		t.Fatalf("批量行数 %d 应等于请求 %d", len(batch), len(ids))
	}
	byID := make(map[int64]*Detail, len(batch))
	for _, d := range batch {
		byID[d.ID] = d
	}
	for _, id := range ids {
		single, serr := repo.GetDetail(ctx, mb.ID, id)
		if serr != nil {
			t.Fatal(serr)
		}
		b := byID[id]
		if b == nil {
			t.Fatalf("批量结果缺行 %d", id)
		}
		if b.UID != single.UID || b.BlobKey != single.BlobKey || b.Subject != single.Subject ||
			b.FromAddr != single.FromAddr || b.RawSize != single.RawSize ||
			b.IsRead != single.IsRead || b.IsFlagged != single.IsFlagged ||
			b.IsAnswered != single.IsAnswered || b.IsDraft != single.IsDraft ||
			b.Deleted != single.Deleted {
			t.Fatalf("行 %d 批量与单查字段不一致: batch=%+v single=%+v", id, b, single)
		}
	}
	// keyword 批量填充断言
	if len(byID[ids[0]].Keywords) != 2 {
		t.Fatalf("首封 keyword 批量填充应 2 枚, got %v", byID[ids[0]].Keywords)
	}
	// 空 ids 零行为
	if out, err := repo.ListDetailsByIDs(ctx, mb.ID, nil); err != nil || out != nil {
		t.Fatalf("空 ids 应返回 nil 零错误, got %v %v", out, err)
	}
}
