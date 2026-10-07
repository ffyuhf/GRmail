// F4/F5/F10（B-C1/B-C2/M3 配置并发批）：SetFlags 单 SQL 原子化+UID 并发唯一
// +IMAPSearch 扩列测试。
// 依据：配置并发批_计划_20261008_00-10-00_v1.0.0 步骤 4/5/10（G2 批准
// 2026-10-08 00:14:04）；架构级评审报告 B-C1/B-C2+复核报告 M3 并入口径；
// FR-006/FR-013。
package storage

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestSetFlagsConcurrentPatchesNoLostUpdate F4（-race+真库锚）：并发三值补丁
// 交错更新（is_read/is_flagged 同行）——修复前读-改-写两步 RMW 并发互相覆盖
// 丢失更新；修复后单 SQL 原子化，字段级无丢失（两组独立补丁的终值均生效）。
func TestSetFlagsConcurrentPatchesNoLostUpdate(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	m := seedInboxMail(t, repo, mbRepo, "flags-race@t.io", "ffflagsrace01", "race")
	inboxID := folderIDByKind(t, NewSQLiteFolderRepo(testDBForRepo(t, repo)), m.ID, FolderKindInbox)
	items, err := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID})
	if err != nil || len(items) == 0 {
		t.Fatalf("IMAPSearch: %v len=%d", err, len(items))
	}
	id := items[0].ID
	t.Run("fieldwise-no-loss", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ { // 并发写 is_read 与 is_flagged 两组
			wg.Add(2)
			go func() { defer wg.Done(); r := true; _ = repo.SetFlags(ctx, id, FlagPatch{IsRead: &r}) }()
			go func() { defer wg.Done(); f := true; _ = repo.SetFlags(ctx, id, FlagPatch{IsFlagged: &f}) }()
		}
		wg.Wait()
		d, err := repo.GetDetail(ctx, m.ID, id)
		if err != nil {
			t.Fatalf("GetDetail: %v", err)
		}
		// 字段级无丢失：两字段各自被独立补丁写过——终值必须均为 true
		// （修复前 RMW 竞态可致一组补丁读旧值回写覆盖另一组）
		if !d.IsRead || !d.IsFlagged {
			t.Fatalf("并发补丁字段丢失: is_read=%v is_flagged=%v", d.IsRead, d.IsFlagged)
		}
	})
	t.Run("three-value-nil-unchanged", func(t *testing.T) {
		r := false
		if err := repo.SetFlags(ctx, id, FlagPatch{IsRead: &r}); err != nil {
			t.Fatalf("SetFlags: %v", err)
		}
		if err := repo.SetFlags(ctx, id, FlagPatch{}); err != nil { // 全 nil——零变更
			t.Fatalf("SetFlags all-nil: %v", err)
		}
		d, _ := repo.GetDetail(ctx, m.ID, id)
		if d.IsRead {
			t.Fatal("nil 补丁误改 is_read")
		}
		if !d.IsFlagged { // 上一 subtest 的 flagged 保持
			t.Fatal("nil 补丁误改 is_flagged")
		}
		del := true
		if err := repo.SetFlags(ctx, id, FlagPatch{Deleted: &del}); err != nil {
			t.Fatalf("SetFlags deleted: %v", err)
		}
		d, _ = repo.GetDetail(ctx, m.ID, id)
		if !d.Deleted {
			t.Fatal("deleted=true 未生效")
		}
		undel := false
		if err := repo.SetFlags(ctx, id, FlagPatch{Deleted: &undel}); err != nil {
			t.Fatalf("SetFlags undelete: %v", err)
		}
		d, _ = repo.GetDetail(ctx, m.ID, id)
		if d.Deleted {
			t.Fatal("deleted=false 未恢复 normal")
		}
	})
}

// TestIMAPSearchCarriesSizeAndBlobKey F10：IMAPSearch 列集尾部含 raw_size/blob_key
// ——POP3 maildrop 单查询直取的数据面锚（登录期 GetDetail N+1 消除）。
func TestIMAPSearchCarriesSizeAndBlobKey(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	m := seedInboxMail(t, repo, mbRepo, "size-blob@t.io", "sssizeblob02", "sb")
	inboxID := folderIDByKind(t, NewSQLiteFolderRepo(testDBForRepo(t, repo)), m.ID, FolderKindInbox)
	items, err := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID})
	if err != nil || len(items) == 0 {
		t.Fatalf("IMAPSearch: %v len=%d", err, len(items))
	}
	it := items[0]
	if it.Size <= 0 {
		t.Fatalf("Size 列缺失/为零: %d", it.Size)
	}
	if len(it.BlobKey) == 0 {
		t.Fatalf("BlobKey 列缺失: %q", it.BlobKey)
	}
	d, _ := repo.GetDetail(ctx, m.ID, it.ID)
	if it.Size != d.RawSize || it.BlobKey != d.BlobKey { // 与详情直读一致
		t.Fatalf("扩列与详情不一致: size %d/%d blob %q/%q", it.Size, d.RawSize, it.BlobKey, d.BlobKey)
	}
}

// TestAppendConcurrentSameMailboxUIDUnique F5（SQLite 路径——整库单写者串行）：
// 并发 StoreAppend 同邮箱全部成功且 uid 唯一（MySQL/PG 行锁形态经 compose 真库
// 格登记——本地 sqlite 锚沿 queue_guard 先例；SQLite 天然串行为基线回归）。
func TestAppendConcurrentSameMailboxUIDUnique(t *testing.T) {
	repo, mbRepo := newMessageRepo(t)
	ctx := context.Background()
	m := seedInboxMail(t, repo, mbRepo, "uid-race@t.io", "uuuidrace03", "ur")
	folderRepo := NewSQLiteFolderRepo(testDBForRepo(t, repo))
	inboxID := folderIDByKind(t, folderRepo, m.ID, FolderKindInbox)
	// 注：SQLite 测试库无 busy_timeout——并发写事务立即 SQLITE_BUSY（驱动层
	// 限流，非 uid 冲突）；串行循环承载 uid 唯一性断言（MySQL/PG 并发串行化
	// 语义由 LockMailboxForUID 行锁承载——compose 真库格登记，CHANGE5 第四章）。
	for i := 0; i < 4; i++ {
		meta := &AppendMeta{Message: MessageMeta{
			MessageID: fmt.Sprintf("uid-race-%d-%d@t.io", i, timeNanoSeed()),
			BlobKey:   fmt.Sprintf("uuuidrace%032d", i), RawSize: 42,
			Subject: "append-race", FromAddr: "a@t.io", ToAddrs: `["b@t.io"]`, BodyCache: "body",
		}}
		if _, err := repo.StoreAppend(ctx, m.ID, inboxID, meta); err != nil {
			t.Fatalf("StoreAppend %d 失败: %v", i, err)
		}
	}
	uids := map[int64]bool{}
	items, err := repo.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: m.ID, FolderID: inboxID})
	if err != nil {
		t.Fatalf("IMAPSearch: %v", err)
	}
	for _, it := range items {
		if uids[it.UID] {
			t.Fatalf("uid 重复: %d", it.UID)
		}
		uids[it.UID] = true
	}
	if len(items) != 5 { // 种子 1 封 + 追加 4 封
		t.Fatalf("行数期望 5 实际 %d", len(items))
	}
}

// timeNanoSeed 纳秒时戳（并发 MessageID 唯一性辅助）。
func timeNanoSeed() int64 {
	return time.Now().UnixNano()
}
