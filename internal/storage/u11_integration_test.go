// U11 三库集成实测（TC-014 判定：三库分别完成部署引导与核心收发读写流程）。
// 承载：Q3-A Docker compose 起库（deploy/docker-compose.yml——mysql:8@13306/pg:16@15432）。
// 跳过语义：未设置对应 DSN 环境变量时跳过（离线默认零依赖——NFR-015 既有用例不受影响；
// 实测命令见修改文档第四章实录）。
// 流程（每库一致）：Open→MigrateUp（部署引导存储侧）→EnsureAdmin（向导步 2 存储）→
// CreateMailbox（五文件夹初始化）→StoreInbound 收信落库→PageList 读→SetFlags 写→
// Enqueue/ClaimDue/MarkResult 队列流转——三环境操作记录对比（TC-014 判定方法）。
// 覆盖条目：FR-014（TC-014）；CON-004（ClaimDue 四不变量之 claim 原子/不重叠——
// 流程设计 3.2 语义等价断言）。
// 修改历史：
//
//	2026-09-20 05:55:00 | 新增 | U11 三库验收（计划书步骤 7）
//	2026-09-30 17:55:00 | 扩展 | 阶段复审冒烟批次：4b Sieve 投递形态收件人断言
//	  （fileinto 目标文件夹+imap4flags 初值三库同断言——缺陷③回归锚）+6b 五系统
//	  标志真库往返（F-I16 迁移 00006 两列三库验证；依据：阶段复审冒烟_计划
//	  _20260930_17-50-00_v1.0.0 1.1#2，G2 批准 2026-09-30 17:51:51）
//	2026-10-03 21:33:00 | 修正 | 测试库落位缺陷修复批次：SQLite 格 DSN 去自带
//	  "file:" 前缀改纯路径（前缀形态经 sqliteDSN 前缀剥离双保险统一——DSN 前缀
//	  与参数构造单一来源归 sqliteDSN；G2 批准 2026-10-03 21:29:59）
package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
)

// u11DSN 各库实测 DSN（环境变量注入；MySQL 需 parseTime=true&loc=UTC——1.5⑧ DSN 收敛）。
const (
	u11MySQLDSN = "root:grmail@tcp(127.0.0.1:13306)/grmail?parseTime=true&loc=UTC&charset=utf8mb4&collation=utf8mb4_bin&sql_mode=ANSI_QUOTES"
	u11PGDSN    = "postgres://postgres:grmail@127.0.0.1:15432/grmail?sslmode=disable"
)

// TestU11SQLiteIntegration SQLite 基线格（TC-014 判定链之一——文件态内置默认）。
func TestU11SQLiteIntegration(t *testing.T) {
	dir := t.TempDir()
	u11RunCoreFlow(t, "sqlite", filepath.Join(dir, "t.db"))
}

// TestU11MySQLIntegration MySQL 格（compose 环境就绪时执行；否则跳过）。
func TestU11MySQLIntegration(t *testing.T) {
	if _, err := netDialProbe("127.0.0.1:13306"); err != nil {
		t.Skip("MySQL 容器未就绪（compose 未起或环境变量禁用）——跳过；实测实录见修改文档第四章")
	}
	u11RunCoreFlow(t, "mysql", u11MySQLDSN)
}

// TestU11PostgresIntegration PostgreSQL 格（compose 环境就绪时执行；否则跳过）。
func TestU11PostgresIntegration(t *testing.T) {
	if _, err := netDialProbe("127.0.0.1:15432"); err != nil {
		t.Skip("PostgreSQL 容器未就绪——跳过；实测实录见修改文档第四章")
	}
	u11RunCoreFlow(t, "postgres", u11PGDSN)
}

// u11RunCoreFlow 核心收发读写全流程（三库同一断言集——TC-014「三环境操作记录对比」
// 的代码化承载：任一环节失败即该库格 FAIL）。
func u11RunCoreFlow(t *testing.T, driver, dsn string) {
	t.Helper()
	ctx := context.Background()

	// 1. 连接+迁移（部署引导存储侧：goose 三库分目录）
	conf := config.DatabaseConf{Driver: driver, DSN: dsn}
	db, err := Open(ctx, conf)
	if err != nil {
		t.Fatalf("[%s] 连接: %v", driver, err)
	}
	defer func() { _ = db.Close() }()
	if err = MigrateUp(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移: %v", driver, err)
	}

	repos, err := NewRepoSet(conf, db)
	if err != nil {
		t.Fatalf("[%s] 装配: %v", driver, err)
	}

	// 2. 管理员（向导步 2 存储：幂等创建+可查）
	admin := &User{Username: "admin", PasswordHash: "$argon2id$stub"}
	if err = repos.Users.EnsureAdmin(ctx, admin); err != nil {
		t.Fatalf("[%s] EnsureAdmin: %v", driver, err)
	}
	if err = repos.Users.EnsureAdmin(ctx, admin); err != nil {
		t.Fatalf("[%s] EnsureAdmin 幂等二调: %v", driver, err)
	}
	got, err := repos.Users.FindByName(ctx, "admin")
	if err != nil || got.Username != "admin" || !got.IsAdmin {
		t.Fatalf("[%s] FindByName: got=%+v err=%v", driver, got, err)
	}

	// 3. 邮箱创建（五文件夹事务初始化；真库可重跑——地址唯一化后缀）
	uniqu := time.Now().UnixNano()
	addr := "alice" + fmt.Sprintf("%d", uniqu) + "@example.test"
	mb := &Mailbox{LocalPart: "alice" + fmt.Sprintf("%d", uniqu), Domain: "example.test", Address: addr, Status: MailboxStatusActive}
	if err = repos.Mailboxes.Create(ctx, mb); err != nil {
		t.Fatalf("[%s] CreateMailbox: %v", driver, err)
	}
	if mb.ID == 0 {
		t.Fatalf("[%s] 邮箱 ID 未回填", driver)
	}
	folders, err := repos.Folders.List(ctx, mb.ID)
	if err != nil || len(folders) != 5 {
		t.Fatalf("[%s] 五系统文件夹: n=%d err=%v", driver, len(folders), err)
	}

	// 4. 收信落库（多收件人单事务+UID 分配）
	now := time.Now().UTC().Truncate(time.Second)
	blobKey := fmt.Sprintf("%064x", uniqu)[0:64]
	meta := &InboundMeta{
		Message: MessageMeta{
			BlobKey:   blobKey,
			RawSize:   42,
			Subject:   "三库实测",
			FromAddr:  "bob@ext.test",
			ToAddrs:   `["alice@example.test"]`,
			SentAt:    now,
			SPFResult: "pass",
		},
		Recipients: []RecipientTarget{{MailboxID: mb.ID}},
	}
	if err = repos.Messages.StoreInbound(ctx, meta); err != nil {
		t.Fatalf("[%s] StoreInbound: %v", driver, err)
	}

	// 4b. Sieve 投递形态收件人（阶段复审冒烟批次——缺陷③回归锚，三库同断言）：
	// fileinto 目标文件夹+imap4flags 初值（\Seen/\Flagged）经 RecipientTarget
	// 全字段承载（FR-011/FR-014；修复前 MySQL/PG 收信路径丢弃 FolderName/FlagSeen/FlagFlagged）。
	const sieveFolderName = "Sieve-Targets"
	if err = repos.Folders.CreateCustom(ctx, mb.ID, sieveFolderName); err != nil {
		t.Fatalf("[%s] CreateCustomFolder: %v", driver, err)
	}
	folders2, err := repos.Folders.List(ctx, mb.ID)
	if err != nil {
		t.Fatalf("[%s] ListFolders: %v", driver, err)
	}
	sieveFolderID := int64(0)
	for _, f := range folders2 {
		if f.Name == sieveFolderName {
			sieveFolderID = f.ID
		}
	}
	if sieveFolderID == 0 {
		t.Fatalf("[%s] fileinto 目标文件夹未建成: %+v", driver, folders2)
	}
	sieveMeta := &InboundMeta{
		Message: MessageMeta{
			BlobKey:   fmt.Sprintf("%064x", uniqu+2)[0:64],
			RawSize:   43,
			Subject:   "fileinto 归档",
			FromAddr:  "bob@ext.test",
			ToAddrs:   `["alice@example.test"]`,
			SentAt:    now,
			SPFResult: "pass",
		},
		Recipients: []RecipientTarget{{MailboxID: mb.ID, FolderName: sieveFolderName, FlagSeen: true, FlagFlagged: true}},
	}
	if err = repos.Messages.StoreInbound(ctx, sieveMeta); err != nil {
		t.Fatalf("[%s] StoreInbound(sieve): %v", driver, err)
	}
	svItems, svTotal, err := repos.Messages.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: sieveFolderID, Limit: 10, Offset: 0})
	if err != nil || svTotal != 1 || len(svItems) != 1 {
		t.Fatalf("[%s] fileinto 目标文件夹命中: n=%d total=%d err=%v", driver, len(svItems), svTotal, err)
	}
	if !svItems[0].IsRead || !svItems[0].IsFlagged {
		t.Fatalf("[%s] imap4flags 初值(\\Seen/\\Flagged): %+v", driver, svItems[0])
	}

	// 5. 列表读（分页主路径）+详情
	inboxID := int64(0)
	for _, f := range folders {
		if f.Kind == FolderKindInbox {
			inboxID = f.ID
		}
	}
	items, total, err := repos.Messages.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: inboxID, Limit: 10, Offset: 0})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("[%s] PageList: total=%d n=%d err=%v", driver, total, len(items), err)
	}
	if items[0].Subject != "三库实测" || items[0].IsRead {
		t.Fatalf("[%s] 列表行语义: %+v", driver, items[0])
	}
	detail, err := repos.Messages.GetDetail(ctx, mb.ID, items[0].ID)
	if err != nil || detail.BlobKey != blobKey || detail.RawSize != 42 {
		t.Fatalf("[%s] GetDetail: %+v err=%v", driver, detail, err)
	}

	// 6. flags 写（未读→已读）
	r := true
	if err = repos.Messages.SetFlags(ctx, items[0].ID, FlagPatch{IsRead: &r}); err != nil {
		t.Fatalf("[%s] SetFlags: %v", driver, err)
	}
	items2, _, err := repos.Messages.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: inboxID, Limit: 10, Offset: 0})
	if err != nil || len(items2) != 1 || !items2[0].IsRead {
		t.Fatalf("[%s] flags 回读: %+v err=%v", driver, items2, err)
	}

	// 6b. 五系统标志真库往返（阶段复审冒烟批次——F-I16 真库锚）：\Answered/\Draft
	// SetFlags 写入+GetDetail 回读（TC-006 存储侧；迁移 00006 两列三库验证）。
	ansTrue, draftTrue := true, true
	if err = repos.Messages.SetFlags(ctx, items[0].ID, FlagPatch{IsAnswered: &ansTrue, IsDraft: &draftTrue}); err != nil {
		t.Fatalf("[%s] SetFlags(\\Answered/\\Draft): %v", driver, err)
	}
	det, err := repos.Messages.GetDetail(ctx, mb.ID, items[0].ID)
	if err != nil || !det.IsAnswered || !det.IsDraft {
		t.Fatalf("[%s] 五标志真库往返: answered=%v draft=%v err=%v", driver, det.IsAnswered, det.IsDraft, err)
	}

	// 7. 队列流转（提交入队→认领→回写终态；ClaimDue 原子性=流程设计 3.2 不变量）
	qs, ok := repos.Queue.(QueueStore)
	if !ok {
		t.Fatalf("[%s] QueueRepo 未实现 QueueStore 超集", driver)
	}
	qitem := &QueueItem{EnvelopeFrom: "alice@example.test", RcptTo: "bob@ext.test", NextAttemptAt: time.Now().UTC()}
	if err = qs.StoreSubmission(ctx, &SubmissionMeta{Message: MessageMeta{
		BlobKey: blobKey, RawSize: 42, Subject: "出站", FromAddr: addr, ToAddrs: `["bob@ext.test"]`,
	}, Items: []*QueueItem{qitem}}); err != nil {
		t.Fatalf("[%s] StoreSubmission: %v", driver, err)
	}
	claimed, err := repos.Queue.ClaimDue(ctx, time.Now().UTC().Add(time.Minute), 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("[%s] ClaimDue: n=%d err=%v", driver, len(claimed), err)
	}
	if claimed[0].Status != QueueInFlight {
		t.Fatalf("[%s] 认领后状态: %s", driver, claimed[0].Status)
	}
	// 二次认领不重叠（四不变量：已认领行不再返回）
	claimed2, err := repos.Queue.ClaimDue(ctx, time.Now().UTC().Add(time.Minute), 10)
	if err != nil || len(claimed2) != 0 {
		t.Fatalf("[%s] ClaimDue 不重叠: n=%d err=%v", driver, len(claimed2), err)
	}
	if err = repos.Queue.MarkResult(ctx, claimed[0].ID, AttemptResult{
		Status: AttemptSent, Attempts: 1,
	}); err != nil {
		t.Fatalf("[%s] MarkResult: %v", driver, err)
	}

	// 8. 会话域（Create/Find——Web 登录存储侧）
	sessHash := fmt.Sprintf("%064x", uniqu+1)[0:64]
	sess := &Session{
		ID: sessHash, SubjectType: SubjectTypeMailbox, SubjectID: mb.ID,
		IP: "127.0.0.1", UserAgent: "u11", CSRFToken: "tok",
		CreatedAt: now, LastSeenAt: now, AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if err = repos.Sessions.Create(ctx, sess); err != nil {
		t.Fatalf("[%s] CreateSession: %v", driver, err)
	}
	found, err := repos.Sessions.Find(ctx, sessHash)
	if err != nil || found.SubjectID != mb.ID || found.CSRFToken != "tok" {
		t.Fatalf("[%s] FindSession: %+v err=%v", driver, found, err)
	}

	// 9. 动态查询路径（Webmail 过滤/搜索——Bob 方言构建在真库执行）
	filtered, ftotal, err := repos.Messages.PageList(ctx, ListQuery{MailboxID: mb.ID, FolderID: inboxID, Limit: 10, Offset: 0, UnreadOnly: true})
	if err != nil || ftotal != 0 || len(filtered) != 0 {
		t.Fatalf("[%s] Webmail 未读过滤: n=%d total=%d err=%v", driver, len(filtered), ftotal, err)
	}
	searched, stotal, err := repos.Messages.Search(ctx, SearchQuery{MailboxID: mb.ID, Keyword: "三库", Limit: 10, Offset: 0})
	if err != nil || stotal != 1 || len(searched) != 1 || searched[0].Subject != "三库实测" {
		t.Fatalf("[%s] 搜索: n=%d total=%d err=%v", driver, len(searched), stotal, err)
	}
	hits, err := repos.Messages.IMAPSearch(ctx, IMAPSearchQuery{MailboxID: mb.ID, FolderID: inboxID, Filter: SearchFilter{From: "bob"}})
	if err != nil || len(hits) != 1 {
		t.Fatalf("[%s] IMAPSearch: n=%d err=%v", driver, len(hits), err)
	}
}

// netDialProbe TCP 探活（compose 就绪探测；GRMAIL_U11_SKIP_DB 置位时直接跳过真库格）。
func netDialProbe(addr string) (struct{}, error) {
	var zero struct{}
	if os.Getenv("GRMAIL_U11_SKIP_DB") != "" {
		return zero, errSkipProbe
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return zero, err
	}
	_ = c.Close()
	return zero, nil
}

// errSkipProbe 环境变量跳过哨兵（netDialProbe 返回非 nil error 即跳过）。
var errSkipProbe = errors.New("跳过真库格（GRMAIL_U11_SKIP_DB）")
