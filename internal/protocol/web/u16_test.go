// U16 Webmail 体验收尾测试（NFR-015 全离线——纯函数与临时库直驱）。
// 覆盖：①i18n 文案表双语矩阵+缺省回落 ②CSV 解析纯函数矩阵（分隔符/表头中英列/
// 无效行跳过/无表头宽容）③/lang 端点（cookie 设置+站内重定向+开放重定向拒绝）
// ④body_cache 全链（StoreAppend 写入往返+ListBodyCachePending/FillBodyCache 回填
// 幂等+Search 第四列命中——临时 SQLite 真库）。
// 依据：U16 计划书 1.5⑧（Q2-A/Q3-A/Q5-A 断言锚）；契约 v1.12.0。
// Sent 副本 e2e（登录→发信→Sent 计数）与深级管理页双语断言登记为下次触碰批次
// 补强（修改文档第三章登记——archiveSentCopy 经编译级接线+StoreAppend 同构路径覆盖）。
// 修改历史：
//
//	2026-09-24 21:52:00 | 新建 | U16 Webmail 体验收尾（计划书步骤 7，G2 批准 2026-09-24 11:51:57）
package web

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"GRmail/internal/config"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// TestU16I18nTextMatrix 双语文案矩阵：zh 缺省/en 取值/非法值回落/格式化占位。
func TestU16I18nTextMatrix(t *testing.T) {
	if got := templates.Tr(templates.LangZH, "common.logout"); got != "登出" {
		t.Fatalf("zh 登出文案不符: %q", got)
	}
	if got := templates.Tr(templates.LangEN, "common.logout"); got != "Log out" {
		t.Fatalf("en 登出文案不符: %q", got)
	}
	if got := templates.Tr(templates.NormalizeLang("xx-bad"), "common.logout"); got != "登出" {
		t.Fatalf("非法语言未回落 zh: %q", got)
	}
	if got := templates.Tr(templates.LangZH, "nonexistent.key"); got != "nonexistent.key" {
		t.Fatalf("缺 key 未机械兜底: %q", got)
	}
	if got := templates.Trf(templates.LangEN, "mail.totalFmt", 42); got != "42 total" {
		t.Fatalf("en 格式化占位不符: %q", got)
	}
	if got := templates.Trf(templates.LangZH, "mail.pageFmt", 2, 9); got != "第 2 / 9 页" {
		t.Fatalf("zh 格式化占位不符: %q", got)
	}
}

// TestU16CsvParseMatrix CSV 解析矩阵：四分隔符/中英表头/姓名列/无效行跳过/无表头宽容。
func TestU16CsvParseMatrix(t *testing.T) {
	// 逗号+英文表头
	rows, skipped := parseCSVRecipients([]byte("email,name\na@x.com,Alice\nb@x.com,Bob\n"))
	if len(rows) != 2 || rows[0].Addr != "a@x.com" || rows[0].Name != "Alice" || skipped != 0 {
		t.Fatalf("逗号+英文表头解析不符: %+v skipped=%d", rows, skipped)
	}
	// 分号+中文表头
	rows, _ = parseCSVRecipients([]byte("邮箱;姓名\na@x.com;张三\n"))
	if len(rows) != 1 || rows[0].Name != "张三" {
		t.Fatalf("分号+中文表头解析不符: %+v", rows)
	}
	// 制表符+管道
	rows, _ = parseCSVRecipients([]byte("e-mail\tname\nc@x.com\tC\n"))
	if len(rows) != 1 || rows[0].Addr != "c@x.com" {
		t.Fatalf("制表符解析不符: %+v", rows)
	}
	if detectCsvDelimiter("a|b|c") != '|' {
		t.Fatalf("管道分隔符检测不符")
	}
	// 无效行跳过（非法地址+重复地址；空行经 csv.Reader 自动跳过不计 skipped）
	rows, skipped = parseCSVRecipients([]byte("email\nbad-addr\n\nd@x.com\nd@x.com\n"))
	if len(rows) != 1 || rows[0].Addr != "d@x.com" || skipped != 2 {
		t.Fatalf("无效行跳过计数不符: %+v skipped=%d", rows, skipped)
	}
	// 无表头宽容（单列纯地址清单——首行也按数据解析）
	rows, _ = parseCSVRecipients([]byte("e@x.com\nf@x.com\n"))
	if len(rows) != 2 || rows[0].Addr != "e@x.com" {
		t.Fatalf("无表头宽容解析不符: %+v", rows)
	}
	// 空输入
	if rows, skipped = parseCSVRecipients(nil); len(rows) != 0 || skipped != 0 {
		t.Fatalf("空输入不符: %+v", rows)
	}
}

// TestU16LangSetEndpoint /lang 端点：cookie 设置+站内重定向+站外路径拒绝回 /。
func TestU16LangSetEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{engine: gin.New()}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/lang?l=en&next=/mails", nil)
	s.langSetGET(c)
	if w.Code != 302 {
		t.Fatalf("重定向状态码不符: %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/mails" {
		t.Fatalf("站内重定向不符: %q", loc)
	}
	found := false
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "lang" && ck.Value == "en" {
			found = true
		}
	}
	if !found {
		t.Fatalf("lang cookie 未设置")
	}
	// 站外路径拒绝（协议相对形态同拒——开放重定向防线）
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest("GET", "/lang?l=zh&next=//evil.com", nil)
	s.langSetGET(c2)
	if loc := w2.Header().Get("Location"); loc != "/" {
		t.Fatalf("站外路径未拒绝回 /: %q", loc)
	}
}

// TestU16BodyCacheFullChain body_cache 全链（临时 SQLite 真库）：StoreAppend 写入
// 往返（第四列填充）→ListBodyCachePending 空（已即时填充）→手工置 NULL 后回填
// 幂等→Search 第四列命中（三缓存列不命中场景）。
func TestU16BodyCacheFullChain(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u16.db")})
	if err != nil {
		t.Fatalf("临时库打开失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err = storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	mbRepo := storage.NewMailboxRepoFor("sqlite", db)
	fdRepo := storage.NewFolderRepoFor("sqlite", db)
	msgs := storage.NewSQLiteMessageRepo(db)

	mb := &storage.Mailbox{LocalPart: "u16", Domain: "test.local", Address: "u16@test.local", Status: storage.MailboxStatusActive}
	if err = mbRepo.Create(ctx, mb); err != nil {
		t.Fatalf("邮箱创建失败: %v", err)
	}
	if err = fdRepo.EnsureSystemFolders(ctx, mb.ID); err != nil {
		t.Fatalf("系统文件夹初始化失败: %v", err)
	}
	folders, _ := fdRepo.List(ctx, mb.ID)
	var inboxID int64
	for _, f := range folders {
		if f.Kind == storage.FolderKindInbox {
			inboxID = f.ID
		}
	}
	// 写入路径：StoreAppend（IMAP APPEND 路径等价——meta.BodyCache 填充）
	raw := []byte("From: s@x.com\r\nTo: u16@test.local\r\nSubject: cap\r\n\r\nunique_body_token_here\r\n")
	meta := storage.MessageMeta{
		BlobKey: "u16fakeblob0000000000000000000000000000000000000000000000000000",
		Subject: "cap", FromAddr: "s@x.com", ToAddrs: `["u16@test.local"]`,
		BodyCache: "unique_body_token_here", RawSize: int64(len(raw)),
	}
	if _, err = msgs.StoreAppend(ctx, mb.ID, inboxID, &storage.AppendMeta{Message: meta}); err != nil {
		t.Fatalf("StoreAppend 失败: %v", err)
	}
	// 即时填充：待回填批查为空
	if pend, _ := msgs.ListBodyCachePending(ctx, 10); len(pend) != 0 {
		t.Fatalf("即时填充后不应有待回填行: %d", len(pend))
	}
	// 搜索第四列命中（subject/from/to 均不含 unique_body_token——仅 body_cache 命中）
	items, total, err := msgs.Search(ctx, storage.SearchQuery{MailboxID: mb.ID, Keyword: "unique_body_token", Limit: 10})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("正文缓存搜索命中不符: total=%d items=%d err=%v", total, len(items), err)
	}
	// 回填幂等：置 NULL 后回填，再批查为空
	if _, err = db.ExecContext(ctx, "UPDATE messages SET body_cache = NULL"); err != nil {
		t.Fatalf("置 NULL 失败: %v", err)
	}
	pend, _ := msgs.ListBodyCachePending(ctx, 10)
	if len(pend) != 1 {
		t.Fatalf("置 NULL 后待回填行数不符: %d", len(pend))
	}
	if err = msgs.FillBodyCache(ctx, pend[0].ID, "unique_body_token_here"); err != nil {
		t.Fatalf("回填失败: %v", err)
	}
	if pend2, _ := msgs.ListBodyCachePending(ctx, 10); len(pend2) != 0 {
		t.Fatalf("回填后不应残留待回填行: %d", len(pend2))
	}
	// 回填后搜索仍命中
	if _, total, err = msgs.Search(ctx, storage.SearchQuery{MailboxID: mb.ID, Keyword: "unique_body_token", Limit: 10}); err != nil || total != 1 {
		t.Fatalf("回填后搜索命中不符: total=%d err=%v", total, err)
	}
}

// TestU16BodyCacheOfExtraction 截断提取单点：正常提取+截断上限+畸形输入空串兜底。
func TestU16BodyCacheOfExtraction(t *testing.T) {
	raw := []byte("From: a@b.c\r\nSubject: t\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello body text\r\n")
	if got := mailBodyCacheForTest(raw); !strings.HasPrefix(got, "hello body text") {
		t.Fatalf("正文提取不符: %q", got)
	}
	long := strings.Repeat("x", 70000)
	if got := len(mailBodyCacheForTest([]byte("Content-Type: text/plain\r\n\r\n" + long))); got != 65536 {
		t.Fatalf("截断上限不符: %d", got)
	}
	if got := mailBodyCacheForTest([]byte("garbage")); got != "" {
		t.Fatalf("畸形输入未兜底空串: %q", got)
	}
}

// mailBodyCacheForTest 截断提取单点包装（mail.BodyCacheOf——测试内直驱）。
func mailBodyCacheForTest(raw []byte) string {
	return mail.BodyCacheOf(raw)
}
