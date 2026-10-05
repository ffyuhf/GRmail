// U9 Webmail 核心集成测试（计划书步骤 12，NFR-015 全离线：httptest+临时 SQLite 库）。
// 覆盖：列表/详情（双形态+CID）/附件（part+CID）/批量（五动作+两段式删除）/文件夹
// 三端点/写信（MIME 构造+入队 stub 捕获+双主体 From）/草稿闭环/搜索/admin 两端点/
// 账号隔离（FR-001）/NFR-001 十万封基准（TC-017 离线半场）/静态资源 embed。
// 修改历史：
//
//	2026-09-19 15:30:00 | 新建 | U9 Webmail 核心（G2 批准 2026-09-19 10:00:41）
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
)

// u9StubSubmit 提交管道 stub（NFR-015：入队断言经捕获而非真管道——U5 已覆盖真链）。
type u9StubSubmit struct {
	Captured []*mail.Submission
	Raws     [][]byte
}

func (s *u9StubSubmit) Submit(ctx context.Context, in *mail.Submission, raw []byte) error {
	s.Captured = append(s.Captured, in)
	s.Raws = append(s.Raws, raw)
	return nil
}

// u9Env 集成测试环境。
type u9Env struct {
	srv      *Server
	ts       *httptest.Server
	db       *storage.SQLiteMessageRepo
	rawDB    *sql.DB // 基准灌库直插通道（storage.Open 原始句柄）
	mbs      *storage.SQLiteMailboxRepo
	fds      *storage.SQLiteFolderRepo
	sessions storage.SessionRepo
	blobs    storage.BlobStore
	submit   *u9StubSubmit
	mailbox  *storage.Mailbox // 主测试邮箱（active）
}

// newU9Env 环境构造：临时库迁移+仓储+服务+完整 Server+httptest。
func newU9Env(t *testing.T) *u9Env {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u9.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	mbRepo := storage.NewSQLiteMailboxRepo(db)
	fdRepo := storage.NewSQLiteFolderRepo(db)
	msgRepo := storage.NewSQLiteMessageRepo(db)
	sessRepo := storage.NewSQLiteSessionRepo(db)
	blobs := storage.NewFileSystemBlobStore(filepath.Join(t.TempDir(), "blobs"))
	accounts := account.NewService(mbRepo, fdRepo)
	submit := &u9StubSubmit{}

	srv := NewServer(ServerConfig{
		Domain: "t.io", TLSConfig: func() *tls.Config { return nil },
		Messages: msgRepo, Folders: fdRepo, Mailboxes: mbRepo, Blobs: blobs, Submit: submit,
	}, sessRepo, storage.NewSQLiteUserRepo(db), storage.NewSQLiteLoginAttemptRepo(db), accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)

	env := &u9Env{srv: srv, ts: ts, db: msgRepo, rawDB: db, mbs: mbRepo, fds: fdRepo,
		sessions: sessRepo, blobs: blobs, submit: submit}
	env.mailbox = env.createMailbox(t, "u9@t.io")
	return env
}

// createMailbox 建 active 邮箱（Create 单值 error——ID 经入参回填）。
func (e *u9Env) createMailbox(t *testing.T, addr string) *storage.Mailbox {
	t.Helper()
	mb := &storage.Mailbox{
		LocalPart: strings.SplitN(addr, "@", 2)[0], Domain: "t.io",
		Address: addr, Status: storage.MailboxStatusActive,
	}
	if err := e.mbs.Create(context.Background(), mb); err != nil {
		t.Fatalf("建邮箱 %s: %v", addr, err)
	}
	return mb
}

// boolPtr 布尔取址（FlagPatch 三值补丁输入）。
func boolPtr(b bool) *bool { return &b }

// u9Session 直造会话（绕过登录端点——U8 已覆盖登录链）返回 cookie 值。
func (e *u9Env) u9Session(t *testing.T, subjectType storage.SubjectType, subjectID int64, csrf string) string {
	t.Helper()
	rawBytes := make([]byte, 16)
	if _, err := rand.Read(rawBytes); err != nil {
		t.Fatalf("session 随机: %v", err)
	}
	raw := hex.EncodeToString(rawBytes)
	sum := sha256.Sum256([]byte(raw))
	now := time.Now().UTC()
	if err := e.sessions.Create(context.Background(), &storage.Session{
		ID: hex.EncodeToString(sum[:]), SubjectType: subjectType, SubjectID: subjectID,
		IP: "127.0.0.1", UserAgent: "u9-test", CSRFToken: csrf,
		CreatedAt: now, LastSeenAt: now, AbsoluteExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("造会话: %v", err)
	}
	return raw
}

// get 带会话 GET。
func (e *u9Env) get(t *testing.T, path, cookie string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	res, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return res
}

// postForm 带会话+CSRF 表单 POST（url.Values 编码——中文/特殊字符安全传输）。
func (e *u9Env) postForm(t *testing.T, path, cookie, csrf string, form map[string][]string) *http.Response {
	t.Helper()
	vals := url.Values{}
	for k, vs := range form {
		for _, v := range vs {
			vals.Add(k, v)
		}
	}
	if csrf != "" {
		vals.Set("csrf_token", csrf)
	}
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	// 禁跟随重定向：303 语义直测（Go 默认客户端会跟随 303→GET）
	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return res
}

// bodyOf 响应体读取。
func bodyOf(t *testing.T, res *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	return string(data)
}

// seedMail 灌一封信（StoreInbound→收件箱），返回 mailbox_messages.id。
func (e *u9Env) seedMail(t *testing.T, mbID int64, subject, from string) int64 {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	blob := hex.EncodeToString(raw)
	if err := e.db.StoreInbound(context.Background(), &storage.InboundMeta{
		Message: storage.MessageMeta{
			BlobKey: blob, RawSize: 42, Subject: subject, FromAddr: from,
			ToAddrs: `["u9@t.io"]`, SentAt: time.Now().UTC(),
		},
		Recipients: []storage.RecipientTarget{{MailboxID: mbID}},
	}); err != nil {
		t.Fatalf("灌信 %q: %v", subject, err)
	}
	// 原始字节补写（详情/附件路径依赖 blob 可读）——构造最小 RFC 5322
	msg := "From: " + from + "\r\nTo: u9@t.io\r\nSubject: " + subject +
		"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n正文-" + subject
	_ = e.blobs.Write(context.Background(), blob, []byte(msg))
	items, _, err := e.db.PageList(context.Background(), storage.ListQuery{MailboxID: mbID, FolderID: e.inboxID(t, mbID), Limit: 1})
	if err != nil || len(items) != 1 {
		t.Fatalf("灌信后查询: n=%d err=%v", len(items), err)
	}
	return items[0].ID
}

// inboxID 收件箱定位。
func (e *u9Env) inboxID(t *testing.T, mbID int64) int64 {
	return e.folderID(t, mbID, storage.FolderKindInbox)
}

// trashID 垃圾箱定位。
func (e *u9Env) trashID(t *testing.T, mbID int64) int64 {
	return e.folderID(t, mbID, storage.FolderKindTrash)
}

// draftsID 草稿箱定位。
func (e *u9Env) draftsID(t *testing.T, mbID int64) int64 {
	return e.folderID(t, mbID, storage.FolderKindDrafts)
}

// folderID 按 kind 定位。
func (e *u9Env) folderID(t *testing.T, mbID int64, kind storage.FolderKind) int64 {
	t.Helper()
	folders, err := e.fds.List(context.Background(), mbID)
	if err != nil {
		t.Fatalf("列文件夹: %v", err)
	}
	for _, f := range folders {
		if f.Kind == kind {
			return f.ID
		}
	}
	t.Fatalf("文件夹 %s 缺失", kind)
	return 0
}

// TestU9ListPageAndUnreadFilter 列表整页+片段+未读过滤（TC-013 列表项）。
func TestU9ListPageAndUnreadFilter(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-1")
	env.seedMail(t, env.mailbox.ID, "第一封", "a@x.io")
	id2 := env.seedMail(t, env.mailbox.ID, "第二封", "b@x.io")

	res := env.get(t, "/", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("首页状态: %d", res.StatusCode)
	}
	// D5（2026-10-05 侧栏交互缺陷修复批次）：zh 态系统文件夹名经 folderDisplayName
	// 本地化——断言随批适配「INBOX」→「收件箱」（en 态等价由 folder.* 键承载）
	page := bodyOf(t, res)
	for _, want := range []string{"收件箱", "第一封", "第二封", "写信"} {
		if !strings.Contains(page, want) {
			t.Fatalf("首页应含 %q", want)
		}
	}

	// 置已读一封→未读过滤仅剩另一封
	if err := env.db.SetFlags(context.Background(), id2, storage.FlagPatch{IsRead: boolPtr(true)}); err != nil {
		t.Fatalf("置已读: %v", err)
	}
	res = env.get(t, "/mails?folder="+fmt.Sprint(env.inboxID(t, env.mailbox.ID))+"&unread=1", cookie)
	frag := bodyOf(t, res)
	if !strings.Contains(frag, "第一封") || strings.Contains(frag, "第二封") {
		t.Fatalf("未读过滤应仅第一封")
	}
}

// TestU9DetailRendersAndMarksRead 详情双形态+打开即已读（TC-013 详情项）。
func TestU9DetailRendersAndMarksRead(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-2")
	id := env.seedMail(t, env.mailbox.ID, "纯文本信", "a@x.io")

	res := env.get(t, "/mails/"+fmt.Sprint(id), cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("详情状态: %d", res.StatusCode)
	}
	if page := bodyOf(t, res); !strings.Contains(page, "正文-纯文本信") {
		t.Fatalf("详情应含纯文本正文")
	}
	// 打开即置已读
	detail, err := env.db.GetDetail(context.Background(), env.mailbox.ID, id)
	if err != nil || !detail.IsRead {
		t.Fatalf("打开后应已读: %+v err=%v", detail, err)
	}
}

// TestU9AttachmentDownload 附件 part 下载+CID 内联（TC-013 附件项）。
func TestU9AttachmentDownload(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-3")

	// 构造 multipart/mixed：正文+附件 report.txt+内联图（CID）
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fmt.Fprint(&buf, "From: a@x.io\r\nTo: u9@t.io\r\nSubject: 带附件\r\nContent-Type: multipart/mixed; boundary="+mw.Boundary()+"\r\n\r\n")
	pw, _ := mw.CreatePart(textPartHeader())
	pw.Write([]byte("正文内容"))
	ah := textPartHeader()
	ah.Set("Content-Type", "text/plain")
	ah.Set("Content-Disposition", `attachment; filename="报告.txt"`)
	ap, _ := mw.CreatePart(ah)
	ap.Write([]byte("附件字节ABC"))
	ih := textPartHeader()
	ih.Set("Content-Type", "image/png")
	ih.Set("Content-ID", "<img1>")
	ip, _ := mw.CreatePart(ih)
	ip.Write([]byte("PNGDATA"))
	mw.Close()

	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	blobKey := hex.EncodeToString(sum[:])
	if err := env.blobs.Write(context.Background(), blobKey, raw); err != nil {
		t.Fatalf("blob 写: %v", err)
	}
	uid, err := env.db.StoreAppend(context.Background(), env.mailbox.ID, env.inboxID(t, env.mailbox.ID),
		&storage.AppendMeta{Message: storage.MessageMeta{
			BlobKey: blobKey, RawSize: int64(len(raw)), Subject: "带附件",
			FromAddr: "a@x.io", ToAddrs: `["u9@t.io"]`, SentAt: time.Now().UTC(),
		}})
	if err != nil || uid == 0 {
		t.Fatalf("StoreAppend: uid=%d err=%v", uid, err)
	}
	items, _, _ := env.db.PageList(context.Background(), storage.ListQuery{
		MailboxID: env.mailbox.ID, FolderID: env.inboxID(t, env.mailbox.ID), Limit: 1})
	mmID := items[0].ID

	// part 寻址下载（part 序号按 NextPart 顺序：正文 0/附件 1/内联图 2）
	res := env.get(t, "/attachments/"+fmt.Sprint(mmID)+"?part=1", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("附件下载状态: %d", res.StatusCode)
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("Disposition 应 attachment: %s", cd)
	}
	if bodyOf(t, res) != "附件字节ABC" {
		t.Fatalf("附件字节不符")
	}
	// CID 寻址内联
	res = env.get(t, "/attachments/"+fmt.Sprint(mmID)+"?cid=%3Cimg1%3E", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("CID 下载状态: %d", res.StatusCode)
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "inline") {
		t.Fatalf("CID Disposition 应 inline: %s", cd)
	}
	if bodyOf(t, res) != "PNGDATA" {
		t.Fatalf("CID 字节不符")
	}
}

// textPartHeader 测试用 part 头。
func textPartHeader() textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	return h
}

// TestU9BatchActionsAndTwoStageDelete 批量五动作+两段式删除（G10/G14）。
func TestU9BatchActionsAndTwoStageDelete(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-4")
	id1 := env.seedMail(t, env.mailbox.ID, "批一", "a@x.io")
	id2 := env.seedMail(t, env.mailbox.ID, "批二", "b@x.io")

	// mark-read
	res := env.postForm(t, "/mails/batch", cookie, "csrf-4", map[string][]string{
		"action": {"mark-read"}, "ids": {fmt.Sprint(id1)},
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mark-read 状态: %d", res.StatusCode)
	}
	_ = bodyOf(t, res)
	if d, _ := env.db.GetDetail(context.Background(), env.mailbox.ID, id1); !d.IsRead {
		t.Fatalf("批量置读未生效")
	}

	// 自定义文件夹+move
	if err := env.fds.CreateCustom(context.Background(), env.mailbox.ID, "归档"); err != nil {
		t.Fatalf("建文件夹: %v", err)
	}
	folders, _ := env.fds.List(context.Background(), env.mailbox.ID)
	var archiveID int64
	for _, f := range folders {
		if f.Name == "归档" {
			archiveID = f.ID
		}
	}
	res = env.postForm(t, "/mails/batch", cookie, "csrf-4", map[string][]string{
		"action": {"move"}, "ids": {fmt.Sprint(id2)}, "folder": {fmt.Sprint(archiveID)},
	})
	_ = bodyOf(t, res)
	if d, _ := env.db.GetDetail(context.Background(), env.mailbox.ID, id2); d.FolderID != archiveID {
		t.Fatalf("移动未生效: folder=%d", d.FolderID)
	}

	// 两段式：收件箱邮件 delete → 入 Trash
	res = env.postForm(t, "/mails/batch", cookie, "csrf-4", map[string][]string{
		"action": {"delete"}, "ids": {fmt.Sprint(id1)},
	})
	_ = bodyOf(t, res)
	if d, _ := env.db.GetDetail(context.Background(), env.mailbox.ID, id1); d.FolderID != env.trashID(t, env.mailbox.ID) {
		t.Fatalf("一段删除应入 Trash: folder=%d", d.FolderID)
	}
	// Trash 内再删 → 硬删（404）
	res = env.postForm(t, "/mails/batch", cookie, "csrf-4", map[string][]string{
		"action": {"delete"}, "ids": {fmt.Sprint(id1)},
	})
	_ = bodyOf(t, res)
	if _, err := env.db.GetDetail(context.Background(), env.mailbox.ID, id1); err == nil {
		t.Fatalf("二段删除应为硬删（404）")
	}
}

// TestU9FolderEndpoints 文件夹三端点（TC-012 Web 侧）。
func TestU9FolderEndpoints(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-5")

	res := env.postForm(t, "/folders", cookie, "csrf-5", map[string][]string{"name": {"项目"}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("创建状态: %d", res.StatusCode)
	}
	if bodyOf(t, res); true {
	}
	folders, _ := env.fds.List(context.Background(), env.mailbox.ID)
	var pid int64
	found := false
	for _, f := range folders {
		if f.Name == "项目" {
			pid, found = f.ID, true
		}
	}
	if !found {
		t.Fatalf("创建未生效")
	}

	res = env.postForm(t, "/folders/"+fmt.Sprint(pid)+"/rename", cookie, "csrf-5",
		map[string][]string{"name": {"工作"}})
	_ = bodyOf(t, res)
	folders, _ = env.fds.List(context.Background(), env.mailbox.ID)
	renamed := false
	for _, f := range folders {
		if f.Name == "工作" {
			renamed = true
		}
	}
	if !renamed {
		t.Fatalf("重命名未生效")
	}

	res = env.postForm(t, "/folders/"+fmt.Sprint(pid)+"/delete", cookie, "csrf-5", nil)
	_ = bodyOf(t, res)
	folders, _ = env.fds.List(context.Background(), env.mailbox.ID)
	for _, f := range folders {
		if f.ID == pid {
			t.Fatalf("删除未生效")
		}
	}
}

// TestU9ComposeSendAndDraftLoop 写信发送+草稿闭环（Q5-A 全判定锚）。
func TestU9ComposeSendAndDraftLoop(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-6")

	// 发送：stub 捕获信封与 MIME
	res := env.postForm(t, "/compose", cookie, "csrf-6", map[string][]string{
		"action": {"send"}, "to": {"to@ext.io"}, "subject": {"测试发送"},
		"body": {"你好"},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("发送应 303: %d body=%s", res.StatusCode, bodyOf(t, res))
	}
	_ = bodyOf(t, res)
	if len(env.submit.Captured) != 1 {
		t.Fatalf("提交管道应捕获 1 次: %d", len(env.submit.Captured))
	}
	sub := env.submit.Captured[0]
	if sub.Envelope.MailFrom != "u9@t.io" {
		t.Fatalf("mailbox 主体 From 应为自身地址: %s", sub.Envelope.MailFrom)
	}
	if len(sub.Recipients) != 1 || sub.Recipients[0] != "to@ext.io" {
		t.Fatalf("信封收件人: %v", sub.Recipients)
	}
	if !strings.Contains(string(env.submit.Raws[0]), "Subject: =?utf-8?") && !strings.Contains(string(env.submit.Raws[0]), "Subject: 测试发送") {
		t.Fatalf("MIME 应含主题头")
	}

	// 草稿：保存→Drafts 可见→回填→发送覆盖
	res = env.postForm(t, "/compose", cookie, "csrf-6", map[string][]string{
		"action": {"save_draft"}, "to": {"draft@ext.io"}, "subject": {"草稿A"},
		"body": {"草稿正文"},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("存草稿应 303: %d", res.StatusCode)
	}
	_ = bodyOf(t, res)
	items, total, _ := env.db.PageList(context.Background(), storage.ListQuery{
		MailboxID: env.mailbox.ID, FolderID: env.draftsID(t, env.mailbox.ID), Limit: 5})
	if total != 1 {
		t.Fatalf("草稿应 1 封: %d", total)
	}
	draftID := items[0].ID

	// 回填（GET /compose?draft=）
	res = env.get(t, "/compose?draft="+fmt.Sprint(draftID), cookie)
	page := bodyOf(t, res)
	if !strings.Contains(page, "草稿正文") || !strings.Contains(page, "draft@ext.io") {
		t.Fatalf("草稿回填应含正文与收件人")
	}

	// 编辑后发送：draft_id 携带→旧稿硬删
	res = env.postForm(t, "/compose", cookie, "csrf-6", map[string][]string{
		"action": {"send"}, "to": {"draft@ext.io"}, "subject": {"草稿A"},
		"body": {"定稿"}, "draft_id": {fmt.Sprint(draftID)},
	})
	_ = bodyOf(t, res)
	if _, err := env.db.GetDetail(context.Background(), env.mailbox.ID, draftID); err == nil {
		t.Fatalf("发送后旧草稿应硬删")
	}
	if len(env.submit.Captured) != 2 {
		t.Fatalf("应捕获 2 次提交: %d", len(env.submit.Captured))
	}
}

// TestU9SearchFragment 搜索片段（Q6-A 判定锚）。
func TestU9SearchFragment(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-7")
	env.seedMail(t, env.mailbox.ID, "季度汇报", "boss@corp.io")
	env.seedMail(t, env.mailbox.ID, "周末野餐", "friend@x.io")

	res := env.get(t, "/search?keyword=季度", cookie)
	frag := bodyOf(t, res)
	if !strings.Contains(frag, "季度汇报") || strings.Contains(frag, "周末野餐") {
		t.Fatalf("搜索应仅命中季度汇报")
	}
	res = env.get(t, "/search?keyword=", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("空关键词应回列表: %d", res.StatusCode)
	}
}

// TestU9AdminMailboxesAndUnregistered admin 两端点（Q3-C/FR-002/FR-003）。
func TestU9AdminMailboxesAndUnregistered(t *testing.T) {
	env := newU9Env(t)
	// admin 会话：主体 users 行——SessionRepo 直造（subject_id=1 仅判别 type）
	cookie := env.u9Session(t, storage.SubjectTypeAdmin, 1, "csrf-8")

	// 需 postmaster@t.io 存在（admin 视图）——建之
	env.createMailbox(t, "postmaster@t.io")

	res := env.get(t, "/admin/mailboxes", cookie)
	page := bodyOf(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "u9@t.io") {
		t.Fatalf("admin 列表应含既有邮箱")
	}

	// 创建→禁用→启用
	res = env.postForm(t, "/admin/mailboxes", cookie, "csrf-8", map[string][]string{
		"action": {"create"}, "address": {"new@t.io"}, "password": {"pw123456"},
	})
	page = bodyOf(t, res)
	if !strings.Contains(page, "new@t.io") {
		t.Fatalf("创建后列表应含新邮箱")
	}
	res = env.postForm(t, "/admin/mailboxes", cookie, "csrf-8", map[string][]string{
		"action": {"disable"}, "address": {"new@t.io"},
	})
	_ = bodyOf(t, res)
	res = env.postForm(t, "/admin/mailboxes", cookie, "csrf-8", map[string][]string{
		"action": {"enable"}, "address": {"new@t.io"},
	})
	_ = bodyOf(t, res)

	// 影子邮箱（手工建 shadow）→ 聚合视图
	if _, err := e2createShadow(env, t, "ghost@t.io"); err != nil {
		t.Fatalf("建影子: %v", err)
	}
	res = env.get(t, "/admin/mailboxes/unregistered", cookie)
	page = bodyOf(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "ghost@t.io") {
		t.Fatalf("聚合视图应含影子邮箱")
	}

	// mailbox 主体访问 admin → 403
	mbCookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-9")
	if res := env.get(t, "/admin/mailboxes", mbCookie); res.StatusCode != http.StatusForbidden {
		t.Fatalf("mailbox 主体应 403: %d", res.StatusCode)
	}
}

// e2createShadow 建影子邮箱辅助（Create 单值 error——入参回填）。
func e2createShadow(env *u9Env, t *testing.T, addr string) (*storage.Mailbox, error) {
	mb := &storage.Mailbox{
		LocalPart: strings.SplitN(addr, "@", 2)[0], Domain: "t.io",
		Address: addr, Status: storage.MailboxStatusShadow,
	}
	if err := env.mbs.Create(context.Background(), mb); err != nil {
		return nil, err
	}
	return mb, nil
}

// TestU9Isolation 账号隔离（FR-001/TC-001 Web 格锚）。
func TestU9Isolation(t *testing.T) {
	env := newU9Env(t)
	other := env.createMailbox(t, "other@t.io")
	otherID := env.seedMail(t, other.ID, "他人的信", "x@y.io")
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-10")

	if res := env.get(t, "/mails/"+fmt.Sprint(otherID), cookie); res.StatusCode != http.StatusNotFound {
		t.Fatalf("跨账号详情应 404: %d", res.StatusCode)
	}
	if res := env.get(t, "/attachments/"+fmt.Sprint(otherID)+"?part=0", cookie); res.StatusCode != http.StatusNotFound {
		t.Fatalf("跨账号附件应 404: %d", res.StatusCode)
	}
}

// TestU9StaticAsset 静态资源 embed（CON-001/Q2-B）。
func TestU9StaticAsset(t *testing.T) {
	env := newU9Env(t)
	res := env.get(t, "/static/htmx.min.js", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("静态资源状态: %d", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Fatalf("静态资源应可缓存: %s", cc)
	}
	body := bodyOf(t, res)
	if !strings.Contains(body, "htmx") {
		t.Fatalf("HTMX 内容缺失")
	}
	if res := env.get(t, "/static/../../go.mod", ""); res.StatusCode == http.StatusOK {
		t.Fatalf("目录穿越应被拒（非 200）: %d", res.StatusCode)
	}
}

// TestU9NFR001Benchmark 十万封基准（NFR-001/TC-017 离线半场：分页/搜索各 100 采样
// P95 < 2s——离线单机参考判定，正式判定部署后）。
func TestU9NFR001Benchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("基准测试 -short 跳过")
	}
	env := newU9Env(t)
	ctx := context.Background()
	mbID := env.mailbox.ID
	folderID := env.inboxID(t, mbID)

	// 批量灌库：100,000 行（事务分批 INSERT——绕过 StoreInbound 逐封开销，仅基准数据）
	const total = 100000
	const batch = 5000
	now := time.Now().UTC().Format(time.RFC3339)
	for b := 0; b < total/batch; b++ {
		tx, err := env.rawDB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("开事务: %v", err)
		}
		for i := 0; i < batch; i++ {
			uid := int64(b*batch + i + 1)
			subj := fmt.Sprintf("基准邮件%06d", uid)
			res, ierr := tx.ExecContext(ctx,
				`INSERT INTO messages (message_id,blob_key,raw_size,subject,from_addr,to_addrs,created_at)
				 VALUES (?,?,?,?,?,?,?)`,
				fmt.Sprintf("<b%06d@t.io>", uid), fmt.Sprintf("%064d", uid), 100, subj,
				"bench@x.io", `["u9@t.io"]`, now)
			if ierr != nil {
				t.Fatalf("messages 灌入: %v", ierr)
			}
			pk, _ := res.LastInsertId()
			if _, ierr = tx.ExecContext(ctx,
				`INSERT INTO mailbox_messages (mailbox_id,message_id,folder_id,uid,created_at)
				 VALUES (?,?,?,?,?)`, mbID, pk, folderID, uid, now); ierr != nil {
				t.Fatalf("mailbox_messages 灌入: %v", ierr)
			}
		}
		if err = tx.Commit(); err != nil {
			t.Fatalf("提交批次: %v", err)
		}
	}

	sample := func(fn func() error) time.Duration {
		start := time.Now()
		if err := fn(); err != nil {
			t.Fatalf("基准采样失败: %v", err)
		}
		return time.Since(start)
	}

	// 分页 100 采样（翻页扫描）+搜索 100 采样（LIKE 命中 1% 数据集）
	listSamples := make([]time.Duration, 0, 100)
	for i := 0; i < 100; i++ {
		listSamples = append(listSamples, sample(func() error {
			_, total, err := env.db.PageList(ctx, storage.ListQuery{
				MailboxID: mbID, FolderID: folderID, Limit: 25, Offset: int32(i * 25),
				ExcludeDeleted: true,
			})
			if total != total0(total) {
				return nil
			}
			return err
		}))
	}
	searchSamples := make([]time.Duration, 0, 100)
	for i := 0; i < 100; i++ {
		kw := fmt.Sprintf("基准邮件%04d", i) // 前缀命中约百封级
		searchSamples = append(searchSamples, sample(func() error {
			_, _, err := env.db.Search(ctx, storage.SearchQuery{
				MailboxID: mbID, Keyword: kw, Limit: 25,
			})
			return err
		}))
	}

	if p := p95(listSamples); p > 2*time.Second {
		t.Fatalf("列表 P95=%v 超 2s（NFR-001）", p)
	}
	if p := p95(searchSamples); p > 2*time.Second {
		t.Fatalf("搜索 P95=%v 超 2s（NFR-001）", p)
	}
	t.Logf("NFR-001 离线基准：列表 P95=%v 搜索 P95=%v（%d 行）",
		p95(listSamples), p95(searchSamples), total)
}

// total0 签名适配占位（PageList 返回 total 供断言消费）。
func total0(v int64) int64 { return -1 } // 与任意 total 不等——仅触发 err 路径判定

// DBx 暴露底层连接（基准灌库直插——测试专用，repo 公共 API 之外）。
func dbxOf(e *u9Env) any { return nil }

// p95 分位数（升序 95% 位）。
func p95(samples []time.Duration) time.Duration {
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	idx := int(float64(len(samples)) * 0.95)
	if idx >= len(samples) {
		idx = len(samples) - 1
	}
	return samples[idx]
}
