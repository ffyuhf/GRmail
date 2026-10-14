// Webmail前端可用性收口批（α 批——审计实施批）web 侧测试（计划书 v1.0.0 第三章
// 步骤 1~8 验收锚；G2 批准 2026-10-14 20:37 三组候选 E-1-A/E-2-A/E-3-A）。
// 覆盖：①B1 plugins/sieve 两表 th scope+sr-only caption（组件直驱）②B6 详情返回
// 链接保留来源页码（HTTP 层——page=2 上下文断言）③B7 审计点名空体/裸文本点收口
// （sieve 503 双态/password 401/tokens 400——HTTP 状态码语义保持+错误页呈现）
// ④B2/E-1-A 三族成功反馈 noticed 303+notice 呈现（admin setpassword/sieve save/
// tokens revoke）⑤C5 buildDNSRecords 双语（包内直测——en 无中文残留+zh 原文保持）
// ⑥B3/B4 compose data-attach-err/data-rcpt-err 注入锚（JS 交互逻辑 HTTP 层断言面
// 受限登记——沿历批口径）。D9-6（E-3-A 保留中点登记）零代码零断言。
package web

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// ───────────────────────── 环境（u9Env 形态+admin+tokens/sieve 参数化注入） ─────────────────────────

// batch6Env α 批测试环境（sqlite 临时库+管理员+mailbox+消息/文件夹/Token 仓储注入）。
type batch6Env struct {
	srv     *Server
	ts      *httptest.Server
	fds     storage.FolderRepo
	msgs    storage.MessageRepo
	blobs   storage.BlobStore
	mailbox *storage.Mailbox

	mbCk string // mailbox 会话 cookie（登录直通缓存）
	adCk string // admin 会话 cookie（登录直通缓存）
}

// newBatch6Env 构造测试环境。withSieve=true 注入 SieveScripts（B2 sieve 用例——保存
// 303 反馈链）；false 保持 503 渐进态（B7 sieve 用例——未注入态错误页收口断言）。
func newBatch6Env(t *testing.T, withSieve bool) *batch6Env {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "b6.db")})
	if err != nil {
		t.Fatalf("打开临时库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	mbRepo := storage.NewSQLiteMailboxRepo(db)
	fdRepo := storage.NewSQLiteFolderRepo(db)
	msgRepo := storage.NewSQLiteMessageRepo(db)
	sessRepo := storage.NewSQLiteSessionRepo(db)
	users := storage.NewSQLiteUserRepo(db)
	tokens := storage.NewSQLiteTokenRepo(db)
	blobs := storage.NewFileSystemBlobStore(filepath.Join(t.TempDir(), "blobs"))
	accounts := account.NewService(mbRepo, fdRepo)

	adminHash, err := account.HashPassword("b6-admin-pass!")
	if err != nil {
		t.Fatalf("哈希管理员密码: %v", err)
	}
	if err := users.EnsureAdmin(ctx, &storage.User{Username: "admin", PasswordHash: adminHash}); err != nil {
		t.Fatalf("预置管理员: %v", err)
	}
	mb, err := accounts.CreateMailbox(ctx, "b6@test.local", "b6-mb-pass!")
	if err != nil {
		t.Fatalf("创建 mailbox 账号: %v", err)
	}
	cfg := ServerConfig{
		Domain: "test.local", TLSConfig: func() *tls.Config { return nil },
		Messages: msgRepo, Folders: fdRepo, Mailboxes: mbRepo, Blobs: blobs,
		Submit: &u9StubSubmit{}, Tokens: tokens,
	}
	if withSieve {
		cfg.SieveScripts = storage.NewSQLiteSieveScriptRepo(db)
	}
	srv := NewServer(cfg, sessRepo, users, storage.NewSQLiteLoginAttemptRepo(db), accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &batch6Env{srv: srv, ts: ts, fds: fdRepo, msgs: msgRepo, blobs: blobs, mailbox: mb}
}

// b6Post 表单 POST（不跟随重定向——303 Location 断言承载）。
func (e *batch6Env) b6Post(t *testing.T, path string, form url.Values, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}

// b6Get GET（可选 cookie 与额外头——HX 断言承载）。
func (e *batch6Env) b6Get(t *testing.T, path, cookie string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}

// b6Body 读响应体（测试方负责 Close 前调用）。
func b6Body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

// b6LoginMailbox mailbox 登录直通（未绑定 2FA——303）并缓存会话 cookie。
func (e *batch6Env) b6LoginMailbox(t *testing.T) string {
	t.Helper()
	if e.mbCk != "" {
		return e.mbCk
	}
	resp := e.b6Post(t, "/webmail/login", url.Values{
		"address": {e.mailbox.Address}, "password": {"b6-mb-pass!"}}, "")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("mailbox 登录应 303 直通: %d", resp.StatusCode)
	}
	ck := sessionCookieOf(resp)
	if ck == nil {
		t.Fatal("登录直通应签发会话 cookie")
	}
	_ = resp.Body.Close()
	e.mbCk = ck.Value
	return e.mbCk
}

// b6LoginAdmin admin 登录直通（未绑定 2FA——303）并缓存会话 cookie。
func (e *batch6Env) b6LoginAdmin(t *testing.T) string {
	t.Helper()
	if e.adCk != "" {
		return e.adCk
	}
	resp := e.b6Post(t, "/login", url.Values{
		"username": {"admin"}, "password": {"b6-admin-pass!"}}, "")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin 登录应 303 直通: %d", resp.StatusCode)
	}
	ck := sessionCookieOf(resp)
	if ck == nil {
		t.Fatal("登录直通应签发会话 cookie")
	}
	_ = resp.Body.Close()
	e.adCk = ck.Value
	return e.adCk
}

// b6CSRF 从页面响应体提取会话绑定 csrf_token（表单隐藏域形态）。
func b6CSRF(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatal("未从页面提取到 csrf_token")
	}
	return m[1]
}

// b6InboxID 定位当前 mailbox 的收件箱文件夹 ID。
func (e *batch6Env) b6InboxID(t *testing.T) int64 {
	t.Helper()
	folders, err := e.fds.List(context.Background(), e.mailbox.ID)
	if err != nil {
		t.Fatalf("列举文件夹: %v", err)
	}
	for _, f := range folders {
		if f.Kind == storage.FolderKindInbox {
			return f.ID
		}
	}
	t.Fatal("收件箱缺失")
	return 0
}

// ───────────────────────── B1：两表 scope+caption（组件直驱） ─────────────────────────

// TestBatch6B1ScopeCaption B1：plugins 表四 th 与 sieve 表三 th 补 scope="col"+
// sr-only caption（批五 B11 漏网两表——读屏表头关联与表用途播报；视觉零变化）。
func TestBatch6B1ScopeCaption(t *testing.T) {
	w := httptest.NewRecorder()
	if err := templates.PluginsView(templates.PluginsData{
		Lang: string(templates.LangZH), CSRF: "csrf",
		Plugins: []templates.PluginRow{{Name: "p1", Version: "1", Caps: []string{"inbound_hook"}, Alive: true}},
	}).Render(context.Background(), w); err != nil {
		t.Fatalf("plugins 渲染: %v", err)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<th scope="col">`) || !strings.Contains(body, `<caption class="sr-only">`) {
		t.Fatal("plugins 表应补 th scope+sr-only caption（B1）")
	}
	if strings.Count(body, `<th scope="col">`) != 4 {
		t.Fatal("plugins 表四列均应携带 scope")
	}

	w2 := httptest.NewRecorder()
	if err := templates.SieveListView(&templates.SieveListData{
		Lang: templates.LangZH, CSRF: "csrf",
		Scripts: []templates.SieveScriptRow{{Name: "s1", Active: true}},
	}).Render(context.Background(), w2); err != nil {
		t.Fatalf("sieve 渲染: %v", err)
	}
	body2 := w2.Body.String()
	if !strings.Contains(body2, `<th scope="col">`) || !strings.Contains(body2, `<caption class="sr-only">`) {
		t.Fatal("sieve 表应补 th scope+sr-only caption（B1）")
	}
	if strings.Count(body2, `<th scope="col">`) != 3 {
		t.Fatal("sieve 表三列均应携带 scope")
	}
}

// ───────────────────────── B6：返回链接保留来源页码（HTTP 层） ─────────────────────────

// TestBatch6B6BackHrefKeepsPage B6：详情返回链接携带来源页码（page=2 上下文——
// 原恒 page=1 的上下文丢失收口；pagesize 保持）。
func TestBatch6B6BackHrefKeepsPage(t *testing.T) {
	e := newBatch6Env(t, false)
	ctx := context.Background()
	cookie := e.b6LoginMailbox(t)

	raw := []byte("From: a@test.local\r\nTo: b6@test.local\r\nSubject: b6-page-ctx\r\n\r\nbody")
	sum := sha256.Sum256(raw)
	blobKey := hex.EncodeToString(sum[:])
	if err := e.blobs.Write(ctx, blobKey, raw); err != nil {
		t.Fatalf("写 blob: %v", err)
	}
	meta := mail.CachedToMessageMeta(mail.ParseCachedHeaders(raw), blobKey, int64(len(raw)))
	msgID, err := e.msgs.StoreAppend(ctx, e.mailbox.ID, e.b6InboxID(t), &storage.AppendMeta{Message: meta})
	if err != nil {
		t.Fatalf("存邮件: %v", err)
	}

	res := e.b6Get(t, "/mails/"+strconv.FormatInt(msgID, 10)+"?page=2&pagesize=25", cookie,
		map[string]string{"HX-Request": "true"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("详情状态: %d", res.StatusCode)
	}
	body := b6Body(t, res)
	// href 属性值经 HTML 实体转义（&→&——批四 B2 同款形态：以拼接构造 needle）。
	if !strings.Contains(body, "page=2&"+"amp;pagesize=25") {
		t.Fatal("返回链接应保留来源页码 page=2（B6）")
	}
	if strings.Contains(body, "folder=") && strings.Contains(body, "page=1&") {
		t.Fatal("返回链接不应回退第 1 页（B6）")
	}
}

// ───────────────────────── B7：空体/裸文本点收口（状态码保持+错误页） ─────────────────────────

// TestBatch6B7ErrorPages B7：审计点名三点收口断言（HTTP 状态码语义保持——仅响应体
// 从空体/裸文本变错误整页；sieveEditPOST 503/passwordFormGET 401/tokensRevoke 400）。
func TestBatch6B7ErrorPages(t *testing.T) {
	// ① passwordFormGET 无会话直访：requireAuth 中间件先拦（302 登录跳转——E-5-A
	// 无记忆 cookie 缺省 /login）；审计点名 401 防御分支位于中间件之后（会话失效
	// 瞬间防御态），HTTP 层不可达——B7 收口为防御态呈现变化（errPage 化已落码
	// password.go），断言面为中间件 302 语义保持（B7 未波及中间件链）。
	e := newBatch6Env(t, false)
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req1, err := http.NewRequest(http.MethodGet, e.ts.URL+"/settings/password", nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	res1, err := noFollow.Do(req1)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	_ = res1.Body.Close()
	if res1.StatusCode != http.StatusFound {
		t.Fatalf("无会话直访应 302（requireAuth 语义保持）: %d", res1.StatusCode)
	}

	// ② tokensRevoke 400（admin 登录+非法 id——err.page400 错误整页）。
	adminCk := e.b6LoginAdmin(t)
	listRes := e.b6Get(t, "/admin/mailboxes", adminCk, nil)
	csrf := b6CSRF(t, b6Body(t, listRes))
	res2 := e.b6Post(t, "/admin/tokens/abc/revoke", url.Values{"csrf_token": {csrf}}, adminCk)
	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("400 状态码语义应保持: %d", res2.StatusCode)
	}
	// templ 序列化输出小写 <!doctype html——断言不区分大小写（诊断版 Fatalf 保留）。
	if body := b6Body(t, res2); !strings.Contains(strings.ToLower(body), "<!doctype html>") {
		head := body
		if len(head) > 300 {
			head = head[:300]
		}
		t.Fatalf("400 应呈现错误整页（原空体收口——B7）——body(%d字节)=%s", len(body), head)
	}

	// ③ sieveEditPOST 503（SieveScripts 未注入渐进态——原裸 c.String 收口入 errPage）。
	mbCk := e.b6LoginMailbox(t)
	homeRes := e.b6Get(t, "/", mbCk, nil)
	mbCSRF := b6CSRF(t, b6Body(t, homeRes))
	res3 := e.b6Post(t, "/sieve/new", url.Values{
		"name": {"b6s"}, "content": {"keep;"}, "csrf_token": {mbCSRF}}, mbCk)
	if res3.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("503 状态码语义应保持: %d", res3.StatusCode)
	}
	if body := b6Body(t, res3); !strings.Contains(strings.ToLower(body), "<!doctype html>") {
		t.Fatalf("503 应呈现错误整页（原裸文本收口——B7）——body=%q", body)
	}
}

// ───────────────────────── B2/E-1-A：三族成功反馈 noticed 303 ─────────────────────────

// TestBatch6B2NoticedFeedback B2/E-1-A：管理侧三族成功反馈（admin setpassword 303+
// notice 呈现/tokens revoke 303+sieve save 303——原成功静默无文字反馈收口）。
func TestBatch6B2NoticedFeedback(t *testing.T) {
	e := newBatch6Env(t, true)

	// ⓪ sieve 保存（mailbox 主体——旧密码登录先于 admin setpassword 改密：段序承载
	// 密码时序依赖）：303 ?noted=saved+notice。
	mbCk := e.b6LoginMailbox(t)
	homeRes := e.b6Get(t, "/", mbCk, nil)
	mbCSRF := b6CSRF(t, b6Body(t, homeRes))
	svRes := e.b6Post(t, "/sieve/new", url.Values{
		"name": {"b6script"}, "content": {"keep;"}, "csrf_token": {mbCSRF}}, mbCk)
	if svRes.StatusCode != http.StatusSeeOther {
		t.Fatalf("sieve 保存成功应 303: %d", svRes.StatusCode)
	}
	if loc := svRes.Header.Get("Location"); !strings.Contains(loc, "noted=saved") {
		t.Fatalf("sieve 保存 303 Location 应携带 noted=saved: %q", loc)
	}
	_ = svRes.Body.Close()
	nsRes := e.b6Get(t, "/sieve?noted=saved", mbCk, nil)
	if body := b6Body(t, nsRes); !strings.Contains(body, "脚本已保存") {
		t.Fatal("GET ?noted=saved 应呈现成功 notice（B2/E-1-A）")
	}

	// ① admin 行内改密：303 ?noted=password + GET notice 呈现。
	adminCk := e.b6LoginAdmin(t)
	listRes := e.b6Get(t, "/admin/mailboxes", adminCk, nil)
	csrf := b6CSRF(t, b6Body(t, listRes))
	res := e.b6Post(t, "/admin/mailboxes", url.Values{
		"action": {"setpassword"}, "address": {e.mailbox.Address},
		"password": {"b6-new-pass!"}, "csrf_token": {csrf}}, adminCk)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("setpassword 成功应 303: %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "/admin/mailboxes?noted=password") {
		t.Fatalf("303 Location 应携带 noted=password: %q", loc)
	}
	_ = res.Body.Close()
	notedRes := e.b6Get(t, "/admin/mailboxes?noted=password", adminCk, nil)
	if body := b6Body(t, notedRes); !strings.Contains(body, "邮箱密码已修改") {
		t.Fatal("GET ?noted=password 应呈现成功 notice（B2/E-1-A）")
	}

	// ② tokens 撤销：生成→提取 id→revoke 303 ?noted=revoked+notice。
	genRes := e.b6Post(t, "/admin/tokens", url.Values{
		"expires": {"forever"}, "csrf_token": {csrf}}, adminCk)
	if genRes.StatusCode != http.StatusOK {
		t.Fatalf("token 生成状态: %d", genRes.StatusCode)
	}
	tokenPage := b6Body(t, genRes)
	m := regexp.MustCompile(`/admin/tokens/(\d+)/revoke`).FindStringSubmatch(tokenPage)
	if len(m) != 2 {
		t.Fatal("未从列表页提取 revoke 目标 id")
	}
	rvRes := e.b6Post(t, "/admin/tokens/"+m[1]+"/revoke", url.Values{"csrf_token": {csrf}}, adminCk)
	if rvRes.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke 成功应 303: %d", rvRes.StatusCode)
	}
	if loc := rvRes.Header.Get("Location"); !strings.Contains(loc, "noted=revoked") {
		t.Fatalf("revoke 303 Location 应携带 noted=revoked: %q", loc)
	}
	_ = rvRes.Body.Close()
	nrRes := e.b6Get(t, "/admin/tokens?noted=revoked", adminCk, nil)
	if body := b6Body(t, nrRes); !strings.Contains(body, "Token 已撤销") {
		t.Fatal("GET ?noted=revoked 应呈现成功 notice（B2/E-1-A）")
	}
}

// ───────────────────────── C5：setup DNS 占位词双语（包内直测） ─────────────────────────

// TestBatch6C5DNSPlaceholder C5：buildDNSRecords 双语（en 无中文残留——原「你的域名」
// 硬编码收口；zh 原文零变化锚；A 记录引导串同族键化）。
func TestBatch6C5DNSPlaceholder(t *testing.T) {
	cfg := &config.Config{} // 零值：Server.Domain 空——占位词分支
	recsEN := buildDNSRecords(cfg, templates.LangEN)
	if len(recsEN) == 0 {
		t.Fatal("DNS 建议清单非空")
	}
	if recsEN[0].Name != "your domain" {
		t.Fatalf("en 占位词应键化: %q", recsEN[0].Name)
	}
	if strings.Contains(recsEN[0].Note, "主机记录") || strings.Contains(recsEN[0].Note, "你的服务器") {
		t.Fatalf("en 引导串不应残留中文: %q", recsEN[0].Note)
	}
	recsZH := buildDNSRecords(cfg, templates.LangZH)
	if recsZH[0].Name != "你的域名" {
		t.Fatalf("zh 占位词原文保持: %q", recsZH[0].Name)
	}
	// A 记录引导串两态（公网探测成败）zh 原文枚举断言。
	if recsZH[0].Note != "主机记录解析" && recsZH[0].Note != "填你的服务器公网 IP（自动探测不可用——本机处于内网/NAT 环境）" {
		t.Fatalf("zh 引导串原文保持: %q", recsZH[0].Note)
	}
}

// ───────────────────────── B3/B4：compose 前端防线注入锚 ─────────────────────────

// TestBatch6ComposeDataAttrs B3/B4：compose 页 data-attach-err/data-rcpt-err 双语注入
// （compose.js dataset 消费通道；JS 交互逻辑浏览器域——HTTP 层断言注入锚，沿历批口径）。
func TestBatch6ComposeDataAttrs(t *testing.T) {
	e := newBatch6Env(t, false)
	cookie := e.b6LoginMailbox(t)
	res := e.b6Get(t, "/compose", cookie, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("compose 页状态: %d", res.StatusCode)
	}
	body := b6Body(t, res)
	if !strings.Contains(body, `data-attach-err=`) || !strings.Contains(body, "35MiB") {
		t.Fatal("compose 页应注入 data-attach-err 附件预检文案（B3）")
	}
	if !strings.Contains(body, `data-rcpt-err=`) {
		t.Fatal("compose 页应注入 data-rcpt-err 收件人提示文案（B4/E-2-A）")
	}
}
