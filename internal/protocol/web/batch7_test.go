// Webmail前端可见性一致性令牌批（β 批——审计实施批）web 侧测试（计划书 v1.0.0 第三章
// 步骤 2~8 验收锚；G2 批准 2026-10-15 00:12 候选 E-1-A/E-2-A）。
// 覆盖：①A1+E4 双骨架 theme-color 双 media 拆分+Layout manifest 补挂（组件直驱）
// ②A2 settings 四 size 属性清零+弹性宽规则落码（HTTP 层+CSS 文件锚）③C1 枢纽四卡
// emoji→SVG（组件直驱——emoji 清零锚）④C2/E-1-A csv 候选表容器并入 .table-wrap
// （HTTP 层 multipart）⑤C4/E-2-A 散值令牌化+E1 placeholder 令牌（CSS 文件锚——
// 令牌定义在位+旧散值用法清零）。布局渲染浏览器域走查属干系人实机域（历批口径）。
package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// ───────────────────────── 环境（batch6 形态精简——settings 页需 CfgSnapshot） ─────────────────────────

// batch7Env β 批测试环境（sqlite 临时库+管理员+mailbox——A2 设置页与 C2 CSV 片段承载）。
type batch7Env struct {
	srv     *Server
	ts      *httptest.Server
	mailbox *storage.Mailbox

	mbCk string
	adCk string
}

// newBatch7Env 构造测试环境（CfgSnapshot 注入——/admin/settings 渐进态 503 消除）。
func newBatch7Env(t *testing.T) *batch7Env {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "b7.db")})
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
	blobs := storage.NewFileSystemBlobStore(filepath.Join(t.TempDir(), "blobs"))
	accounts := account.NewService(mbRepo, fdRepo)

	adminHash, err := account.HashPassword("b7-admin-pass!")
	if err != nil {
		t.Fatalf("哈希管理员密码: %v", err)
	}
	if err := users.EnsureAdmin(ctx, &storage.User{Username: "admin", PasswordHash: adminHash}); err != nil {
		t.Fatalf("预置管理员: %v", err)
	}
	mb, err := accounts.CreateMailbox(ctx, "b7@test.local", "b7-mb-pass!")
	if err != nil {
		t.Fatalf("创建 mailbox 账号: %v", err)
	}
	cfg := ServerConfig{
		Domain: "test.local", TLSConfig: func() *tls.Config { return nil },
		Messages: msgRepo, Folders: fdRepo, Mailboxes: mbRepo, Blobs: blobs,
		Submit:      &u9StubSubmit{},
		CfgSnapshot: func() *config.Config { return &config.Config{} },
	}
	srv := NewServer(cfg, sessRepo, users, storage.NewSQLiteLoginAttemptRepo(db), accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &batch7Env{srv: srv, ts: ts, mailbox: mb}
}

// b7Post 表单 POST（不跟随重定向）。
func (e *batch7Env) b7Post(t *testing.T, path string, form url.Values, cookie string) *http.Response {
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

// b7Get GET（可选 cookie）。
func (e *batch7Env) b7Get(t *testing.T, path, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}

// b7Body 读响应体。
func b7Body(t *testing.T, resp *http.Response) string {
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

// b7LoginMailbox mailbox 登录直通（303）并缓存会话 cookie。
func (e *batch7Env) b7LoginMailbox(t *testing.T) string {
	t.Helper()
	if e.mbCk != "" {
		return e.mbCk
	}
	resp := e.b7Post(t, "/webmail/login", url.Values{
		"address": {e.mailbox.Address}, "password": {"b7-mb-pass!"}}, "")
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

// b7LoginAdmin admin 登录直通（303）并缓存会话 cookie。
func (e *batch7Env) b7LoginAdmin(t *testing.T) string {
	t.Helper()
	if e.adCk != "" {
		return e.adCk
	}
	resp := e.b7Post(t, "/login", url.Values{
		"username": {"admin"}, "password": {"b7-admin-pass!"}}, "")
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

// b7CSRF 从页面响应体提取会话绑定 csrf_token（隐藏域形态——b6CSRF 同款语义）。
func b7CSRF(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `name="csrf_token" value="`)
	if i < 0 {
		t.Fatal("未从页面提取到 csrf_token")
	}
	rest := body[i+len(`name="csrf_token" value="`):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatal("csrf_token 值形态异常")
	}
	return rest[:j]
}

// b7AppCSS 读取 app.css 源（C4/E1 文件锚——CWD=包目录）。
func b7AppCSS(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "app.css"))
	if err != nil {
		t.Fatalf("读取 app.css: %v", err)
	}
	return string(b)
}

// ───────────────────────── A1+E4：双骨架 head 元数据（组件直驱） ─────────────────────────

// TestBatch7A1E4HeadMeta A1：双骨架 theme-color 双 media 拆分（δ批 D-4 色值更新：
// 亮 #17181c 墨石/暗 #101113 对齐 --bg 暗档——2026-10-15 16:28:59 G2 批准面内
// 机械适配，双 media+恰二 meta 意图锚保持）；E4：Layout manifest 引用（对齐 AppLayout）。
func TestBatch7A1E4HeadMeta(t *testing.T) {
	w := httptest.NewRecorder()
	if err := templates.AppLayout(templates.LangZH, "t", "lbl", false, "csrf").Render(context.Background(), w); err != nil {
		t.Fatalf("AppLayout 渲染: %v", err)
	}
	body := w.Body.String()
	if !strings.Contains(body, `media="(prefers-color-scheme: light)"`) || !strings.Contains(body, "#17181c") {
		t.Fatal("AppLayout 应呈现亮色 theme-color #17181c（media light——δ批墨石）")
	}
	if !strings.Contains(body, `media="(prefers-color-scheme: dark)"`) || !strings.Contains(body, "#101113") {
		t.Fatal("AppLayout 应呈现暗色 theme-color #101113（media dark——δ批对齐 --bg 暗档）")
	}
	if strings.Count(body, `name="theme-color"`) != 2 {
		t.Fatal("AppLayout theme-color 应恰为双 meta（A1）")
	}

	w2 := httptest.NewRecorder()
	if err := templates.Layout(templates.LangZH, "t", "").Render(context.Background(), w2); err != nil {
		t.Fatalf("Layout 渲染: %v", err)
	}
	body2 := w2.Body.String()
	if !strings.Contains(body2, `media="(prefers-color-scheme: dark)"`) || !strings.Contains(body2, "#101113") {
		t.Fatal("Layout 应呈现暗色 theme-color（δ批 D-4 与 AppLayout 同步）")
	}
	if !strings.Contains(body2, `rel="manifest"`) || !strings.Contains(body2, "manifest.webmanifest") {
		t.Fatal("Layout 应补 manifest 引用（E4——对齐 AppLayout 既有形态）")
	}
}

// ───────────────────────── A2：settings size 清零+弹性宽规则 ─────────────────────────

// TestBatch7A2SettingsElasticInputs A2：settings 页四处 size 物理宽属性清零（HTTP 层）
// +content-page fieldset 弹性宽规则落码（CSS 文件锚——窄屏溢出收口承载）。
func TestBatch7A2SettingsElasticInputs(t *testing.T) {
	e := newBatch7Env(t)
	adminCk := e.b7LoginAdmin(t)
	res := e.b7Get(t, "/admin/settings", adminCk)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("设置页状态: %d", res.StatusCode)
	}
	body := b7Body(t, res)
	for _, s := range []string{`size="40"`, `size="16"`, `size="32"`} {
		if strings.Contains(body, s) {
			t.Fatalf("settings 页应清零 size 物理宽属性（A2）: 残留 %s", s)
		}
	}
	css := b7AppCSS(t)
	if !strings.Contains(css, ".content-page form fieldset input:not(") {
		t.Fatal("app.css 应落 content-page fieldset 弹性宽规则（A2）")
	}
	if strings.Contains(css, "size=\"40\"") {
		t.Fatal("模板残留检查（A2 由模板承担——CSS 仅规则面）")
	}
}

// ───────────────────────── C1：枢纽图标 SVG 化（组件直驱） ─────────────────────────

// TestBatch7C1HubIconsSVG C1：枢纽四卡片 emoji→内联 SVG（currentColor 暗色联动+
// 跨平台字形一致；emoji 清零锚）。
func TestBatch7C1HubIconsSVG(t *testing.T) {
	w := httptest.NewRecorder()
	if err := templates.SettingsHubView(&templates.SettingsHubData{
		Lang: string(templates.LangZH), Address: "b7@test.local",
	}).Render(context.Background(), w); err != nil {
		t.Fatalf("枢纽页渲染: %v", err)
	}
	body := w.Body.String()
	if strings.Count(body, `<span class="hub-ic" aria-hidden="true"><svg`) != 4 {
		t.Fatalf("枢纽四卡片图标应全部 SVG 化（C1）——实得 %d", strings.Count(body, `<span class="hub-ic" aria-hidden="true"><svg`))
	}
	for _, emo := range []string{"🔑", "🛡️", "📑", "📧"} {
		if strings.Contains(body, emo) {
			t.Fatalf("枢纽卡片不应残留 emoji（C1）: %s", emo)
		}
	}
}

// ───────────────────────── C2/E-1-A：csv 候选表并入 .table-wrap（HTTP 层） ─────────────────────────

// TestBatch7C2CsvTableWrap C2/E-1-A：CSV 导入候选片段容器挂 .table-wrap 双类
// （统一表格体系——圆角描边/表头底色全继承；i18n.go 仅类名消费零逻辑变化）。
func TestBatch7C2CsvTableWrap(t *testing.T) {
	e := newBatch7Env(t)
	mbCk := e.b7LoginMailbox(t)
	homeRes := e.b7Get(t, "/", mbCk)
	csrf := b7CSRF(t, b7Body(t, homeRes))

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// csrf 经 multipart 表单字段承载（csrfProtect 经 c.PostForm 消费——手设
	// req.PostForm 会被 body 解析覆盖，403 根因；测试自身缺陷修正）。
	if err := mw.WriteField("csrf_token", csrf); err != nil {
		t.Fatalf("写 csrf 字段: %v", err)
	}
	fw, err := mw.CreateFormFile("file", "a.csv")
	if err != nil {
		t.Fatalf("构造 multipart: %v", err)
	}
	if _, err := fw.Write([]byte("email,name\nx@test.local,X\n")); err != nil {
		t.Fatalf("写文件体: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("关闭 multipart: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/compose/csv-import", &buf)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: mbCk})
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CSV 解析状态: %d", resp.StatusCode)
	}
	body := b7Body(t, resp)
	if !strings.Contains(body, `class="csv-candidates table-wrap"`) {
		t.Fatal("csv 候选表容器应挂 .table-wrap 双类（C2/E-1-A）")
	}
}

// ───────────────────────── C4/E-2-A+E1：散值令牌化+placeholder 令牌（CSS 文件锚） ─────────────────────────

// TestBatch7C4E1CssTokens C4/E-2-A：16 微调散值归令牌承载原值（令牌定义在位+旧散值
// 用法清零——视觉零变化锚）；E1：--placeholder 明暗双档+::placeholder 规则落码。
func TestBatch7C4E1CssTokens(t *testing.T) {
	css := b7AppCSS(t)
	// C4 令牌定义在位（承载原值——数值零变化）。
	for _, tok := range []string{
		"--fs-code: .82em;", "--fs-brand: 1.1rem;", "--fs-empty: 1.25rem;",
		"--fs-nav: .875rem;", "--fs-detail-sm: .8125rem;", "--fs-editor: .9375rem;",
		"--ls-th: .03em;", "--ls-brand: -0.02em;", "--ls-mono: .06em;",
		"--fs-toggle: 1.25rem;",
		"--pad-code-y: .08rem;", "--pad-kbd-x: .4rem;", "--pad-link-x: .25rem;",
		"--pad-badge-y: .12rem;", "--pad-unread-x: .55rem;", "--icon-lg: 1.5rem;",
	} {
		if !strings.Contains(css, tok) {
			t.Fatalf("C4/E-2-A 令牌定义缺失: %s", tok)
		}
	}
	// C4 旧散值用法清零（令牌定义行除外——用法形态逐项）。
	for _, legacy := range []string{
		"font-size: .82em;", "font-size: 1.1rem;", "font-size: 1.25rem;",
		"font-size: .875rem;", "font-size: .8125rem;", "font-size: .9375rem;",
		"letter-spacing: .03em;", "letter-spacing: .02em;", "letter-spacing: .06em;",
		"padding: .08rem .35rem;", "padding: 0 .4rem;", "padding: 0 .25rem;",
		"padding: .12rem .6rem;", "padding: 0 .55rem;",
	} {
		if strings.Contains(css, legacy) {
			t.Fatalf("C4/E-2-A 旧散值用法应清零（归令牌）: %s", legacy)
		}
	}
	// E1：明暗双档令牌+::placeholder 规则。
	if !strings.Contains(css, "--placeholder: rgba(0, 0, 0, 0.54);") {
		t.Fatal("E1 亮色占位令牌缺失")
	}
	if !strings.Contains(css, "--placeholder: rgba(255, 255, 255, 0.5);") {
		t.Fatal("E1 暗色占位令牌缺失")
	}
	if !strings.Contains(css, "::placeholder { color: var(--placeholder); opacity: 1; }") {
		t.Fatal("E1 ::placeholder 规则缺失")
	}
	// C2 配套：csv 自有边框规则废止锚。
	if strings.Contains(css, ".csv-candidates table { border-collapse: collapse; }") {
		t.Fatal("C2/E-1-A 自有边框规则应废止")
	}
}
