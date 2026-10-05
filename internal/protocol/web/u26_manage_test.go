// Webmail管理职能批次 web 层全离线测试（NFR-015：httptest+临时 SQLite 库，零网络依赖）。
// 覆盖：G1 密码三通道（admin 自身改密[旧密码验证+主体一致性+会话重建]/mailbox 个人改密
// [旧密码验证+会话重建]/admin 行内 setpassword action）+G2 个人设置枢纽（mailbox 四分区
// 渲染+admin 302 管理枢纽）+G6 插件状态页（nil=503 渐进态+注入后 200 呈现）。
// 依据：Webmail管理职能计划书 v1.0.0 第三章检查点（G2 批准 2026-10-05 15:15:22）；
// SRS FR-001/002/013/016；TC-001/002 伴随口径。
// 修改历史：
//
//	2026-10-05 15:30:00 | 新增 | Webmail管理职能批次（计划书阶段 7）
package web

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// u26Env 管理职能批次测试环境（u24Env 形态——临时库+管理员+mailbox+可选 Plugins 注入）。
type u26Env struct {
	srv     *Server
	ts      *httptest.Server
	plugins PluginStatusSource
}

// newU26Env 构造测试环境（plugins 非nil时注入——G6 两态用例数据源）。
func newU26Env(t *testing.T, plugins PluginStatusSource) *u26Env {
	t.Helper()
	db, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: t.TempDir() + "/u26web.db"})
	if err != nil {
		t.Fatalf("打开临时库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.MigrateUp(context.Background(), db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	mailboxRepo := storage.NewSQLiteMailboxRepo(db)
	folderRepo := storage.NewSQLiteFolderRepo(db)
	users := storage.NewSQLiteUserRepo(db)
	sessions := storage.NewSQLiteSessionRepo(db)
	attempts := storage.NewSQLiteLoginAttemptRepo(db)
	accounts := account.NewService(mailboxRepo, folderRepo)

	hash, err := account.HashPassword("admin-pass!")
	if err != nil {
		t.Fatalf("哈希管理员密码: %v", err)
	}
	if err := users.EnsureAdmin(context.Background(), &storage.User{Username: "admin", PasswordHash: hash}); err != nil {
		t.Fatalf("预置管理员: %v", err)
	}
	if _, err := accounts.CreateMailbox(context.Background(), "u26@test.local", "mb-pass!"); err != nil {
		t.Fatalf("创建 mailbox 账号: %v", err)
	}

	srv := NewServer(ServerConfig{
		Domain:    "test.local",
		TLSConfig: func() *tls.Config { return nil },
		Mailboxes: mailboxRepo,
		Plugins:   plugins,
	}, sessions, users, attempts, accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &u26Env{srv: srv, ts: ts, plugins: plugins}
}

// u26Client 带 cookie jar 的客户端（禁跟随重定向——303 断言锚）。
func u26Client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// u26Login 登录并返回会话 cookie 值（kind=admin|mailbox 分派端点）。
func u26Login(t *testing.T, c *http.Client, ts, kind, user, pass string) string {
	t.Helper()
	endpoint := "/login"
	form := url.Values{"username": {user}, "password": {pass}}
	if kind == "mailbox" {
		endpoint = "/webmail/login"
		form = url.Values{"address": {user}, "password": {pass}}
	}
	resp := u26Post(t, c, ts+endpoint, form, "")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("登录应 303: %d", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == "__Host-sid" || ck.Name == "sid" {
			return ck.Value
		}
	}
	t.Fatalf("登录未签发会话 cookie")
	return ""
}

// u26Post 表单 POST（csrf 非空时附 token；返回响应——body 由调用方按需读取）。
func u26Post(t *testing.T, c *http.Client, target string, form url.Values, csrf string) *http.Response {
	t.Helper()
	if csrf != "" {
		form.Set("csrf_token", csrf)
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}

// u26CSRF GET 页面抓取 csrf_token 隐藏域值（认证会话表单消费——csrfProtect 校验锚）。
func u26CSRF(t *testing.T, c *http.Client, target string) string {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(string(body))
	if len(m) != 2 {
		t.Fatalf("页面 %s 未含 csrf_token", target)
	}
	return m[1]
}

// TestU26AdminPasswordChange 管理员自身改密通道（G1）：
// 旧密码错误拒绝（可读文案）→ 正确改密 303+会话 cookie 重建（ID 变化）→
// 旧密码登录失败/新密码登录成功（UpdatePassword 落库链）。
func TestU26AdminPasswordChange(t *testing.T) {
	e := newU26Env(t, nil)
	c := u26Client(t)
	oldSID := u26Login(t, c, e.ts.URL, "admin", "admin", "admin-pass!")
	csrf := u26CSRF(t, c, e.ts.URL+"/admin/password")

	// 旧密码错误 → 200 错误文案（非 303——TC 校验拒绝语义）
	resp := u26Post(t, c, e.ts.URL+"/admin/password", url.Values{
		"username": {"admin"}, "oldPassword": {"wrong"}, "newPassword": {"n3w-pass-xx!"}, "confirmPassword": {"n3w-pass-xx!"},
	}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("旧密码错误应 200 重渲染: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "当前密码验证失败") {
		t.Fatalf("应含旧密码验证失败文案")
	}

	// 正确改密 → 303 + 新会话（cookie 值变化——OWASP Renew ID）
	resp = u26Post(t, c, e.ts.URL+"/admin/password", url.Values{
		"username": {"admin"}, "oldPassword": {"admin-pass!"}, "newPassword": {"n3w-pass-xx!"}, "confirmPassword": {"n3w-pass-xx!"},
	}, csrf)
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "/admin/settings?pwchanged=1") {
		t.Fatalf("改密应 303 回枢纽: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var newSID string
	for _, ck := range resp.Cookies() {
		if ck.Name == "__Host-sid" || ck.Name == "sid" {
			newSID = ck.Value
		}
	}
	if newSID == "" || newSID == oldSID {
		t.Fatalf("会话应重建（ID 变化）: old=%s new=%s", oldSID, newSID)
	}

	// 旧密码登录失败 / 新密码登录成功
	c2 := u26Client(t)
	if r := u26Post(t, c2, e.ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"admin-pass!"}}, ""); r.StatusCode != http.StatusOK {
		t.Fatalf("旧密码登录应被拒（200 重渲染）: %d", r.StatusCode)
	}
	c3 := u26Client(t)
	u26Login(t, c3, e.ts.URL, "admin", "admin", "n3w-pass-xx!") // 成功即通过（失败内部 Fatal）
}

// TestU26MailboxPasswordChange 邮箱用户个人改密通道（G1）：
// 旧密码验证（防枚举链复用）→ 改密 303+会话重建 → 旧密码登录统一拒绝/新密码通过。
func TestU26MailboxPasswordChange(t *testing.T) {
	e := newU26Env(t, nil)
	c := u26Client(t)
	oldSID := u26Login(t, c, e.ts.URL, "mailbox", "u26@test.local", "mb-pass!")
	csrf := u26CSRF(t, c, e.ts.URL+"/settings/password")

	// 旧密码错误 → 200 错误文案
	resp := u26Post(t, c, e.ts.URL+"/settings/password", url.Values{
		"oldPassword": {"wrong"}, "newPassword": {"n3w-mb-yy!"}, "confirmPassword": {"n3w-mb-yy!"},
	}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("旧密码错误应 200 重渲染: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "当前密码验证失败") {
		t.Fatalf("应含旧密码验证失败文案")
	}

	// 正确改密 → 303 + 会话重建
	resp = u26Post(t, c, e.ts.URL+"/settings/password", url.Values{
		"oldPassword": {"mb-pass!"}, "newPassword": {"n3w-mb-yy!"}, "confirmPassword": {"n3w-mb-yy!"},
	}, csrf)
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "/settings?pwchanged=1") {
		t.Fatalf("改密应 303 回枢纽: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var newSID string
	for _, ck := range resp.Cookies() {
		if ck.Name == "__Host-sid" || ck.Name == "sid" {
			newSID = ck.Value
		}
	}
	if newSID == "" || newSID == oldSID {
		t.Fatalf("会话应重建（ID 变化）")
	}

	// 旧密码登录统一拒绝 / 新密码通过
	c2 := u26Client(t)
	if r := u26Post(t, c2, e.ts.URL+"/webmail/login", url.Values{"address": {"u26@test.local"}, "password": {"mb-pass!"}}, ""); r.StatusCode != http.StatusOK {
		t.Fatalf("旧密码登录应被拒: %d", r.StatusCode)
	}
	c3 := u26Client(t)
	u26Login(t, c3, e.ts.URL, "mailbox", "u26@test.local", "n3w-mb-yy!")
}

// TestU26AdminSetPasswordAction 管理员行内改密（G1 第三通道——POST /admin/mailboxes
// action=setpassword）：改密成功后 mailbox 以新密码登录通过（SetMailboxPassword 域链）。
func TestU26AdminSetPasswordAction(t *testing.T) {
	e := newU26Env(t, nil)
	c := u26Client(t)
	u26Login(t, c, e.ts.URL, "admin", "admin", "admin-pass!")
	csrf := u26CSRF(t, c, e.ts.URL+"/admin/mailboxes")

	resp := u26Post(t, c, e.ts.URL+"/admin/mailboxes", url.Values{
		"action": {"setpassword"}, "address": {"u26@test.local"}, "password": {"adm-set-zz!"},
	}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("行内改密应 200 重渲染列表: %d", resp.StatusCode)
	}

	c2 := u26Client(t)
	u26Login(t, c2, e.ts.URL, "mailbox", "u26@test.local", "adm-set-zz!")
}

// TestU26SettingsHub 个人设置枢纽（G2/G3）：mailbox 登录后 /settings 呈现四分区入口
// （改密/2FA/规则——D5 导航孤儿收口锚）；admin 访问 302 管理枢纽。
func TestU26SettingsHub(t *testing.T) {
	e := newU26Env(t, nil)
	c := u26Client(t)
	u26Login(t, c, e.ts.URL, "mailbox", "u26@test.local", "mb-pass!")

	resp, err := c.Get(e.ts.URL + "/settings")
	if err != nil {
		t.Fatalf("GET /settings: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"/settings/password", "/settings/2fa", "/sieve", "u26@test.local"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("个人枢纽应含 %q", want)
		}
	}

	// admin 访问 → 302 /admin/settings（单枢纽原则）
	ca := u26Client(t)
	u26Login(t, ca, e.ts.URL, "admin", "admin", "admin-pass!")
	resp2, err := ca.Get(e.ts.URL + "/settings")
	if err != nil {
		t.Fatalf("admin GET /settings: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound || resp2.Header.Get("Location") != "/admin/settings" {
		t.Fatalf("admin 应 302 管理枢纽: %d %s", resp2.StatusCode, resp2.Header.Get("Location"))
	}
}

// u26FakePlugins 假插件状态源（G6 注入态用例——零 plugin 依赖）。
type u26FakePlugins struct{}

// PluginStatuses 实现 PluginStatusSource（固定两行：运行中+已崩溃）。
func (u26FakePlugins) PluginStatuses() []PluginStatus {
	return []PluginStatus{
		{Name: "demo", Version: "v0.1.0", Caps: []string{"inbound_hook", "submit_hook"}, Alive: true},
		{Name: "broken", Version: "v0.0.3", Caps: nil, Alive: false},
	}
}

// TestU26AdminPluginsPage 插件状态页两态（G6）：未注入=503 渐进态；
// 注入后 200 呈现名称/版本/能力/运行态（崩溃行如实呈现）。
func TestU26AdminPluginsPage(t *testing.T) {
	// 未注入 → 503
	e1 := newU26Env(t, nil)
	c1 := u26Client(t)
	u26Login(t, c1, e1.ts.URL, "admin", "admin", "admin-pass!")
	resp, err := c1.Get(e1.ts.URL + "/admin/plugins")
	if err != nil {
		t.Fatalf("GET /admin/plugins: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("未注入应 503: %d", resp.StatusCode)
	}

	// 注入 → 200 呈现
	e2 := newU26Env(t, u26FakePlugins{})
	c2 := u26Client(t)
	u26Login(t, c2, e2.ts.URL, "admin", "admin", "admin-pass!")
	resp2, err := c2.Get(e2.ts.URL + "/admin/plugins")
	if err != nil {
		t.Fatalf("GET /admin/plugins: %v", err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	for _, want := range []string{"demo", "v0.1.0", "inbound_hook", "broken", "已崩溃"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("插件页应含 %q", want)
		}
	}
}
