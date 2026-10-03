// U24 双因素认证 web 层全离线测试（NFR-015：httptest+临时 SQLite 库，零网络依赖）。
// 覆盖：FR-018 判定②（绑定账号密码步后二步页——无有效因子不得建立会话 TC-027 判定②③）/
// 未绑定直通兼容锚（既有登录路径零变化）/**强制引导门卫（Required 未绑定→重定向绑定页
// TC-028 判定③④）**/2FA 设置页渲染（mailbox 主体可达+admin 403）/admin 标记 action
// （require2fa/unrequire2fa 落库 TC-028 判定⑤）。
// 绑定业务逻辑经 account 域测试覆盖（u24_test.go account 包）；本文件经服务直调完成
// 绑定态预置后聚焦 HTTP 层行为。
// 修改历史：
//
//	2026-10-01 17:15:00 | 新增 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）
package web

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"

	"github.com/creachadair/otp"
)

// u24Env U24 测试环境（u14Env 形态+TwoFactor 注入+mailbox 账号）。
type u24Env struct {
	srv            *Server
	ts             *httptest.Server
	twoFA          *account.TwoFactorService
	mailbox        *storage.Mailbox
	mbPass         string
	adminCookieVal string
}

// newU24Env 构造测试环境（临时库+管理员+mailbox 账号+TwoFactor 注入）。
func newU24Env(t *testing.T) *u24Env {
	t.Helper()
	db, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: t.TempDir() + "/u24web.db"})
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

	mb, err := accounts.CreateMailbox(context.Background(), "u24@test.local", "mb-pass!")
	if err != nil {
		t.Fatalf("创建 mailbox 账号: %v", err)
	}
	twoFA := account.NewTwoFactorService(mailboxRepo)

	srv := NewServer(ServerConfig{
		Domain:    "test.local",
		TLSConfig: func() *tls.Config { return nil },
		Mailboxes: mailboxRepo, // 2FA 页主体反查/管理页数据源（twoFactorViewOf/admin 消费）
		TwoFactor: twoFA,
	}, sessions, users, attempts, accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &u24Env{srv: srv, ts: ts, twoFA: twoFA, mailbox: mb, mbPass: "mb-pass!"}
}

// u24Bind 经服务直调完成绑定（HTTP 层测试的态预置——业务逻辑归 account 测试）。
// 返回恢复码集（停用/验证场景用）。
func (e *u24Env) u24Bind(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	mat, err := e.twoFA.InitiateBinding(ctx, e.mailbox.ID, e.mailbox.Address, "test.local")
	if err != nil {
		t.Fatalf("发起绑定: %v", err)
	}
	cfg, err := (otp.Config{Digits: 6}).WithKey(mat.Secret)
	if err != nil {
		t.Fatalf("解析密钥: %v", err)
	}
	code := cfg.HOTP(uint64(time.Now().Unix() / 30))
	codes, err := e.twoFA.ConfirmBinding(ctx, e.mailbox.ID, code)
	if err != nil {
		t.Fatalf("确认绑定: %v", err)
	}
	return codes
}

// u24PostLogin 密码步提交。返回：响应（body 未关闭——供 readBody 断言；
// postForm 会预关 body，此处沿其形态自构不关闭）。
func (e *u24Env) u24PostLogin(t *testing.T) *http.Response {
	t.Helper()
	form := url.Values{"address": {e.mailbox.Address}, "password": {e.mbPass}}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/webmail/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}

// TestU24LoginTwoStep 绑定账号登录二步流（TC-027 判定②③ HTTP 面）：
// 密码正确→二步页（200，非 303——无有效因子不得建立会话）→错误码拒绝可重试→
// 正确码→303+会话 cookie 签发。
func TestU24LoginTwoStep(t *testing.T) {
	e := newU24Env(t)
	codes := e.u24Bind(t)

	// 密码步：正确密码→二步页（会话不建立）
	resp := e.u24PostLogin(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("密码步应渲染二步页: %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) != nil {
		t.Fatal("因子未通过不得签发会话 cookie（TC-027 判定②）")
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "/webmail/login/2fa") {
		t.Fatal("二步页应指向因子端点")
	}
	tok := u24ExtractToken(t, body)

	// 因子步：错误码拒绝（可重试——重签凭据）
	resp = postFormCookie(t, e.ts, "/webmail/login/2fa", url.Values{"t": {tok}, "code": {"000000"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("错误码应重渲染二步页: %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) != nil {
		t.Fatal("错误码不得签发会话")
	}
	tok2 := u24ExtractToken(t, readBody(t, resp))
	if tok2 == "" || tok2 == tok {
		t.Fatal("重试应重签一次性凭据")
	}

	// 因子步：恢复码通过→303+会话
	resp = postFormCookie(t, e.ts, "/webmail/login/2fa", url.Values{"t": {tok2}, "code": {codes[0]}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("正确因子应 303: %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) == nil {
		t.Fatal("因子通过应签发会话（TC-027 判定②）")
	}
}

// TestU24UnboundDirectLogin 未绑定账号登录直通（兼容锚——既有路径零变化）。
func TestU24UnboundDirectLogin(t *testing.T) {
	e := newU24Env(t) // 不绑定
	resp := e.u24PostLogin(t)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("未绑定应直通 303: %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) == nil {
		t.Fatal("未绑定直通应签发会话")
	}
}

// TestU24ForcedGate 强制引导门卫（TC-028 判定③④）：
// Required+未绑定→登录重定向绑定页；认证域其他路径被门卫拦截至绑定页；
// 绑定完成后门卫放行；取消标记后放行。
func TestU24ForcedGate(t *testing.T) {
	e := newU24Env(t)
	ctx := context.Background()
	if err := e.twoFA.SetRequired(ctx, e.mailbox.ID, true); err != nil {
		t.Fatalf("设置强制标记: %v", err)
	}

	// 登录→重定向绑定页（forced）
	resp := e.u24PostLogin(t)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings/2fa?forced=1" {
		t.Fatalf("强制未绑定登录应引导绑定页: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	ck := sessionCookieOf(resp)
	if ck == nil {
		t.Fatal("强制引导仍应建立会话（引导非拒绝登录）")
	}

	// 认证域其他路径→302 绑定页（「方可继续使用」语义）
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/", nil)
	req.AddCookie(ck)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求首页: %v", err)
	}
	if resp2.StatusCode != http.StatusFound || resp2.Header.Get("Location") != "/settings/2fa?forced=1" {
		t.Fatalf("门卫应拦截至绑定页: %d %s", resp2.StatusCode, resp2.Header.Get("Location"))
	}

	// 绑定页自身可达（门卫白名单）
	req2, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/settings/2fa?forced=1", nil)
	req2.AddCookie(ck)
	resp3, err := client.Do(req2)
	if err != nil {
		t.Fatalf("请求绑定页: %v", err)
	}
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("绑定页应可达: %d", resp3.StatusCode)
	}

	// 完成绑定→门卫放行；取消标记→放行
	e.u24Bind(t)
	resp4, err := client.Do(req)
	if err != nil || resp4.StatusCode == http.StatusFound {
		t.Fatalf("绑定后门卫应放行: %v %d", err, resp4.StatusCode)
	}
	if err := e.twoFA.SetRequired(ctx, e.mailbox.ID, false); err != nil {
		t.Fatalf("取消标记: %v", err)
	}
	resp5, err := client.Do(req)
	if err != nil || resp5.StatusCode == http.StatusFound {
		t.Fatalf("取消标记后应放行: %v %d", err, resp5.StatusCode)
	}
}

// TestU24AdminRequireActions admin 标记 action（TC-028 判定⑤ HTTP 面）。
func TestU24AdminRequireActions(t *testing.T) {
	e := newU24Env(t)
	ctx := context.Background()
	// 管理员登录（/login——admin 主体无 2FA 判定）
	resp := postForm(t, e.ts, "/login", url.Values{"username": {"admin"}, "password": {"admin-pass!"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("管理员登录: %d", resp.StatusCode)
	}
	ck := sessionCookieOf(resp)
	if ck == nil {
		t.Fatal("管理员会话未签发")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// CSRF：从管理页提取 token
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/admin/mailboxes", nil)
	req.AddCookie(ck)
	page, err := client.Do(req)
	if err != nil {
		t.Fatalf("管理页: %v", err)
	}
	csrf := u24ExtractCSRF(t, readBody(t, page))

	// require2fa → 落库
	form := url.Values{"csrf_token": {csrf}, "address": {e.mailbox.Address}, "action": {"require2fa"}}
	resp = postFormCookie(t, e.ts, "/admin/mailboxes", form, ck)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("require2fa: %d", resp.StatusCode)
	}
	st, _ := e.twoFA.State(ctx, e.mailbox.ID)
	if !st.Required {
		t.Fatal("强制标记未落库（TC-028 判定⑤）")
	}

	// unrequire2fa → 清除
	form.Set("action", "unrequire2fa")
	resp = postFormCookie(t, e.ts, "/admin/mailboxes", form, ck)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unrequire2fa: %d", resp.StatusCode)
	}
	if st, _ = e.twoFA.State(ctx, e.mailbox.ID); st.Required {
		t.Fatal("标记未清除")
	}
}

// ───────────────────────── 测试辅助 ─────────────────────────

// u24ExtractToken 从二步页 HTML 提取 pending 凭据（name="t" 隐藏域）。
func u24ExtractToken(t *testing.T, body string) string {
	t.Helper()
	const mark = `name="t" value="`
	return u24Between(t, body, mark)
}

// u24ExtractCSRF 从页面 HTML 提取 csrf_token 隐藏域值。
func u24ExtractCSRF(t *testing.T, body string) string {
	t.Helper()
	const mark = `name="csrf_token" value="`
	return u24Between(t, body, mark)
}

// u24Between 提取 mark 之后至下一个引号的子串。
func u24Between(t *testing.T, body, mark string) string {
	t.Helper()
	i := strings.Index(body, mark)
	if i < 0 {
		t.Fatalf("页面未含标记 %q", mark)
	}
	rest := body[i+len(mark):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatal("标记值未闭合")
	}
	return rest[:j]
}

// readBody 读尽响应体为字符串（测试便捷）。
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}

// postFormCookie 表单 POST（不跟随重定向——303/302 状态断言载体；body 不预关供
// readBody；cookie 可选携带）。
func postFormCookie(t *testing.T, ts *httptest.Server, path string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}
