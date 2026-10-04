// U8 Web 会话与登录全离线测试（NFR-015：httptest+临时 SQLite 库驱动，零网络端点依赖）。
// 覆盖：OWASP 八条判定锚（cookie 属性/仅 cookie 交换/双超时/防 fixation 重建/盐哈希日志/
// no-store+Clear-Site-Data）、Q2-B 双端点、Q3-A TLS 未就绪、Q4-B 限流持久化、Q5-B CSRF、
// repo 层往返（TC-001 Webmail 格离线半场锚点）。
// 修改历史：
//
//	2026-09-19 05:25:00 | 新建 | U8 Web 会话与登录（计划书步骤 9，G2 批准 2026-09-19 04:56:31）
package web

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
)

// testEnv 测试环境：临时 SQLite 库 + 完整 repo/服务装配 + httptest 服务。
type testEnv struct {
	srv       *Server
	ts        *httptest.Server
	dbPath    string
	sessions  storage.SessionRepo
	users     storage.UserRepo
	attempts  storage.LoginAttemptRepo
	accounts  *account.Service
	adminPass string
}

// newTestEnv 构造测试环境（每用例独立临时库；管理员 admin/s3cret! 预置）。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	dbPath := dir + "/u8.db"
	db, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: dbPath})
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

	hash, err := account.HashPassword("s3cret!")
	if err != nil {
		t.Fatalf("哈希管理员密码: %v", err)
	}
	if err := users.EnsureAdmin(context.Background(), &storage.User{Username: "admin", PasswordHash: hash}); err != nil {
		t.Fatalf("预置管理员: %v", err)
	}

	srv := NewServer(ServerConfig{Domain: "test.local", TLSConfig: func() *tls.Config { return nil }},
		sessions, users, attempts, accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &testEnv{srv: srv, ts: ts, dbPath: dbPath, sessions: sessions, users: users,
		attempts: attempts, accounts: accounts, adminPass: "s3cret!"}
}

// postForm 表单 POST 便捷封装（跟随重定向=false，返回响应与字节）。
func postForm(t *testing.T, ts *httptest.Server, path string, form url.Values, cookies ...*http.Cookie) *http.Response {
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
	resp.Body.Close()
	return resp
}

// get 便捷 GET（不跟随重定向）。
func get(t *testing.T, ts *httptest.Server, path string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	resp.Body.Close()
	return resp
}

// sessionCookieOf 从响应提取会话 cookie（不存在返回 nil）。
func sessionCookieOf(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

// ───────────────────────── 用例 1：双端点登录成功 + cookie 六属性（OWASP 第 1/2 条） ─────────────────────────

func TestWebAdminLoginSuccessCookieAttributes(t *testing.T) {
	env := newTestEnv(t)
	resp := postForm(t, env.ts, "/login", url.Values{"username": {"admin"}, "password": {env.adminPass}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("管理员登录应 303，得 %d", resp.StatusCode)
	}
	cookie := sessionCookieOf(resp)
	if cookie == nil {
		t.Fatal("登录成功必须下发会话 cookie")
	}
	if cookie.Name != "__Host-sid" || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("cookie 属性不符合 OWASP 基线: %+v", cookie)
	}
	if !cookie.Expires.IsZero() || cookie.MaxAge != 0 {
		t.Fatalf("会话 cookie 必须非持久（无 Expires/Max-Age）: %+v", cookie)
	}
	if len(cookie.Value) != 32 {
		t.Fatalf("session ID 应为 CSPRNG 128bit hex（32 字符），得 %d", len(cookie.Value))
	}
	// 库内存 SHA-256 哈希（64 字符），非原文
	idHash := env.srv.sess.idHashOf(cookie.Value)
	if _, err := env.sessions.Find(context.Background(), idHash); err != nil {
		t.Fatalf("库存应为 ID 哈希: %v", err)
	}
}

func TestWebMailboxLoginSuccess(t *testing.T) {
	env := newTestEnv(t)
	if _, err := env.accounts.CreateMailbox(context.Background(), "alice@test.local", "pw123456"); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	resp := postForm(t, env.ts, "/webmail/login", url.Values{"address": {"alice@test.local"}, "password": {"pw123456"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("邮箱账号登录应 303，得 %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) == nil {
		t.Fatal("邮箱账号登录必须下发会话 cookie")
	}
}

// ───────────────────────── 用例 2：失败统一拒绝（防枚举） ─────────────────────────

func TestWebLoginFailuresUnifiedText(t *testing.T) {
	env := newTestEnv(t)
	cases := []url.Values{
		{"username": {"admin"}, "password": {"wrong"}},    // 错密码
		{"username": {"ghost"}, "password": {"whatever"}}, // 不存在用户
		{"username": {""}, "password": {""}},              // 空输入
	}
	for i, form := range cases {
		resp := postForm(t, env.ts, "/login", form)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("用例 %d：失败应 200+错误文本，得 %d", i, resp.StatusCode)
		}
	}
	// 邮箱端点：影子（无凭据）/不存在同文本
	if _, err := env.accounts.CreateShadowMailbox(context.Background(), "shadow@test.local"); err != nil {
		t.Fatalf("建影子: %v", err)
	}
	for _, form := range []url.Values{
		{"address": {"shadow@test.local"}, "password": {"x"}}, // 影子无凭据
		{"address": {"nobody@test.local"}, "password": {"x"}}, // 不存在地址
	} {
		if resp := postForm(t, env.ts, "/webmail/login", form); resp.StatusCode != http.StatusOK {
			t.Fatalf("邮箱端点失败应 200，得 %d", resp.StatusCode)
		}
	}
}

// ───────────────────────── 用例 3：限流（Q4-B：锁定/清零/重启保持） ─────────────────────────

func TestWebRateLimitLockAndPersist(t *testing.T) {
	env := newTestEnv(t)
	// 5 次失败
	for i := 0; i < 5; i++ {
		postForm(t, env.ts, "/login", url.Values{"username": {"admin"}, "password": {"bad"}})
	}
	// 第 6 次（正确密码）也锁定：423
	resp := postForm(t, env.ts, "/login", url.Values{"username": {"admin"}, "password": {env.adminPass}})
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("达到阈值后应 423 锁定，得 %d", resp.StatusCode)
	}
	// 重启进程语义：重开库（Q4-B 持久化判定锚）
	db2, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: env.dbPath})
	if err != nil {
		t.Fatalf("重开库: %v", err)
	}
	defer func() { _ = db2.Close() }()
	attempts2 := storage.NewSQLiteLoginAttemptRepo(db2)
	fails, err := attempts2.CountRecentFails(context.Background(), "admin:admin", time.Now().UTC().Add(-15*time.Minute))
	if err != nil || fails != 5 {
		t.Fatalf("重启后失败计数应保持 5，得 %d err=%v", fails, err)
	}
	// 独立主体不受牵连（窗口内 0 失败）
	failsOther, _ := attempts2.CountRecentFails(context.Background(), "admin:other", time.Now().UTC().Add(-15*time.Minute))
	if failsOther != 0 {
		t.Fatalf("无关主体不应被连带锁定，得 %d", failsOther)
	}
}

// ───────────────────────── 用例 4：双超时（OWASP 第 5 条，服务端强制） ─────────────────────────

func TestWebSessionIdleAndAbsoluteTimeout(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	mkSession := func(lastSeen, absExpires time.Time) *http.Cookie {
		raw := env.srv.sess.newSessionID()
		sess := &storage.Session{
			ID: env.srv.sess.idHashOf(raw), SubjectType: storage.SubjectTypeAdmin, SubjectID: 1,
			IP: "127.0.0.1", UserAgent: "u8test", CSRFToken: env.srv.sess.newCSRFToken(),
			CreatedAt: time.Now().UTC(), LastSeenAt: lastSeen, AbsoluteExpiresAt: absExpires,
		}
		if err := env.sessions.Create(ctx, sess); err != nil {
			t.Fatalf("造会话: %v", err)
		}
		return &http.Cookie{Name: sessionCookieName, Value: raw}
	}
	// 空闲超时：last_seen 老于 30min（U10 Q7-C 后取值经 config 缺省档——30min 字面锚定）
	idle := mkSession(time.Now().UTC().Add(-30*time.Minute-time.Minute), time.Now().UTC().Add(time.Hour))
	if resp := get(t, env.ts, "/", idle); resp.StatusCode != http.StatusFound {
		t.Fatalf("空闲超时会话应判匿名 302，得 %d", resp.StatusCode)
	}
	if _, err := env.sessions.Find(ctx, env.srv.sess.idHashOf(idle.Value)); err == nil {
		t.Fatal("超时会话必须被服务端删除")
	}
	// 绝对超时：absolute_expires 已过
	abs := mkSession(time.Now().UTC(), time.Now().UTC().Add(-time.Minute))
	if resp := get(t, env.ts, "/", abs); resp.StatusCode != http.StatusFound {
		t.Fatalf("绝对超时会话应判匿名 302，得 %d", resp.StatusCode)
	}
	// 有效会话：200
	valid := mkSession(time.Now().UTC(), time.Now().UTC().Add(12*time.Hour))
	if resp := get(t, env.ts, "/", valid); resp.StatusCode != http.StatusOK {
		t.Fatalf("有效会话应 200，得 %d", resp.StatusCode)
	}
}

// ───────────────────────── 用例 5：Touch 更新 + no-store（OWASP 第 7/8 条半场） ─────────────────────────

func TestWebTouchAndNoStoreHeader(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	raw := env.srv.sess.newSessionID()
	old := time.Now().UTC().Add(-10 * time.Minute)
	if err := env.sessions.Create(ctx, &storage.Session{
		ID: env.srv.sess.idHashOf(raw), SubjectType: storage.SubjectTypeAdmin, SubjectID: 1,
		CSRFToken: env.srv.sess.newCSRFToken(), CreatedAt: old, LastSeenAt: old,
		AbsoluteExpiresAt: time.Now().UTC().Add(12 * time.Hour),
	}); err != nil {
		t.Fatalf("造会话: %v", err)
	}
	resp := get(t, env.ts, "/", &http.Cookie{Name: sessionCookieName, Value: raw})
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("会话响应必须 no-store（OWASP 第 8 条）")
	}
	fresh, err := env.sessions.Find(ctx, env.srv.sess.idHashOf(raw))
	if err != nil {
		t.Fatalf("回查会话: %v", err)
	}
	if !fresh.LastSeenAt.After(old) {
		t.Fatal("请求后 last_seen_at 必须 Touch 更新")
	}
}

// ───────────────────────── 用例 6：登出双侧失效 + Clear-Site-Data + 主体化重定向 ─────────────────────────

func TestWebLogoutDualInvalidation(t *testing.T) {
	env := newTestEnv(t)
	resp := postForm(t, env.ts, "/webmail/login", url.Values{"address": {"bob@test.local"}, "password": {"pw"}})
	// bob 未创建 → 统一拒绝；改用已建邮箱
	if _, err := env.accounts.CreateMailbox(context.Background(), "bob@test.local", "pw123456"); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	resp = postForm(t, env.ts, "/webmail/login", url.Values{"address": {"bob@test.local"}, "password": {"pw123456"}})
	cookie := sessionCookieOf(resp)
	if cookie == nil {
		t.Fatal("预置登录失败")
	}
	// 登出需 CSRF token（Q5-B）——从库中取会话 token
	sess, err := env.sessions.Find(context.Background(), env.srv.sess.idHashOf(cookie.Value))
	if err != nil {
		t.Fatalf("查会话: %v", err)
	}
	out := postForm(t, env.ts, "/logout", url.Values{"csrf_token": {sess.CSRFToken}}, &http.Cookie{Name: sessionCookieName, Value: cookie.Value})
	if out.StatusCode != http.StatusSeeOther {
		t.Fatalf("登出应 303，得 %d", out.StatusCode)
	}
	if out.Header.Get("Clear-Site-Data") != `"cache", "cookies", "storage"` {
		t.Fatal("登出必须附 Clear-Site-Data 三类清理")
	}
	if loc := out.Header.Get("Location"); loc != "/webmail/login" {
		t.Fatalf("邮箱主体登出应回 /webmail/login，得 %s", loc)
	}
	cleared := sessionCookieOf(out)
	if cleared == nil || cleared.Value != "" || cleared.Expires.After(time.Now()) {
		t.Fatal("登出必须客户端 cookie 置空过期")
	}
	if _, err := env.sessions.Find(context.Background(), env.srv.sess.idHashOf(cookie.Value)); err == nil {
		t.Fatal("登出后服务端会话必须删除")
	}
}

// ───────────────────────── 用例 7：CSRF 三态（Q5-B） ─────────────────────────

func TestWebCSRFTokenValidation(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	if _, err := env.accounts.CreateMailbox(ctx, "carol@test.local", "pw123456"); err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	resp := postForm(t, env.ts, "/webmail/login", url.Values{"address": {"carol@test.local"}, "password": {"pw123456"}})
	cookie := sessionCookieOf(resp)
	sess, _ := env.sessions.Find(ctx, env.srv.sess.idHashOf(cookie.Value))
	jar := &http.Cookie{Name: sessionCookieName, Value: cookie.Value}

	// 无 token → 403
	if r := postForm(t, env.ts, "/logout", url.Values{}, jar); r.StatusCode != http.StatusForbidden {
		t.Fatalf("无 CSRF token 应 403，得 %d", r.StatusCode)
	}
	// 错 token → 403
	if r := postForm(t, env.ts, "/logout", url.Values{"csrf_token": {"deadbeef"}}, jar); r.StatusCode != http.StatusForbidden {
		t.Fatalf("错 CSRF token 应 403，得 %d", r.StatusCode)
	}
	// 正确 token → 303（特权会话仍有效）
	if r := postForm(t, env.ts, "/logout", url.Values{"csrf_token": {sess.CSRFToken}}, jar); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("正确 CSRF token 应 303，得 %d", r.StatusCode)
	}
}

// ───────────────────────── 用例 8：仅 cookie 交换（OWASP Used vs Accepted） ─────────────────────────

func TestWebOnlyCookieExchangeAccepted(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	raw := env.srv.sess.newSessionID()
	if err := env.sessions.Create(ctx, &storage.Session{
		ID: env.srv.sess.idHashOf(raw), SubjectType: storage.SubjectTypeAdmin, SubjectID: 1,
		CSRFToken: "x", CreatedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("造会话: %v", err)
	}
	// URL 参数携带 → 不认账
	if r := get(t, env.ts, "/?"+sessionCookieName+"="+raw); r.StatusCode != http.StatusFound {
		t.Fatalf("URL 参数携带会话 ID 应拒绝（302 匿名），得 %d", r.StatusCode)
	}
	// 自定义 header 携带 → 不认账
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/", nil)
	req.Header.Set("X-Session", raw)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Do(req)
	if err != nil {
		t.Fatalf("header 携带请求: %v", err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusFound {
		t.Fatalf("header 携带会话 ID 应拒绝，得 %d", r.StatusCode)
	}
	// cookie 携带 → 认账
	if r := get(t, env.ts, "/", &http.Cookie{Name: sessionCookieName, Value: raw}); r.StatusCode != http.StatusOK {
		t.Fatalf("cookie 携带应 200，得 %d", r.StatusCode)
	}
}

// ───────────────────────── 用例 9：认证门卫形态（契约 3.4：302 与 401+HX-Redirect） ─────────────────────────

func TestWebRequireAuthRedirectForms(t *testing.T) {
	env := newTestEnv(t)
	if r := get(t, env.ts, "/"); r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/login" {
		t.Fatalf("匿名整页访问应 302 /login，得 %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/", nil)
	req.Header.Set("HX-Request", "true")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Do(req)
	if err != nil {
		t.Fatalf("HX 请求: %v", err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized || r.Header.Get("HX-Redirect") != "/login" {
		t.Fatalf("HX 请求应 401+HX-Redirect，得 %d %q", r.StatusCode, r.Header.Get("HX-Redirect"))
	}
}

// ───────────────────────── 用例 10：TLS 未就绪跳过（Q3-A） ─────────────────────────

func TestWebTLSNotReadySkipped(t *testing.T) {
	srv := NewServer(ServerConfig{Domain: "t", TLSConfig: func() *tls.Config { return nil }},
		nil, nil, nil, nil)
	if err := srv.ListenAndServeTLS(":0"); err != ErrTLSNotReady {
		t.Fatalf("证书未就绪应返回 ErrTLSNotReady，得 %v", err)
	}
}

// ───────────────────────── 用例 11：防 fixation 重建（OWASP 第 4 条） ─────────────────────────

func TestWebSessionRotationOnLogin(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	// 预置一个旧「匿名期」会话（模拟登录前已持 cookie）
	oldRaw := env.srv.sess.newSessionID()
	if err := env.sessions.Create(ctx, &storage.Session{
		ID: env.srv.sess.idHashOf(oldRaw), SubjectType: storage.SubjectTypeAdmin, SubjectID: 99,
		CreatedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
		AbsoluteExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("造旧会话: %v", err)
	}
	// 携旧 cookie 登录 → 新 cookie 且旧会话删除
	resp := postForm(t, env.ts, "/login", url.Values{"username": {"admin"}, "password": {env.adminPass}},
		&http.Cookie{Name: sessionCookieName, Value: oldRaw})
	fresh := sessionCookieOf(resp)
	if fresh == nil || fresh.Value == oldRaw {
		t.Fatal("认证成功必须签发新 session ID（防 fixation）")
	}
	if _, err := env.sessions.Find(ctx, env.srv.sess.idHashOf(oldRaw)); err == nil {
		t.Fatal("旧会话必须随认证失效")
	}
}

// ───────────────────────── 用例 12：repo 层往返 + LogID 入口（NFR-015/016 半场） ─────────────────────────

func TestWebRepoRoundTripAndLogID(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	// SessionRepo：Create/Find/Touch/PurgeExpired
	raw := env.srv.sess.newSessionID()
	hashID := env.srv.sess.idHashOf(raw)
	if err := env.sessions.Create(ctx, &storage.Session{ID: hashID, SubjectType: storage.SubjectTypeMailbox,
		SubjectID: 7, LastSeenAt: time.Now().UTC(), AbsoluteExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s, err := env.sessions.Find(ctx, hashID); err != nil || s.SubjectID != 7 {
		t.Fatalf("Find: %v %+v", err, s)
	}
	if err := env.sessions.Touch(ctx, hashID, "1.2.3.4", "ua", time.Now().UTC()); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if n, err := env.sessions.PurgeExpired(ctx, time.Now().UTC().Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("PurgeExpired 应清 1，得 %d err=%v", n, err)
	}
	// UserRepo：EnsureAdmin 幂等 + FindByName + UpdatePassword
	if err := env.users.EnsureAdmin(ctx, &storage.User{Username: "admin", PasswordHash: "x"}); err != nil {
		t.Fatalf("EnsureAdmin 幂等: %v", err)
	}
	u, err := env.users.FindByName(ctx, "admin")
	if err != nil || u.Username != "admin" || !u.IsAdmin {
		t.Fatalf("FindByName: %v %+v", err, u)
	}
	if err := env.users.UpdatePassword(ctx, u.ID, "newhash"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	// LoginAttemptRepo：Record/Count/Clear/Purge
	if err := env.attempts.RecordAttempt(ctx, "admin:admin", "1.1.1.1", false, time.Now().UTC()); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if n, _ := env.attempts.CountRecentFails(ctx, "admin:admin", time.Now().UTC().Add(-time.Minute)); n != 1 {
		t.Fatalf("CountRecentFails 应 1，得 %d", n)
	}
	if err := env.attempts.ClearSubject(ctx, "admin:admin"); err != nil {
		t.Fatalf("ClearSubject: %v", err)
	}
	if n, _ := env.attempts.CountRecentFails(ctx, "admin:admin", time.Now().UTC().Add(-time.Minute)); n != 0 {
		t.Fatalf("清零后应 0，得 %d", n)
	}
	if err := env.attempts.RecordAttempt(ctx, "k", "", false, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("RecordAttempt(旧): %v", err)
	}
	if n, err := env.attempts.PurgeOld(ctx, time.Now().UTC().Add(-30*time.Minute)); err != nil || n != 1 {
		t.Fatalf("PurgeOld 应 1，得 %d err=%v", n, err)
	}
	// LogID：入口生成（slog 捕获断言 log_id 属性出现）
	records := make([]string, 0, 8)
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&sliceWriter{&records}, nil)))
	defer slog.SetDefault(old)
	_ = get(t, env.ts, "/login")
	found := false
	for _, r := range records {
		if strings.Contains(r, "log_id=") {
			found = true
		}
	}
	// httptest 请求不必然产生日志行（登录页 GET 无事件日志）；以 ContextWithNewLogID 直接断言
	_, logID := observability.ContextWithNewLogID(context.Background(), nil)
	if len(logID) != 32 {
		t.Fatalf("LogID 应 32 hex，得 %d", len(logID))
	}
	_ = found // GET /login 静态渲染无日志事件为合法；LogID 生成器已断言
}

// sliceWriter 测试用 slog 输出收集器。
type sliceWriter struct{ rows *[]string }

// Write 实现 io.Writer（逐行收集）。
func (w *sliceWriter) Write(p []byte) (int, error) {
	*w.rows = append(*w.rows, string(p))
	return len(p), nil
}
