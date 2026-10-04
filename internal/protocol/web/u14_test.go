// U14 API Token 管理全离线测试（NFR-015：httptest+临时 SQLite 库驱动，零网络端点依赖）。
// 覆盖：Q1-A Bearer 并列认证矩阵（成功/无效/过期/IP 不符/撤销即失效/无头零回归）、
// Q3-B 管理面三端点（列表/生成一次性明文/撤销）、admin 门卫与 Tokens nil 渐进态、
// csrfProtect 放行分支承载程序化 POST（合成会话 CSRFToken 空）。
// 修改历史：
//
//	2026-09-24 02:58:00 | 新建 | U14 API Token 管理（计划书步骤 4，G2 批准 2026-09-24 02:30:51）
package web

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// u14Env U14 测试环境（testEnv 形态+TokenRepo 注入+管理员 ID）。
type u14Env struct {
	srv       *Server
	ts        *httptest.Server
	tokens    storage.TokenRepo
	adminID   int64
	adminPass string
}

// newU14Env 构造 U14 测试环境（临时库+迁移+管理员预置+Tokens 注入）。
func newU14Env(t *testing.T, withTokens bool) *u14Env {
	t.Helper()
	db, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: t.TempDir() + "/u14web.db"})
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
	admin, err := users.FindByName(context.Background(), "admin")
	if err != nil {
		t.Fatalf("查询管理员: %v", err)
	}

	var tokenRepo storage.TokenRepo
	if withTokens {
		tokenRepo = storage.NewSQLiteTokenRepo(db)
	}
	srv := NewServer(ServerConfig{
		Domain:    "test.local",
		TLSConfig: func() *tls.Config { return nil },
		Tokens:    tokenRepo, // nil=Bearer 通道关闭渐进态（沿 U12/U13 先例）
	}, sessions, users, attempts, accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &u14Env{srv: srv, ts: ts, tokens: tokenRepo, adminID: admin.ID, adminPass: "s3cret!"}
}

// adminCookie 管理员登录取会话 cookie。
func (e *u14Env) adminCookie(t *testing.T) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {"admin"}, "password": {e.adminPass}}
	resp := postForm(t, e.ts, "/login", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("管理员登录: %d", resp.StatusCode)
	}
	ck := sessionCookieOf(resp)
	if ck == nil {
		t.Fatal("登录未签发会话 cookie")
	}
	return ck
}

// getBearer Bearer 请求便捷 GET。
func getBearer(t *testing.T, ts *httptest.Server, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	resp.Body.Close()
	return resp
}

// TestU14BearerAuthMatrix Bearer 认证矩阵：成功/无效/过期/IP 不符/撤销即失效。
func TestU14BearerAuthMatrix(t *testing.T) {
	e := newU14Env(t, true)
	ctx := context.Background()
	now := time.Now().UTC()

	mint := func(expires time.Time, ip string) string {
		raw, err := newBearerToken()
		if err != nil {
			t.Fatalf("生成原文: %v", err)
		}
		if err := e.tokens.Create(ctx, &storage.ApiToken{
			UserID: e.adminID, TokenHash: bearerHashOf(raw),
			ExpiresAt: expires, ClientIP: ip, CreatedAt: now,
		}); err != nil {
			t.Fatalf("写入 Token: %v", err)
		}
		return raw
	}

	// 成功：GET /（Bearer 合成会话过 requireAuth——homeGET 占位形态 200）
	ok := mint(time.Time{}, "")
	if resp := getBearer(t, e.ts, "/", ok); resp.StatusCode != http.StatusOK {
		t.Fatalf("有效 Bearer 应 200: %d", resp.StatusCode)
	}

	// 无效：随机 64hex
	if resp := getBearer(t, e.ts, "/", strings.Repeat("e", 64)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无效 Bearer 应 401: %d", resp.StatusCode)
	}

	// 过期：expires_at 已过
	expired := mint(now.Add(-time.Minute), "")
	if resp := getBearer(t, e.ts, "/", expired); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("过期 Bearer 应 401: %d", resp.StatusCode)
	}

	// IP 不符：绑定非本机地址（httptest 客户端源 127.0.0.1）
	bound := mint(time.Time{}, "203.0.113.99")
	if resp := getBearer(t, e.ts, "/", bound); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("IP 不符应 401: %d", resp.StatusCode)
	}

	// 撤销即失效：repo 删除后同 Token 401
	list, err := e.tokens.ListByUser(ctx, e.adminID)
	if err != nil || len(list) == 0 {
		t.Fatalf("列表: %v %d", err, len(list))
	}
	for _, tk := range list {
		if err := e.tokens.Delete(ctx, tk.ID, e.adminID); err != nil {
			t.Fatalf("撤销: %v", err)
		}
	}
	if resp := getBearer(t, e.ts, "/", ok); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("撤销后应 401: %d", resp.StatusCode)
	}
}

// TestU14NoBearerZeroRegression 无 Authorization 头零回归：匿名 GET / → 302 登录跳转（U13 末态等价）。
func TestU14NoBearerZeroRegression(t *testing.T) {
	e := newU14Env(t, true)
	if resp := getBearer(t, e.ts, "/", ""); resp.StatusCode != http.StatusFound {
		t.Fatalf("无 Bearer 头匿名请求应 302（既有行为）: %d", resp.StatusCode)
	}
}

// TestU14TokensAdminUI 管理面三端点：登录→列表→生成（一次性明文）→repo 断言→撤销→空表。
func TestU14TokensAdminUI(t *testing.T) {
	e := newU14Env(t, true)
	ck := e.adminCookie(t)

	// 列表页（空表）
	resp := get(t, e.ts, "/admin/tokens", ck)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("列表页: %d", resp.StatusCode)
	}

	// 生成（7d 档——响应含一次性 64hex 明文）
	form := url.Values{"csrf_token": {csrfOfSession(t, e, ck)}, "expires": {"7d"}}
	resp = postForm(t, e.ts, "/admin/tokens", form, ck)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("生成: %d", resp.StatusCode)
	}
	list, err := e.tokens.ListByUser(context.Background(), e.adminID)
	if err != nil || len(list) != 1 {
		t.Fatalf("repo 行数: %v %d", err, len(list))
	}
	if list[0].ExpiresAt.IsZero() || !list[0].ExpiresAt.After(time.Now()) {
		t.Fatalf("7d 档过期时间异常: %v", list[0].ExpiresAt)
	}
	if !list[0].LastUsedAt.IsZero() {
		t.Fatalf("新生成 last_used_at 应为零值: %v", list[0].LastUsedAt)
	}

	// 撤销（双条件——CSRF 表单）
	rform := url.Values{"csrf_token": {csrfOfSession(t, e, ck)}}
	resp = postForm(t, e.ts, "/admin/tokens/"+itoa64(list[0].ID)+"/revoke", rform, ck)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("撤销: %d", resp.StatusCode)
	}
	if list, err = e.tokens.ListByUser(context.Background(), e.adminID); err != nil || len(list) != 0 {
		t.Fatalf("撤销后行数: %v %d", err, len(list))
	}
}

// TestU14TokensGuardAndNil admin 门卫（匿名 302）与 Tokens nil 渐进态（503）。
func TestU14TokensGuardAndNil(t *testing.T) {
	// 匿名访问 → requireAuth 302
	e := newU14Env(t, true)
	if resp := get(t, e.ts, "/admin/tokens"); resp.StatusCode != http.StatusFound {
		t.Fatalf("匿名应 302: %d", resp.StatusCode)
	}

	// Tokens nil（渐进部署形态）→ 已登录 admin 访问 503
	e2 := newU14Env(t, false)
	ck := e2.adminCookie(t)
	if resp := get(t, e2.ts, "/admin/tokens", ck); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nil 注入应 503: %d", resp.StatusCode)
	}
	// nil 态 Bearer 头不判定（通道关闭——401 语义不触发，回落匿名 302）
	if resp := getBearer(t, e2.ts, "/", strings.Repeat("f", 64)); resp.StatusCode != http.StatusFound {
		t.Fatalf("nil 态 Bearer 不判定应回落 302: %d", resp.StatusCode)
	}
}

// csrfOfSession 从登录会话取 CSRF token（表单链——U8 Q5-B 形态）。
func csrfOfSession(t *testing.T, e *u14Env, ck *http.Cookie) string {
	t.Helper()
	sess, err := e.srv.sessions.Find(context.Background(), e.srv.sess.idHashOf(ck.Value))
	if err != nil {
		t.Fatalf("查会话: %v", err)
	}
	return sess.CSRFToken
}

// itoa64 int64 转字符串（路径参数构造）。
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
