// GRmail 管理员主体增强批次 HTTP 层测试（G2——D13：admin 登录入口二步验证；
// G6——D15 登录回跳）。沿 u24_test.go 母版形态（环境构造+服务直调预置+登录流断言），
// 复用同包辅助（sessionCookieOf/readBody/postFormCookie/u24ExtractToken）。
// 覆盖：FR-018 admin 通道扩展（S3-W Q2-A 裁决 2026-10-05 23:20:14——TC-027 判定②③
// admin 维度；判定⑤协议入口零触及由 mailbox 版既有回归承载）。
// 修改历史：
//
//	2026-10-06 01:12:00 | 新建 | 管理员主体增强与Webmail职能补全批次（G2 批准 2026-10-05 23:31:37）
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

	"github.com/creachadair/otp"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// u28Env admin 2FA 测试环境（u24Env 形态+AdminTwoFactor 注入）。
type u28Env struct {
	srv      *Server
	ts       *httptest.Server
	admin2FA *account.AdminTwoFactorService
	users    storage.UserRepo
	adminID  int64
}

// newU28Env 构造测试环境（临时库+管理员+AdminTwoFactor 注入；无 mailbox 依赖——
// admin 2FA 独立于邮箱域）。
func newU28Env(t *testing.T) *u28Env {
	t.Helper()
	db, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: t.TempDir() + "/u28web.db"})
	if err != nil {
		t.Fatalf("打开临时库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.MigrateUp(context.Background(), db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	users := storage.NewSQLiteUserRepo(db)
	sessions := storage.NewSQLiteSessionRepo(db)
	attempts := storage.NewSQLiteLoginAttemptRepo(db)

	hash, err := account.HashPassword("admin-pass!")
	if err != nil {
		t.Fatalf("哈希管理员密码: %v", err)
	}
	if err := users.EnsureAdmin(context.Background(), &storage.User{Username: "admin", PasswordHash: hash}); err != nil {
		t.Fatalf("预置管理员: %v", err)
	}
	u, err := users.FindByName(context.Background(), "admin")
	if err != nil {
		t.Fatalf("反查管理员: %v", err)
	}
	admin2FA := account.NewAdminTwoFactorService(users)

	srv := NewServer(ServerConfig{
		Domain:         "test.local",
		TLSConfig:      func() *tls.Config { return nil },
		Mailboxes:      storage.NewSQLiteMailboxRepo(db),
		AdminTwoFactor: admin2FA,
	}, sessions, users, attempts, nil)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &u28Env{srv: srv, ts: ts, admin2FA: admin2FA, users: users, adminID: u.ID}
}

// u28Bind 服务直调完成 admin 绑定（态预置——业务逻辑归 account 测试）；返回恢复码集。
func (e *u28Env) u28Bind(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	mat, err := e.admin2FA.InitiateBinding(ctx, e.adminID, "admin@test.local", "test.local")
	if err != nil {
		t.Fatalf("发起 admin 绑定: %v", err)
	}
	cfg, err := (otp.Config{Digits: 6}).WithKey(mat.Secret)
	if err != nil {
		t.Fatalf("解析密钥: %v", err)
	}
	code := cfg.HOTP(uint64(time.Now().Unix() / 30))
	codes, err := e.admin2FA.ConfirmBinding(ctx, e.adminID, code)
	if err != nil {
		t.Fatalf("确认 admin 绑定: %v", err)
	}
	return codes
}

// u28AdminLoginPOST admin 密码步提交（返回响应——body 由断言方读取）。
func (e *u28Env) u28AdminLoginPOST(t *testing.T) *http.Response {
	t.Helper()
	form := url.Values{"username": {"admin"}, "password": {"admin-pass!"}}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/login", strings.NewReader(form.Encode()))
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

// TestU28AdminTwoStepLogin 绑定后 admin 登录必经二步（D13 主锚——TC-027 判定②语义
// admin 维度）：密码正确→二步页（非 303——无因子不建会话）→恢复码→303+会话。
func TestU28AdminTwoStepLogin(t *testing.T) {
	e := newU28Env(t)
	codes := e.u28Bind(t)

	// 密码步：正确密码→admin 二步页（会话不建立）
	resp := e.u28AdminLoginPOST(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("密码步应渲染 admin 二步页: %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) != nil {
		t.Fatal("因子未通过不得签发 admin 会话 cookie")
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "/login/2fa") {
		t.Fatal("admin 二步页应指向 /login/2fa 端点")
	}
	tok := u24ExtractToken(t, body)

	// 因子步：恢复码通过→303+admin 会话
	resp = postFormCookie(t, e.ts, "/login/2fa", url.Values{"t": {tok}, "code": {codes[0]}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("正确因子应 303: %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) == nil {
		t.Fatal("因子通过应签发 admin 会话")
	}
}

// TestU28AdminUnboundDirectLogin 未绑定 admin 直通（兼容锚——G2 失败判定③防护）。
func TestU28AdminUnboundDirectLogin(t *testing.T) {
	e := newU28Env(t) // 不绑定
	resp := e.u28AdminLoginPOST(t)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("未绑定 admin 应直通 303: %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) == nil {
		t.Fatal("直通应签发 admin 会话")
	}
}

// TestU28Admin2FADisableStopsGate 停用后恢复直通（admin 停用须因子——TC-028 判定②语义
// admin 维度+停用后直通回归）。
func TestU28Admin2FADisableStopsGate(t *testing.T) {
	e := newU28Env(t)
	codes := e.u28Bind(t)

	// 停用：错误码拒绝
	if err := e.admin2FA.Disable(context.Background(), e.adminID, "000000"); err == nil {
		t.Fatal("错误因子停用应被拒绝")
	}
	// 停用：恢复码通过
	if err := e.admin2FA.Disable(context.Background(), e.adminID, codes[1]); err != nil {
		t.Fatalf("恢复码停用应通过: %v", err)
	}
	// 停用后登录恢复直通
	resp := e.u28AdminLoginPOST(t)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("停用后应恢复直通 303: %d", resp.StatusCode)
	}
}
