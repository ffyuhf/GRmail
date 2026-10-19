// GRM高危处置批 GRM-001（Setup Token 鉴权——PMail C4 形态）web 层测试。
// 覆盖五锚：无 token GET 拒（403）/错 token 拒/带 token GET 通（表单隐藏域注入）/
// 无 token POST 拒/带 token POST 通（303 下一 slug 随 token）；附带业务路径 302
// 回入口带 token（非向导路径被拒后不撞 403）。
// 依据：GRM高危处置批计划书 v1.0.0 步骤 2（G2 批准 2026-10-19 07:06:11＋07:11:50
// 修订「A：仅 Setup Token 鉴权（PMail C4 形态，无顺序状态机）」）。
// 修改历史：
//
//	2026-10-19 09-53-00 | 新建 | GRM高危处置批（计划书步骤 2——T1 红线：零既有断言触碰）
package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// testCtxGRM 测试上下文简写。
func testCtxGRM() context.Context { return context.Background() }

// postFormGRM 表单 POST（返回响应——不跟随重定向：303 Location 断言需要原始响应）。
func postFormGRM(t *testing.T, ts *httptest.Server, path string, form url.Values) *http.Response {
	t.Helper()
	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirect.PostForm(ts.URL+path, form)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	resp.Body.Close()
	return resp
}

// getGRMBody GET 并读取完整响应体（包内既有 get 辅助读取后关闭 body——本测试需
// body 内容断言，自研读取形态）。
func getGRMBody(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读响应体: %v", err)
	}
	return resp.StatusCode, string(b)
}

// grmTokenEnv GRM-001 测试环境（沿 newU10Env 形态——token 注入变体）。
type grmTokenEnv struct {
	srv *Server
	ts  *httptest.Server
	mu  sync.Mutex
	cfg *config.Config
}

// newGRMTokenEnv 构造（引导态+固定 token——校验链全真）。
func newGRMTokenEnv(t *testing.T, token string) *grmTokenEnv {
	t.Helper()
	cfg := config.Default()
	cfg.SetupCompleted = false
	db, err := storage.Open(testCtxGRM(), config.DatabaseConf{Driver: "sqlite", DSN: t.TempDir() + "/grm.db"})
	if err != nil {
		t.Fatalf("临时库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.MigrateUp(testCtxGRM(), db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	users := storage.NewSQLiteUserRepo(db)
	sessions := storage.NewSQLiteSessionRepo(db)
	attempts := storage.NewSQLiteLoginAttemptRepo(db)
	accts := account.NewService(storage.NewSQLiteMailboxRepo(db), storage.NewSQLiteFolderRepo(db))
	env := &grmTokenEnv{cfg: cfg}
	env.srv = NewServer(ServerConfig{
		Domain:      cfg.Server.Domain,
		SetupToken:  token,
		SetupDone:   func() bool { return false },
		CfgSnapshot: func() *config.Config { return cfg },
		SaveConfig: func(modify func(*config.Config)) error {
			modify(cfg)
			return nil
		},
	}, sessions, users, attempts, accts)
	env.ts = httptest.NewServer(env.srv.engine)
	t.Cleanup(env.ts.Close)
	return env
}

// TestGRM001SetupTokenGate token 校验五锚（GET×3+POST×2）。
func TestGRM001SetupTokenGate(t *testing.T) {
	const tok = "grm-test-token-0123456789abcdef"
	env := newGRMTokenEnv(t, tok)

	// 锚1：无 token GET → 403（setup.tokenRequired 错误整页）
	resp := get(t, env.ts, "/setup/1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无 token GET 应 403，得 %d", resp.StatusCode)
	}
	// 锚2：错 token GET → 403
	resp = get(t, env.ts, "/setup/1?setup_token=wrong")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("错 token GET 应 403，得 %d", resp.StatusCode)
	}
	// 锚3：带 token GET → 200 且表单含 setup_token 隐藏域
	code, body := getGRMBody(t, env.ts, "/setup/1?setup_token="+tok)
	if code != http.StatusOK {
		t.Fatalf("带 token GET 应 200，得 %d", code)
	}
	if !strings.Contains(body, `name="setup_token"`) || !strings.Contains(body, tok) {
		t.Fatalf("向导页表单应含 setup_token 隐藏域（值注入）")
	}
	// 锚4：无 token POST → 403（步 1 数据库——跳步创建管理员攻击面消解的等价锚）
	form := url.Values{"driver": {"sqlite"}, "sqlitePath": {""}}
	resp = postFormGRM(t, env.ts, "/setup/database", form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无 token POST 应 403，得 %d", resp.StatusCode)
	}
	// 锚5：带 token POST → 303 下一 slug 且 Location 随 token
	form.Set("setup_token", tok)
	resp = postFormGRM(t, env.ts, "/setup/database", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("带 token POST 应 303，得 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/setup/admin?setup_token="+tok {
		t.Fatalf("303 Location 应随 token，得 %q", loc)
	}
}

// TestGRM001BusinessRedirectCarriesToken 业务路径 302 回入口带 token
// （非向导路径被 gate 踢回向导时不撞 403——token 链路续接）。
func TestGRM001BusinessRedirectCarriesToken(t *testing.T) {
	const tok = "grm-redirect-token"
	env := newGRMTokenEnv(t, tok)
	resp := get(t, env.ts, "/")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("业务路径应 302，得 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/setup/1?setup_token="+tok {
		t.Fatalf("302 入口应带 token，得 %q", loc)
	}
}

// TestGRM001TokenDisabledCompat SetupToken 空=校验关闭（既有测试/部署形态兼容锚——
// 沿 Tokens/SieveScripts nil 渐进态先例）。
func TestGRM001TokenDisabledCompat(t *testing.T) {
	env := newGRMTokenEnv(t, "") // 空 token
	resp := get(t, env.ts, "/setup/1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("空 token（校验关闭）GET 应 200，得 %d", resp.StatusCode)
	}
}
