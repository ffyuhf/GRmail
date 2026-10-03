// U10 Setup 向导与 ACME web 层全离线测试（NFR-015：httptest+临时 SQLite 库+内存配置快照）。
// 覆盖：Q2-A setupCompleted 分流（未完成 302→/setup、完成后 /setup 禁入）、六步向导全流程
// （步 1 库选择/步 2 管理员创建与跳过/步 3 域名/步 5 双模式/步 6 完成落盘）、Q7-C 设置页
// （admin 门卫 403/全量保存热生效/校验拒绝）、Q3-A 80 双态（挑战直答+301/向导态 engine 直驱）、
// ACME 挑战表接口（TC-015/TC-009/TC-023 离线半场锚点）。
// 修改历史：
//
//	2026-09-20 01:50:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 9，G2 批准 2026-09-20 00:32:33）
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// u10Env U10 测试环境：内存配置快照（SaveConfig 内存读改写——向导链路全真、持久化归 main 闭包单测范围外）。
type u10Env struct {
	srv   *Server
	ts    *httptest.Server
	mu    sync.Mutex
	cfg   *config.Config
	users storage.UserRepo
}

// newU10Env 构造（setupDone 动态跟随内存 cfg——分流语义全真）。
func newU10Env(t *testing.T, initial *config.Config) *u10Env {
	t.Helper()
	if initial == nil {
		initial = config.Default()
		initial.SetupCompleted = false // 默认引导态
	}
	dir := t.TempDir()
	db, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: dir + "/u10.db"})
	if err != nil {
		t.Fatalf("临时库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.MigrateUp(context.Background(), db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	users := storage.NewSQLiteUserRepo(db)
	sessions := storage.NewSQLiteSessionRepo(db)
	attempts := storage.NewSQLiteLoginAttemptRepo(db)
	mailboxes := storage.NewSQLiteMailboxRepo(db)
	folders := storage.NewSQLiteFolderRepo(db)
	accts := account.NewService(mailboxes, folders)

	env := &u10Env{users: users}
	env.cfg = initial
	srv := NewServer(ServerConfig{
		Domain:      initial.Server.Domain,
		SetupDone:   func() bool { env.mu.Lock(); defer env.mu.Unlock(); return env.cfg.SetupCompleted },
		CfgSnapshot: func() *config.Config { env.mu.Lock(); defer env.mu.Unlock(); return env.cfg },
		SaveConfig: func(modify func(*config.Config)) error {
			env.mu.Lock()
			defer env.mu.Unlock()
			modify(env.cfg)
			return nil
		},
		SessionSnapshot: func() config.SessionConf { env.mu.Lock(); defer env.mu.Unlock(); return env.cfg.Session },
		LimitSnapshot:   func() config.LoginLimitConf { env.mu.Lock(); defer env.mu.Unlock(); return env.cfg.LoginLimit },
	}, sessions, users, attempts, accts)
	env.srv = srv
	env.ts = httptest.NewServer(srv.engine)
	t.Cleanup(env.ts.Close)
	return env
}

// ───────────────────────── 用例 1：Setup 分流（Q2-A/Q4-A + 契约 3.4） ─────────────────────────

func TestU10SetupGateRedirects(t *testing.T) {
	env := newU10Env(t, nil) // 引导态
	// 未完成：业务路径 302 → /setup/1；/setup 族与静态资源放行
	if resp := get(t, env.ts, "/"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/setup/1" {
		t.Fatalf("引导态业务路径应 302 /setup/1，得 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := get(t, env.ts, "/setup/1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("向导步页应 200，得 %d", resp.StatusCode)
	}
	// 完成：/setup 禁入（302 首页）
	env.mu.Lock()
	env.cfg.SetupCompleted = true
	env.mu.Unlock()
	if resp := get(t, env.ts, "/setup/1"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("完成态 /setup 应 302 /，得 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// ───────────────────────── 用例 2：向导六步全流程（TC-015/TC-023 离线半场） ─────────────────────────

func TestU10SetupWizardFullFlow(t *testing.T) {
	env := newU10Env(t, nil)
	// 步 1：SQLite 默认（零 DSN）
	if resp := postForm(t, env.ts, "/setup/database", url.Values{"driver": {"sqlite"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("步 1 应 303，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	if env.cfg.Database.Driver != "sqlite" || env.cfg.Database.DSN != "data/grmail.db" {
		t.Fatalf("步 1 库配置未落: %+v", env.cfg.Database)
	}
	env.mu.Unlock()
	// 步 1 非法驱动拒绝
	if resp := postForm(t, env.ts, "/setup/database", url.Values{"driver": {"oracle"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("步 1 非法驱动应重渲染 200，得 %d", resp.StatusCode)
	}
	// 步 2：管理员创建（argon2id 落库）
	if resp := postForm(t, env.ts, "/setup/admin", url.Values{
		"username": {"root"}, "password": {"Passw0rd!"}, "confirm": {"Passw0rd!"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("步 2 应 303，得 %d", resp.StatusCode)
	}
	if u, err := env.users.FindByName(context.Background(), "root"); err != nil || !u.IsAdmin {
		t.Fatalf("管理员未创建: %v %+v", err, u)
	}
	// 步 2 重复用户名拒绝
	if resp := postForm(t, env.ts, "/setup/admin", url.Values{
		"username": {"root"}, "password": {"x"}, "confirm": {"x"},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("步 2 已存在用户名应重渲染，得 %d", resp.StatusCode)
	}
	// 步 3：域名
	if resp := postForm(t, env.ts, "/setup/domain", url.Values{"domain": {"mail.grmail.example"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("步 3 应 303，得 %d", resp.StatusCode)
	}
	// 步 3 非法域名拒绝（含 @）
	if resp := postForm(t, env.ts, "/setup/domain", url.Values{"domain": {"a@b"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("步 3 非法域名应重渲染，得 %d", resp.StatusCode)
	}
	// 步 4：DNS 只读确认（GET 呈现建议表）
	if resp := get(t, env.ts, "/setup/dns"); resp.StatusCode != http.StatusOK {
		t.Fatalf("步 4 页应 200，得 %d", resp.StatusCode)
	}
	if resp := postForm(t, env.ts, "/setup/dns", url.Values{}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("步 4 确认应 303，得 %d", resp.StatusCode)
	}
	// 步 5：ACME 模式
	if resp := postForm(t, env.ts, "/setup/ssl", url.Values{
		"mode": {"acme"}, "acmeEmail": {"admin@grmail.example"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("步 5 ACME 应 303，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	if !env.cfg.ACME.Enabled || env.cfg.ACME.Email != "admin@grmail.example" {
		t.Fatalf("步 5 ACME 配置未落: %+v", env.cfg.ACME)
	}
	// 步 5 手动模式非法路径拒绝（不存在的证书文件）
	env.mu.Unlock()
	if resp := postForm(t, env.ts, "/setup/ssl", url.Values{
		"mode": {"manual"}, "certFile": {"/nonexistent/c.pem"}, "keyFile": {"/nonexistent/k.pem"},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("步 5 手动模式坏路径应重渲染，得 %d", resp.StatusCode)
	}
	// 步 6：完成——setupCompleted 落位
	if resp := postForm(t, env.ts, "/setup/done", url.Values{}); resp.StatusCode != http.StatusOK {
		t.Fatalf("步 6 完成页应 200，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	done := env.cfg.SetupCompleted
	env.mu.Unlock()
	if !done {
		t.Fatal("步 6 后 setupCompleted 应为 true")
	}
}

// ───────────────────────── 用例 3：向导步 2 跳过路径（计划书 1.5⑩ 旧部署） ─────────────────────────

func TestU10SetupAdminSkipPath(t *testing.T) {
	env := newU10Env(t, nil)
	if resp := postForm(t, env.ts, "/setup/admin", url.Values{"action": {"skip"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("跳过应 303，得 %d", resp.StatusCode)
	}
	// 跳过后仍可回步补设（全新部署误跳过闭环）
	if resp := postForm(t, env.ts, "/setup/admin", url.Values{
		"username": {"late"}, "password": {"p"}, "confirm": {"p"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("跳过后补设应 303，得 %d", resp.StatusCode)
	}
	if _, err := env.users.FindByName(context.Background(), "late"); err != nil {
		t.Fatalf("补设管理员未落库: %v", err)
	}
}

// ───────────────────────── 用例 4：设置页（Q7-C 全量 + admin 门卫 + CSRF） ─────────────────────────

func TestU10AdminSettingsFullConfig(t *testing.T) {
	cfg := config.Default()
	cfg.SetupCompleted = true
	env := newU10Env(t, cfg)
	// 匿名与 mailbox 主体：401/403（requireAuth→401；admin 门卫→403）
	if resp := get(t, env.ts, "/admin/settings"); resp.StatusCode != http.StatusFound {
		t.Fatalf("匿名应经 requireAuth 302，得 %d", resp.StatusCode)
	}
	// admin 会话：GET 200 呈现
	cookie := env.u10Session(t, storage.SubjectTypeAdmin, 1, "csrf-u10")
	if resp := get(t, env.ts, "/admin/settings", cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET 设置页应 200，得 %d", resp.StatusCode)
	}
	// 无 CSRF token POST：403（csrfProtect）
	if resp := postForm(t, env.ts, "/admin/settings", url.Values{"spfEnabled": {"on"}}, cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无 token POST 应 403，得 %d", resp.StatusCode)
	}
	// 全量保存（Q7-C 四节+U13 传输安全节）→ 配置快照断言（TC-009 Web 侧：保存链热生效）
	form := url.Values{
		"csrf_token":         {"csrf-u10"},
		"spfEnabled":         {"on"},
		"dkimEnabled":        {"on"},
		"dmarcEnabled":       {"on"},
		"dkimSelector":       {"s2048"},
		"dkimKeyPath":        {"data/dkim.pem"},
		"dkimAlgorithm":      {"ed25519-sha256"},
		"catchAll":           {"on"},
		"maxMessageSizeMB":   {"20"},
		"retryBaseSeconds":   {"120"},
		"retryFactor":        {"3"},
		"retryCapSeconds":    {"7200"},
		"maxAttempts":        {"6"},
		"idleMinutes":        {"45"},
		"absoluteHours":      {"10"},
		"limitWindowMinutes": {"30"},
		"limitThreshold":     {"4"},
		// U13 传输安全节（FR-010：MTASts 关闭态落库——判定③「Web 可关闭」锚）
		"mtaStsMode":          {"testing"},
		"mtaStsMaxAgeSeconds": {"86400"},
		"tlsrptRuaAddress":    {"tlsrpt@u10.example"},
	}
	if resp := postForm(t, env.ts, "/admin/settings", form, cookie); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("合法保存应 303，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	c := env.cfg
	if c.Auth.ARCEnabled { // 表单未勾 ARC——应关闭（TC-009 判定锚：关 ARC 生效）
		t.Fatal("ARC 未勾选应被置 false")
	}
	if !c.Auth.SPFEnabled || c.Auth.DKIM.Selector != "s2048" || c.Auth.DKIM.Algorithm != "ed25519-sha256" {
		t.Fatalf("认证栈节未落: %+v", c.Auth)
	}
	if !c.CatchAll || c.Mail.MaxMessageSizeBytes != 20*1024*1024 {
		t.Fatalf("catchAll/邮件限值节未落: %v %d", c.CatchAll, c.Mail.MaxMessageSizeBytes)
	}
	if c.Mail.Delivery.MaxAttempts != 6 || c.Mail.Delivery.RetryBaseSeconds != 120 {
		t.Fatalf("投递退避节未落: %+v", c.Mail.Delivery)
	}
	if c.Session.IdleMinutes != 45 || c.LoginLimit.Threshold != 4 {
		t.Fatalf("会话/限流节未落: %+v %+v", c.Session, c.LoginLimit)
	}
	// U13 传输安全节断言：两开关未勾→关闭（判定③锚）+参数落库（mode/maxAge/rua）
	if c.MTASts.Enabled || c.MTASts.ReportEnabled {
		t.Fatalf("传输安全两开关未勾应关闭: %+v", c.MTASts)
	}
	if c.MTASts.Mode != "testing" || c.MTASts.MaxAgeSeconds != 86400 || c.MTASts.RuaAddress != "tlsrpt@u10.example" {
		t.Fatalf("传输安全节参数未落: %+v", c.MTASts)
	}
	env.mu.Unlock()
	// 非法值拒绝（DKIM 算法越权枚举）
	bad := url.Values{"csrf_token": {"csrf-u10"}, "dkimAlgorithm": {"md5"}}
	if resp := postForm(t, env.ts, "/admin/settings", bad, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("非法算法应重渲染 200，得 %d", resp.StatusCode)
	}
	// 非正数拒绝
	bad2 := url.Values{"csrf_token": {"csrf-u10"}, "idleMinutes": {"0"}}
	if resp := postForm(t, env.ts, "/admin/settings", bad2, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("非正数应重渲染 200，得 %d", resp.StatusCode)
	}
}

// u10Session 造 admin/mailbox 会话并返回 cookie（u8/u9 同款直造形态）。
func (e *u10Env) u10Session(t *testing.T, subjectType storage.SubjectType, subjectID int64, csrf string) *http.Cookie {
	t.Helper()
	now := time.Now().UTC()
	raw := e.srv.sess.newSessionID()
	sess := &storage.Session{
		ID: e.srv.sess.idHashOf(raw), SubjectType: subjectType, SubjectID: subjectID,
		IP: "127.0.0.1", UserAgent: "u10test", CSRFToken: csrf,
		CreatedAt: now, LastSeenAt: now, AbsoluteExpiresAt: now.Add(12 * time.Hour),
	}
	// 经 Server 内部 sessions repo 直造——testEnv 字段缺省时回查不便，直接复用签发链路太重；
	// 直造需要 repo：经 CfgSnapshot 无关——用 sessions repo 注入点（Server.sessions）
	if err := e.srv.sessions.Create(context.Background(), sess); err != nil {
		t.Fatalf("造会话: %v", err)
	}
	return &http.Cookie{Name: sessionCookieName, Value: raw}
}

// ───────────────────────── 用例 5：80 双态（Q3-A——挑战直答+301；向导态 engine 直驱） ─────────────────────────

func TestU10HTTP80DualMode(t *testing.T) {
	env := newU10Env(t, nil)
	// 挑战表注入（fake ChallengeLookup）
	fake := &fakeChallenge{vals: map[string]string{"tok-1": "keyauth-1"}}
	env.srv.cfg.Challenge = fake

	// 完成态：挑战命中直答/未命中 404/其余路径 301 https
	env.mu.Lock()
	env.cfg.SetupCompleted = true
	env.mu.Unlock()
	w := httptest.NewRecorder()
	env.srv.challengeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/tok-1", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "keyauth-1") {
		t.Fatalf("挑战直答失败: %d %q", w.Code, w.Body.String())
	}
	w2 := httptest.NewRecorder()
	env.srv.challengeHTTP(w2, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/unknown", nil))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("未知挑战应 404，得 %d", w2.Code)
	}
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/mails", nil)
	r3.Host = "mail.example.com"
	env.srv.http80Root(w3, r3)
	if w3.Code != http.StatusMovedPermanently || !strings.HasPrefix(w3.Header().Get("Location"), "https://mail.example.com") {
		t.Fatalf("完成态 80 其余路径应 301 https，得 %d %s", w3.Code, w3.Header().Get("Location"))
	}

	// 引导态：http80Root 转 engine（向导 200）
	env.mu.Lock()
	env.cfg.SetupCompleted = false
	env.mu.Unlock()
	w4 := httptest.NewRecorder()
	env.srv.http80Root(w4, httptest.NewRequest(http.MethodGet, "/setup/1", nil))
	if w4.Code != http.StatusOK {
		t.Fatalf("引导态 80 应直驱向导 200，得 %d", w4.Code)
	}
}

// fakeChallenge ChallengeLookup 测试桩。
type fakeChallenge struct{ vals map[string]string }

func (f *fakeChallenge) Lookup(token string) (string, bool) {
	v, ok := f.vals[token]
	return v, ok
}
