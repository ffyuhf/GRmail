// Webmail前端缺陷修复批·批三 web 侧测试（计划书 v1.0.0 第三章步骤 1~7 验收锚；
// G2 批准 2026-10-12 22:21:32 三组候选全 A——E-1-A 重建出口/E-2-A 启动确保/E-3-A 白名单）。
// 覆盖：①A1 GET /settings/2fa 与 /admin/2fa pending 态重建二维码+密钥（双侧——
// 契约 v1.42.1 3.2 三态渲染承载；已绑定/未发起态零变化锚）②A4 /sieve 视图缺位
// 503 文案分键（errNoView≠errDisabled）③A5 退出搜索链接缺省回退（无 folder=0
// 非法参数）④A6 save_draft 无收件人 303（send 校验保持 400 锚）⑤B12/E-3-A 文件夹
// 名白名单（非法拒绝+合法中文通过+保留名拒绝）⑥E-2-A EnsureAdminMailbox 幂等。
package web

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// ───────────────────────── A1：2FA GET 重建（双侧） ─────────────────────────

// batch3Env A1 测试环境（u24Env 形态+AdminTwoFactor 注入——admin 侧同源核对承载）。
type batch3Env struct {
	srv         *Server
	ts          *httptest.Server
	twoFA       *account.TwoFactorService
	adminTwoFA  *account.AdminTwoFactorService
	mailbox     *storage.Mailbox
	mbPass      string
	adminPass   string
	b3MailboxCk string // mailbox 会话 cookie（登录直通获取）
}

// newBatch3Env 构造 A1 测试环境（临时库+管理员+mailbox+双 2FA 服务注入）。
func newBatch3Env(t *testing.T) *batch3Env {
	t.Helper()
	db, err := storage.Open(context.Background(), config.DatabaseConf{Driver: "sqlite", DSN: t.TempDir() + "/b3.db"})
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

	adminHash, err := account.HashPassword("b3-admin-pass!")
	if err != nil {
		t.Fatalf("哈希管理员密码: %v", err)
	}
	if err := users.EnsureAdmin(context.Background(), &storage.User{Username: "admin", PasswordHash: adminHash}); err != nil {
		t.Fatalf("预置管理员: %v", err)
	}
	mb, err := accounts.CreateMailbox(context.Background(), "b3@test.local", "b3-mb-pass!")
	if err != nil {
		t.Fatalf("创建 mailbox 账号: %v", err)
	}
	twoFA := account.NewTwoFactorService(mailboxRepo)
	adminTwoFA := account.NewAdminTwoFactorService(users)
	srv := NewServer(ServerConfig{
		Domain:         "test.local",
		TLSConfig:      func() *tls.Config { return nil },
		Mailboxes:      mailboxRepo,
		TwoFactor:      twoFA,
		AdminTwoFactor: adminTwoFA,
	}, sessions, users, attempts, accounts)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return &batch3Env{srv: srv, ts: ts, twoFA: twoFA, adminTwoFA: adminTwoFA,
		mailbox: mb, mbPass: "b3-mb-pass!", adminPass: "b3-admin-pass!"}
}

// b3PostLogin 表单登录（不跟随重定向——取首响应 cookie/状态）。
func (e *batch3Env) b3PostLogin(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(form.Encode()))
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

// b3MailboxLogin mailbox 登录直通（未绑定态 303）并缓存会话 cookie。
func (e *batch3Env) b3MailboxLogin(t *testing.T) string {
	t.Helper()
	if e.b3MailboxCk != "" {
		return e.b3MailboxCk
	}
	resp := e.b3PostLogin(t, "/webmail/login", url.Values{
		"address": {e.mailbox.Address}, "password": {e.mbPass}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("未绑定账号登录应 303 直通: %d", resp.StatusCode)
	}
	ck := sessionCookieOf(resp)
	if ck == nil {
		t.Fatal("登录直通应签发会话 cookie")
	}
	e.b3MailboxCk = ck.Value
	return e.b3MailboxCk
}

// TestBatch3A1MailboxGETRebuildPending A1（mailbox 侧/E-1-A）：pending 态 GET
// /settings/2fa 重建二维码+密钥（密钥零变更——GET 与 setup 响应密钥一致锚；
// 未发起态零变化锚：无二维码无密钥）。
func TestBatch3A1MailboxGETRebuildPending(t *testing.T) {
	e := newBatch3Env(t)
	ctx := context.Background()
	cookie := e.b3MailboxLogin(t)

	// 未发起态锚：GET 无二维码无密钥（启用入口态）
	res := e.getWithCookie(t, "/settings/2fa", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("未发起态 GET 状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if strings.Contains(page, "data:image/png;base64,") || strings.Contains(page, "<code>") {
		t.Fatal("未发起态不应呈现二维码/密钥（零变化锚）")
	}

	// 发起绑定（pending 态）→ GET 重建
	mat, err := e.twoFA.InitiateBinding(ctx, e.mailbox.ID, e.mailbox.Address, "test.local")
	if err != nil {
		t.Fatalf("发起绑定: %v", err)
	}
	res2 := e.getWithCookie(t, "/settings/2fa", cookie)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("pending 态 GET 状态: %d", res2.StatusCode)
	}
	page2 := bodyOf(t, res2)
	if !strings.Contains(page2, "data:image/png;base64,") {
		t.Fatal("pending 态 GET 应重建二维码（A1 死锁收口锚——契约 3.2 双形态）")
	}
	if !strings.Contains(page2, mat.Secret) {
		t.Fatal("pending 态 GET 应重建明文密钥（手动输入通道）")
	}
	// 二次 GET 密钥稳定（E-1-A 密钥零变更——已导入 App 条目保持有效锚）
	res3 := e.getWithCookie(t, "/settings/2fa", cookie)
	if page3 := bodyOf(t, res3); !strings.Contains(page3, mat.Secret) {
		t.Fatal("二次 GET 密钥应保持不变（重建非再生成——E-1-A 能力锚）")
	}
}

// TestBatch3A1AdminSideGETRebuild A1（admin 侧强制并入核对）：/admin/2fa pending
// 态 GET 重建二维码+密钥（评审 §8.4 遗漏面同源风险同修锚）。
func TestBatch3A1AdminSideGETRebuild(t *testing.T) {
	e := newBatch3Env(t)
	ctx := context.Background()
	adminID := int64(1) // EnsureAdmin 首行
	mat, err := e.adminTwoFA.InitiateBinding(ctx, adminID, "admin@test.local", "test.local")
	if err != nil {
		t.Fatalf("admin 发起绑定: %v", err)
	}
	// admin 登录（未绑定直通——password 步即建立会话）
	resp := e.b3PostLogin(t, "/login", url.Values{"username": {"admin"}, "password": {e.adminPass}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin 未绑定登录应 303: %d", resp.StatusCode)
	}
	ck := sessionCookieOf(resp)
	if ck == nil {
		t.Fatal("admin 登录应签发会话")
	}
	res := e.getWithCookie(t, "/admin/2fa", ck.Value)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin pending 态 GET 状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "data:image/png;base64,") || !strings.Contains(page, mat.Secret) {
		t.Fatal("admin pending 态 GET 应重建二维码+密钥（同源核对锚）")
	}
}

// getWithCookie 带 cookie GET（不跟随重定向——沿 u24PostLogin 客户端形态）。
func (e *batch3Env) getWithCookie(t *testing.T, path, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Cookie", sessionCookieName+"="+cookie)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return res
}

// ───────────────────────── A4：/sieve 文案分键 + E-2-A 幂等 ─────────────────────────

// TestBatch3A4SieveNoViewFenjian A4：admin 主体+主邮箱实体缺位 → /sieve 503 呈现
// errNoView（「主邮箱未建立」——原 errDisabled「Sieve 未启用」误导收口锚）。
func TestBatch3A4SieveNoViewFenjian(t *testing.T) {
	env := newU9Env(t) // admin 主体视图=postmaster@域 未建立（仅业务 mailbox 在位）
	adminCookie := env.u9Session(t, storage.SubjectTypeAdmin, 999, "csrf-b3a")
	res := env.get(t, "/sieve", adminCookie)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("视图缺位应 503: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "主邮箱未建立") {
		t.Fatalf("应呈现 errNoView 分键文案（视图缺位≠未启用）: %s", page[:min(300, len(page))])
	}
	if strings.Contains(page, "Sieve 未启用") {
		t.Fatal("视图缺位不得复用 errDisabled 误导文案（分叉锚）")
	}
}

// TestBatch3E2AEnsureAdminMailbox E-2-A：EnsureAdminMailbox 幂等——不存在建影子
// （status=shadow，激活归管理页）；已存在直返同 ID；并发 UNIQUE 冲突回读（F5 先例）。
func TestBatch3E2AEnsureAdminMailbox(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: t.TempDir() + "/b3e2.db"})
	if err != nil {
		t.Fatalf("打开临时库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	svc := account.NewService(storage.NewSQLiteMailboxRepo(db), storage.NewSQLiteFolderRepo(db))
	m1, err := svc.EnsureAdminMailbox(ctx, "admin@t.io")
	if err != nil {
		t.Fatalf("首次确保: %v", err)
	}
	if m1.Status != storage.MailboxStatusShadow {
		t.Fatalf("新建应为影子态（激活归管理页——架构 6.6-G1 注记）: %s", m1.Status)
	}
	m2, err := svc.EnsureAdminMailbox(ctx, "admin@t.io")
	if err != nil {
		t.Fatalf("二次确保（幂等）: %v", err)
	}
	if m2.ID != m1.ID {
		t.Fatalf("幂等应同 ID: %d vs %d", m2.ID, m1.ID)
	}
}

// ───────────────────────── A5：退出搜索链接缺省回退 ─────────────────────────

// TestBatch3A5ExitSearchDefaultFallback A5：搜索态片段退出链接不再拼 ActiveFolder
// （搜索态恒 0——folder=0 非法参数入地址栏收口）；指向缺省全量视图（服务端回退
// 收件箱+unread 清零语义）。
func TestBatch3A5ExitSearchDefaultFallback(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b3b")
	res := env.getWithHeaders(t, "/search?keyword=b3", cookie, map[string]string{"HX-Request": "true"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("搜索态片段状态: %d", res.StatusCode)
	}
	frag := bodyOf(t, res)
	// 注：HTML 属性中 & 转义为 &——断言按转义后形态匹配
	if !strings.Contains(frag, "/mails?page=1") {
		t.Fatal("退出搜索应指向缺省全量视图（无 folder 参数——服务端回退承载）")
	}
	// 属性级匹配（folder=0 作为 URL 参数形态——后随 & 或引号；规避模板注释文字误报）
	if i := strings.Index(frag, "folder=0&"); i >= 0 {
		t.Fatalf("不得再含非法零值 folder 参数（A5 收口锚）: …%s…", frag[max(0, i-100):min(len(frag), i+60)])
	}
	if i := strings.Index(frag, `folder=0"`); i >= 0 {
		t.Fatalf("不得再含非法零值 folder 参数（A5 收口锚·链接尾位形态）: …%s…", frag[max(0, i-100):min(len(frag), i+60)])
	}
}

// ───────────────────────── A6：草稿校验按 action 分组 ─────────────────────────

// TestBatch3A6SaveDraftNoRecipient A6：save_draft 无收件人→303 成功（U9 Q5-A 草稿
// 最小闭环语义兑现）；send 无收件人→400 保持（全量校验锚——发送路径零变化）。
func TestBatch3A6SaveDraftNoRecipient(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b3c")

	// save_draft 无收件人（半成品草稿）：应 303（原被「收件人不能为空」拦截——A6 收口）
	res := env.postForm(t, "/compose", cookie, "csrf-b3c", map[string][]string{
		"action": {"save_draft"}, "to": {}, "subject": {"b3 半成品"}, "body": {"<p>写到一半</p>"},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("save_draft 无收件人应 303: %d body=%s", res.StatusCode, bodyOf(t, res))
	}

	// send 无收件人：400 保持（send 全量校验锚——反向缺陷防线）
	res2 := env.postForm(t, "/compose", cookie, "csrf-b3c", map[string][]string{
		"action": {"send"}, "to": {}, "subject": {"b3"}, "body": {"<p>b3</p>"},
	})
	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("send 无收件人应保持 400: %d", res2.StatusCode)
	}
	if page := bodyOf(t, res2); !strings.Contains(page, "收件人") {
		t.Fatal("send 校验文案应保持（全量校验锚）")
	}
}

// ───────────────────────── B12/E-3-A：文件夹名白名单 ─────────────────────────

// TestBatch3B12FolderNameWhitelist B12/E-3-A：非法名（路径分隔/HTML 标签/控制符/
// 引号/保留系统名/超长）拒绝+用户可读文案；合法常规中文名通过（中文锚——E-3-A
// 可打印字符集兼容面）。
func TestBatch3B12FolderNameWhitelist(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b3d")

	reject := []string{"a/b", "<img src=x>", "x?y", "a#b", "he&llo", `"q"`, "'q'", "inbox", strings.Repeat("长", 65)}
	for _, name := range reject {
		res := env.postForm(t, "/folders", cookie, "csrf-b3d", map[string][]string{"name": {name}})
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("非法名 %q 应 400: %d", name, res.StatusCode)
		}
		if page := bodyOf(t, res); !strings.Contains(page, "文件夹名") {
			t.Fatalf("非法名 %q 应呈现白名单文案: %s", name, page[:min(200, len(page))])
		}
	}

	// 合法中文名（≤64 常规文字）：303 创建成功（中文锚——白名单不得拒绝常规名）
	res := env.postForm(t, "/folders", cookie, "csrf-b3d", map[string][]string{"name": {"批三测试文件夹"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("合法中文名应 303 创建: %d body=%s", res.StatusCode, bodyOf(t, res))
	}
}
