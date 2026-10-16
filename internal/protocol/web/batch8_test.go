// Webmail前端可选交互增强批（γ批——审计实施批）web 侧测试（计划书 v1.0.0 第三章
// 步骤 2~4 验收锚；G2 批准 2026-10-15 01:22 三组候选全 A〔E-1-A/E-2-A/E-3-A〕）。
// 覆盖：①B5/E-1-A 分区提交——四节独立保存+未提交节保留现值+旧全量无 section 400
// +节内校验拒绝仅拒本节（已保存节不回滚）②C3/E-2-A 组件渲染等价——枢纽八项
// （settingsNavHub 唯一消费点）+返回链双分支（settingsNavBack admin/mailbox 两形态
// ——F7 批二双分支语义锚）+aria-label 统一拉平③E2/E-3-A 折叠结构——五节 details
// 默认全展开+summary 节标题（legend 键复用）+桌面禁交互 CSS 锚。
// 移动端视口折叠交互/浏览器走查属干系人实机域（历批口径）。
package web

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// b8Body 读响应体。
func b8Body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读响应体: %v", err)
	}
	return string(raw)
}

// b8Get GET（可选 cookie——body 保持打开，沿 batch7 b7Get 形态；全局 get 辅助返回前
// 已关闭 body〔u10 系仅断言状态码〕，本批 body 断言须经本辅助——测试环境前置自纠）。
func b8Get(t *testing.T, tsURL, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, tsURL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}

// ───────────────────────── B5/E-1-A：分区提交（u10Env——SaveConfig 内存读改写） ─────────────────────────

func TestBatch8B5SectionSubmit(t *testing.T) {
	cfg := config.Default()
	cfg.SetupCompleted = true
	env := newU10Env(t, cfg)
	cookie := env.u10Session(t, storage.SubjectTypeAdmin, 1, "csrf-b8")

	// ① 旧全量形态（无 section）→400（B5 分派——原全量提交不再受支持）
	if resp := postForm(t, env.ts, "/admin/settings", url.Values{
		"csrf_token": {"csrf-b8"}, "spfEnabled": {"on"},
	}, cookie); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("无 section POST 应 400，得 %d", resp.StatusCode)
	}

	// ② auth 节保存——仅本节落库；未提交节保留现值（delivery 默认限值不动锚）
	// 两项变更实施批适配（G2 批准 2026-10-17 03:37；SRS v1.2.0 FR-009 档位语义）：
	// auth 节表单增 SPF/DKIM 拒收档位 radio（soft/hard——缺省 soft 沿 Load 兜底先例）
	if resp := postForm(t, env.ts, "/admin/settings", url.Values{
		"csrf_token": {"csrf-b8"}, "section": {"auth"},
		"spfEnabled": {"on"}, "arcEnabled": {"on"},
		"spfPolicy": {"soft"}, "dkimPolicy": {"soft"},
	}, cookie); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("auth 节保存应 303，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	authNow := env.cfg.Auth
	mailNow := env.cfg.Mail
	env.mu.Unlock()
	if !authNow.SPFEnabled || !authNow.ARCEnabled {
		t.Fatalf("auth 节未落: %+v", authNow)
	}
	if mailNow.MaxMessageSizeBytes != config.Default().Mail.MaxMessageSizeBytes {
		t.Fatalf("未提交 delivery 节应保留现值: %d", mailNow.MaxMessageSizeBytes)
	}

	// ③ delivery 节非法值——仅拒本节（200 重渲染），已保存 auth 节不受牵连
	if resp := postForm(t, env.ts, "/admin/settings", url.Values{
		"csrf_token": {"csrf-b8"}, "section": {"delivery"}, "maxMessageSizeMB": {"0"},
	}, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("delivery 节非法值应重渲染 200，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	authSPFAfter := env.cfg.Auth.SPFEnabled
	env.mu.Unlock()
	if !authSPFAfter {
		t.Fatal("delivery 节校验失败不应回滚已保存 auth 节")
	}

	// ④ session/tls 节独立保存（节内必填项齐备——校验规则零增减锚）
	if resp := postForm(t, env.ts, "/admin/settings", url.Values{
		"csrf_token": {"csrf-b8"}, "section": {"session"},
		"idleMinutes": {"30"}, "absoluteHours": {"12"}, "limitWindowMinutes": {"15"}, "limitThreshold": {"5"},
	}, cookie); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("session 节保存应 303，得 %d", resp.StatusCode)
	}
	if resp := postForm(t, env.ts, "/admin/settings", url.Values{
		"csrf_token": {"csrf-b8"}, "section": {"tls"},
		"mtaStsMode": {"enforce"}, "mtaStsMaxAgeSeconds": {"604800"},
	}, cookie); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("tls 节保存应 303，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	sessNow, limitNow, stsNow := env.cfg.Session, env.cfg.LoginLimit, env.cfg.MTASts
	env.mu.Unlock()
	if sessNow.IdleMinutes != 30 || limitNow.Threshold != 5 {
		t.Fatalf("session 节未落: %+v %+v", sessNow, limitNow)
	}
	if stsNow.Mode != "enforce" || stsNow.MaxAgeSeconds != 604800 {
		t.Fatalf("tls 节未落: %+v", stsNow)
	}
}

// ───────────────────────── C3/E-2-A：组件渲染等价（HTTP 层——三形态锚） ─────────────────────────

func TestBatch8C3NavEquivalence(t *testing.T) {
	cfg := config.Default()
	cfg.SetupCompleted = true
	env := newU10Env(t, cfg)
	adminCk := env.u10Session(t, storage.SubjectTypeAdmin, 1, "csrf-b8a")
	mbCk := env.u10Session(t, storage.SubjectTypeMailbox, 2, "csrf-b8m")

	// 枢纽形态：/admin/settings 页首八项+aria-label（settingsNavHub——唯一枢纽消费点；
	// 与原内联形态逐项等价：active 服务配置+七链）
	body := b8Body(t, b8Get(t, env.ts.URL, "/admin/settings", adminCk))
	for _, want := range []string{
		`aria-label="管理导航"`, `class="active"`,
		`href="/admin/mailboxes"`, `href="/admin/mailboxes/unregistered"`,
		`href="/admin/tokens"`, `href="/admin/plugins"`, `href="/sieve"`, `href="/admin/password"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("枢纽导航缺 %q", want)
		}
	}

	// 返回链 admin 形态：/admin/password 页（settingsNavBack isAdmin=true——
	// aria-label+/admin/settings 直达；单链四消费点 admin×2/plugins/tokens 同构）
	pb := b8Body(t, b8Get(t, env.ts.URL, "/admin/password", adminCk))
	if !strings.Contains(pb, `aria-label="管理导航"`) || !strings.Contains(pb, `href="/admin/settings"`) {
		t.Fatal("admin 返回链应含 aria-label 与 /admin/settings 链")
	}

	// 返回链 mailbox 形态：/settings/password 页（isAdmin=false→/settings——
	// F7 批二「mailbox 经个人枢纽」双分支语义锚；aria-label 组件统一拉平）
	mb := b8Body(t, b8Get(t, env.ts.URL, "/settings/password", mbCk))
	if !strings.Contains(mb, `href="/settings"`) || strings.Contains(mb, `href="/admin/settings"`) {
		t.Fatal("mailbox 返回链应指向 /settings（F7 双分支语义）")
	}
	if !strings.Contains(mb, `aria-label="管理导航"`) {
		t.Fatal("mailbox 返回链应含统一 aria-label（组件拉平）")
	}
}

// ───────────────────────── E2/E-3-A：折叠结构（默认全展开+桌面禁交互 CSS 锚） ─────────────────────────

func TestBatch8E2FoldStructure(t *testing.T) {
	cfg := config.Default()
	cfg.SetupCompleted = true
	env := newU10Env(t, cfg)
	adminCk := env.u10Session(t, storage.SubjectTypeAdmin, 1, "csrf-b8e")
	body := b8Body(t, b8Get(t, env.ts.URL, "/admin/settings", adminCk))

	// E-3-A：五节 details 默认全展开（open×5——移动端默认呈现与现状一致仅新增可收起）
	if got := strings.Count(body, `<details class="settings-fold" open>`); got != 5 {
		t.Fatalf("settings-fold 默认全展开应 5 节，得 %d", got)
	}
	// summary 承载节标题（legend 键复用——zh 原文前缀锚）
	for _, legend := range []string{"认证与反伪造栈", "投递与聚合", "会话与登录限流", "传输安全", "DNS 发布建议"} {
		if !strings.Contains(body, "<summary>"+legend) {
			t.Fatalf("折叠节标题缺 %q", legend)
		}
	}
	// B5/E-1-A：四节独立表单 section 隐藏域（auth/delivery/session/tls——DNS 只读节无表单）
	for _, sec := range []string{"auth", "delivery", "session", "tls"} {
		if !strings.Contains(body, `<input type="hidden" name="section" value="`+sec+`"`) {
			t.Fatalf("section 隐藏域缺 %s", sec)
		}
	}
	// 节尾保存钮×4（每节独立保存钮——「一次保存全部五节」批量交互移除后形态锚；
	// 精确锚 primary 类——顶栏登出钮〔menu-danger〕不计入，测试自身断言形态自纠）
	if got := strings.Count(body, `<button class="primary" type="submit">`); got != 4 {
		t.Fatalf("节尾保存钮应 4（每可编辑节一枚），得 %d", got)
	}

	// 桌面禁交互 CSS 锚（≥768 pointer-events:none——桌面呈现零变化锚）+<768 三角指示
	css, err := os.ReadFile("../../../web/static/app.css")
	if err != nil {
		t.Fatalf("读 app.css: %v", err)
	}
	cssText := string(css)
	for _, want := range []string{
		".settings-fold > summary { pointer-events: none;",
		".settings-fold:not([open]) > summary::after",
		".settings-fold form { gap: 0; }",
	} {
		if !strings.Contains(cssText, want) {
			t.Fatalf("E2 CSS 锚缺失: %q", want)
		}
	}
}
