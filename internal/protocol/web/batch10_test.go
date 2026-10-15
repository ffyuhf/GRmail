// 外部审计缺陷修复批 web 侧测试（计划书 v1.0.0 第三章步骤 3/4/5 验收锚——
// E-2 HSTS 条件注入负锚〔明文不发〕/E-3 Permissions-Policy 在位/E-4 三 cookie
// SameSite 属性/E-5 CSP font-src+woff2 MIME/E-6 超时构造态）。
// E-1（mtasts 通配 mx）断言由 transport 包 u13_test TestU13STSPolicyTextABNF
// 形态适配承载（G2 批准行为变化——批准面机械适配，意图锚保持）。
// 依据：外部审计缺陷修复批_计划_20261015_21-45-00_v1.0.0（G2 批准 2026-10-15
// 21:50:17——INV-26 三要素）；rfc6797 §6.1.1/6.1.2/§7.2 L984（E-2 规范锚——
// 非安全传输 MUST NOT 注入）。
package web

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestBatch10E2E3E5Headers 安全头三增量断言（公开页直驱——无需会话）：
// E-5 CSP 含 font-src 'self'（δ批品牌字体加载通路兑现锚）；E-3 Permissions-Policy
// 六能力全禁用在位；E-2 明文请求（httptest HTTP 端点）响应无 HSTS——条件注入负锚
// （rfc6797 §7.2 L984「MUST NOT include the STS header field in HTTP responses
// conveyed over non-secure transports」合规；TLS 正向分支由条件注入形态+该
// MUST NOT 共同锁定——明文负锚为本测试环境可承载面）。
func TestBatch10E2E3E5Headers(t *testing.T) {
	env := newU9Env(t)
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/login", nil)
	res, err := env.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("状态: %d", res.StatusCode)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "font-src 'self'") {
		t.Fatalf("E-5 CSP 缺 font-src 'self'（实际: %s）", csp)
	}
	wantPP := "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()"
	if pp := res.Header.Get("Permissions-Policy"); pp != wantPP {
		t.Fatalf("E-3 Permissions-Policy 不符:\n got=%q\nwant=%q", pp, wantPP)
	}
	if hsts := res.Header.Get("Strict-Transport-Security"); hsts != "" {
		t.Fatalf("E-2 明文请求不得携带 HSTS（rfc6797 §7.2 MUST NOT——实际: %q）", hsts)
	}
}

// TestBatch10E4CookieSameSite cookie SameSite 属性断言（E-4——与既有注释口径
// 一致化：lang=Lax〔i18n.go〕/loginRedirect=Strict〔session.go 5min 回跳〕）。
// gin c.SetCookie 七参签名无 SameSite 位——改 http.SetCookie 显式承载后的属性锚。
func TestBatch10E4CookieSameSite(t *testing.T) {
	env := newU9Env(t)
	// 禁跟随客户端（沿 batch5 noFollow 先例）：/lang 为 302 重定向响应——自动跟随
	// 将丢失中间响应的 Set-Cookie（httptest client 无 cookie jar），须直取首跳解析。
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	// lang cookie（公开端点 /lang）。
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/lang?l=en&next=/", nil)
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("GET /lang: %v", err)
	}
	res.Body.Close()
	var lang *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "lang" {
			lang = c
		}
	}
	if lang == nil {
		t.Fatalf("lang cookie 未下发")
	}
	if lang.SameSite != http.SameSiteLaxMode {
		t.Fatalf("lang SameSite=%v，want Lax", lang.SameSite)
	}
	// loginRedirect cookie（会话失效 GET 302 前置写入——requireAuth）。
	req2, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/mails", nil)
	res2, err := noFollow.Do(req2)
	if err != nil {
		t.Fatalf("GET /mails: %v", err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusFound {
		t.Fatalf("无会话 /mails 应 302，得 %d", res2.StatusCode)
	}
	var redir *http.Cookie
	for _, c := range res2.Cookies() {
		if c.Name == loginRedirectCookie {
			redir = c
		}
	}
	if redir == nil {
		t.Fatalf("grmail_login_redirect cookie 未下发")
	}
	if redir.SameSite != http.SameSiteStrictMode {
		t.Fatalf("loginRedirect SameSite=%v，want Strict", redir.SameSite)
	}
}

// TestBatch10E5Woff2MIME 字体 MIME 断言（E-5 伴生——font/woff2；原 octet-stream）。
func TestBatch10E5Woff2MIME(t *testing.T) {
	env := newU9Env(t)
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/static/fonts/geist-latin-var.woff2", nil)
	res, err := env.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET woff2: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("woff2 状态: %d（δ批 vendor 资产应在位）", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "font/woff2" {
		t.Fatalf("E-5 woff2 MIME=%q，want font/woff2", ct)
	}
}

// TestBatch10E6Timeouts HTTP 服务超时构造态断言（E-6-A 温和档——G2 批准
// 2026-10-15 21:50:17：Read/Write 300s+Idle 120s；同包私有字段直读）。
func TestBatch10E6Timeouts(t *testing.T) {
	env := newU9Env(t)
	s := env.srv.httpSrv
	if s.ReadTimeout != 300*time.Second {
		t.Fatalf("ReadTimeout=%v，want 300s", s.ReadTimeout)
	}
	if s.WriteTimeout != 300*time.Second {
		t.Fatalf("WriteTimeout=%v，want 300s", s.WriteTimeout)
	}
	if s.IdleTimeout != 120*time.Second {
		t.Fatalf("IdleTimeout=%v，want 120s", s.IdleTimeout)
	}
	if s.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout=%v，want 10s（既有基线保持）", s.ReadHeaderTimeout)
	}
}
