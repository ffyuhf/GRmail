// GRM代码侧批测试（GRM-008/009/010/012 四项实施锚——G2 批准 2026-10-20 12:06:32
// 「E-1 A /E-2 A/ E-3 A/E-4 B/E-5 A/E-6 B/E-7 B/E-8 C/E-9 C/」；纯新增文件——既有
// 断言零触碰，步骤 0 grep 披露：batch2 纯文本样例无 HTML 字符/batch10 next 合法形态）。
// 依据：[GRM代码侧批_计划_20261020_11-26-00_v1.0.0](../../../../../项目文档/02-计划/01-按年度/2026/10-十月/GRM代码侧批_计划_20261020_11-26-00_v1.0.0.md) 第七章。
// 修改历史：
//
//	2026-10-20 12:23:00 | 新增 | GRM代码侧批（E-1-A/E-2-A/E-3-A/E-5-A 四锚）
package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"GRmail/internal/storage"
)

// TestGRM008HtmlEscapeBody E-1-A：纯文本转义真实化直测（原空操作缺陷锚——
// 标签字面量转义为文本呈现；& 先行防二次转义；非 ASCII 原样）。
// 注：实体期望值经变量拼接构造（"+"amp;" 等——免疫工具链写入层实体解码）。
func TestGRM008HtmlEscapeBody(t *testing.T) {
	amp, lt, gt := "&"+"amp;", "&"+"lt;", "&"+"gt;"
	if got := htmlEscapeBody("<b>x</b>"); got != lt+"b"+gt+"x"+lt+"/b"+gt {
		t.Fatalf("标签转义: %q", got)
	}
	if got := htmlEscapeBody("a&b<c>d"); got != "a"+amp+"b"+lt+"c"+gt+"d" {
		t.Fatalf("三字符混合转义: %q", got)
	}
	if got := htmlEscapeBody("批二纯文本正文行"); got != "批二纯文本正文行" {
		t.Fatalf("非 ASCII 原样: %q", got)
	}
	if got := htmlEscapeBody(""); got != "" {
		t.Fatalf("空串: %q", got)
	}
}

// TestGRM010RedirectBackslashRejected E-3-A：站内回跳路径反斜杠变体矩阵
// （原始态 /\ 与编码态 /%5C 同拒；合法站内路径零影响；既有 // 拒绝锚保持）。
func TestGRM010RedirectBackslashRejected(t *testing.T) {
	reject := []string{
		`/\evil.com`,      // 反斜杠原始态（部分浏览器当路径分隔→外跳）
		"/%5Cevil.com",    // 编码态（解码后 /\ 同拒）
		"//evil.com",      // 既有协议相对锚（保持拒绝）
		"/%2F%2Fevil.com", // 双斜杠全编码态
		"",                // 空
		"mails",           // 非绝对路径
	}
	for _, p := range reject {
		if got := safeRedirectPath(p); got != "/" {
			t.Fatalf("safeRedirectPath(%q)=%q, want \"/\"（应拒）", p, got)
		}
	}
	pass := []string{"/mails", "/settings/2fa", "/?folder=3", "/"}
	for _, p := range pass {
		if got := safeRedirectPath(p); got != p {
			t.Fatalf("safeRedirectPath(%q)=%q, want 原值（合法站内路径应放行）", p, got)
		}
	}
}

// TestGRM010LangNextBackslashRejected E-3-A 端点锚：/lang 切换 next 反斜杠
// 编码形态拒绝回 /（双消费点同步收敛验证——i18n.go langSetGET 共用判定）。
func TestGRM010LangNextBackslashRejected(t *testing.T) {
	env := newU9Env(t)
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/lang?l=en&next="+url.QueryEscape(`/\evil.com`), nil)
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("GET /lang: %v", err)
	}
	defer res.Body.Close()
	if loc := res.Header.Get("Location"); loc != "/" {
		t.Fatalf("next=反斜杠形态应拒绝回 /，得 Location=%q", loc)
	}
}

// TestGRM012TimeoutClearsCookie E-5-A：会话空闲超时命中——服务端 Delete 后
// 响应携带 __Host-sid 清除头（置空值+过期时间戳过去——logout.go 同款形态）。
func TestGRM012TimeoutClearsCookie(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	now := time.Now().UTC()
	raw := env.srv.sess.newSessionID()
	sess := &storage.Session{
		ID:                env.srv.sess.idHashOf(raw),
		SubjectType:       storage.SubjectTypeMailbox,
		SubjectID:         env.mailbox.ID,
		CreatedAt:         now.Add(-2 * time.Hour),
		LastSeenAt:        now.Add(-2 * time.Hour), // 空闲 2h > 缺省 30min → 超时命中
		AbsoluteExpiresAt: now.Add(1 * time.Hour),  // 绝对未过期（隔离空闲分支）
	}
	if err := env.sessions.Create(ctx, sess); err != nil {
		t.Fatalf("构造过期会话: %v", err)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: raw})
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer res.Body.Close()

	var cleared *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("超时响应应携带 __Host-sid 清除头（GRM-012 E-5-A）")
	}
	if cleared.Value != "" || !cleared.Expires.Before(time.Now()) {
		t.Fatalf("清除头应为空值+过期时间戳，得 Value=%q Expires=%v", cleared.Value, cleared.Expires)
	}
	// 服务端行已删（超时主动 Delete 既有锚复验）。
	if _, fErr := env.sessions.Find(ctx, env.srv.sess.idHashOf(raw)); !errors.Is(fErr, storage.ErrSessionNotFound) {
		t.Fatalf("超时会话服务端应已删除（ErrSessionNotFound），Find 得 %v", fErr)
	}
}

// TestGRM009VerifyAdminDummyPath E-2-A：不存在用户名走 dummy 哈希路径——
// 拒绝语义/无故障行为等价锚（时序对齐由 dummy 同成本校验承载，不可稳定断言）。
func TestGRM009VerifyAdminDummyPath(t *testing.T) {
	env := newU9Env(t)
	valid, subjectID, err := env.srv.verifyAdmin(context.Background(), "no-such-admin-grm009", "whatever-password")
	if valid || subjectID != 0 || err != nil {
		t.Fatalf("不存在用户名应统一拒绝（valid=false/id=0/err=nil），得 %v/%d/%v", valid, subjectID, err)
	}
	// 二次调用（sync.Once 已初始化路径——dummy 缓存态行为一致）。
	valid2, _, err2 := env.srv.verifyAdmin(context.Background(), "no-such-admin-grm009", "another")
	if valid2 || err2 != nil {
		t.Fatalf("dummy 缓存态二次调用应一致拒绝，得 %v/%v", valid2, err2)
	}
}
