// C级债务收尾批 web 域测试（F12/F13——2026-10-10，G2 批准 15:45:40）。
// 覆盖：lang cookie HttpOnly 属性、公开资源请求不 Touch 续期（OWASP 空闲超时
// 语义增强）。F11（Bearer 登出短路）经代码审查承载——分支为纯三行短路，
// 合成会话构造依赖 Bearer 全链 token 基建（CHANGE5 登记偏差）。
// 修改历史：
//
//	2026-10-10 16:15:00 | 新建 | C级债务收尾批（计划书步骤 1/4）
package web

import (
	"context"
	"net/http"
	"testing"
	"time"

	"GRmail/internal/storage"
)

// TestCDebtLangCookieHttpOnly F12/C23：GET /lang 响应 Set-Cookie 含 HttpOnly。
func TestCDebtLangCookieHttpOnly(t *testing.T) {
	env := newU9Env(t)
	req, err := http.NewRequest(http.MethodGet, env.ts.URL+"/lang?l=en&next=/", nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	// 不跟随重定向：lang cookie 在 302 首响应的 Set-Cookie（默认客户端跟随后丢失）
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatal("应下发 lang cookie")
	}
	found := false
	for _, c := range cookies {
		if c.Name == "lang" {
			found = true
			if !c.HttpOnly {
				t.Fatalf("lang cookie 应 HttpOnly: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("未找到 lang cookie")
	}
}

// TestCDebtPublicAssetNoTouch F13/C24：公开自动加载资源（/static/）不刷新会话
// LastSeenAt（空闲超时不被后台请求续命）；业务请求（/）照常续期（语义锚）。
func TestCDebtPublicAssetNoTouch(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-cdebt")
	hash := env.srv.sess.idHashOf(cookie)
	base, err := env.sessions.Find(ctx, hash)
	if err != nil {
		t.Fatalf("基线会话: %v", err)
	}

	// 跨秒窗口（SQLite 时间列 RFC3339 秒级精度——60ms 内 Touch 与否同秒不可区分；
	// 1.1s 后基线秒与当前秒必然不同：静态请求若误 Touch 则 LastSeenAt 变为当前秒）
	time.Sleep(1100 * time.Millisecond)
	env.get(t, "/static/htmx.min.js", cookie)
	afterStatic, err := env.sessions.Find(ctx, hash)
	if err != nil {
		t.Fatalf("静态后会话: %v", err)
	}
	if !afterStatic.LastSeenAt.Equal(base.LastSeenAt) {
		t.Fatalf("公开资源不应 Touch 续期: base=%v after=%v", base.LastSeenAt, afterStatic.LastSeenAt)
	}

	env.get(t, "/", cookie) // 业务请求——requireAuth 前经 sessionMiddleware Touch
	afterHome, err := env.sessions.Find(ctx, hash)
	if err != nil {
		t.Fatalf("业务后会话: %v", err)
	}
	if !afterHome.LastSeenAt.After(base.LastSeenAt) {
		t.Fatal("业务请求应照常续期（既有语义锚）")
	}
}
