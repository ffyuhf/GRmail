// U23 HTTP 请求摘要 debug 中间件测试（计划书 1.5⑧⑤——开启摘要行四要素+logid 锚/
// 关闭与 nil 注入零输出锚；Q2-A 摘要口径——不含请求体/头断言；沿 u16/u17 httptest 先例）。
// 修改历史：
//
//	2026-09-27 13:56:00 | 新建 | U23 可观测性扩展（计划书步骤 6，G2 批准 2026-09-27 13:20:53）
package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestU23HTTPDebugMiddleware HTTP 请求摘要 debug 条件输出（Q2-A——U21 登记项② Web 侧收口）。
func TestU23HTTPDebugMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	// 开启态：entryMiddleware（logid ctx 建立）+httpDebugMiddleware+探针路由。
	on := &Server{cfg: ServerConfig{ProtocolDebug: func() bool { return true }}}
	on.engine = gin.New()
	on.engine.Use(on.entryMiddleware(), on.httpDebugMiddleware())
	on.engine.GET("/u23probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	w := httptest.NewRecorder()
	on.engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/u23probe", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("探针路由应 200，实际 %d", w.Code)
	}
	out := buf.String()
	for _, anchor := range []string{"http_debug", "method=GET", "/u23probe", "status=200", "log_id="} {
		if !strings.Contains(out, anchor) {
			t.Fatalf("开启态摘要行缺失锚 %q，实际: %s", anchor, out)
		}
	}
	if strings.Contains(out, "cookie=") || strings.Contains(out, "body=") {
		t.Fatalf("摘要口径破坏：输出含请求体/头内容，实际: %s", out)
	}

	// 关闭态（nil 注入=禁用）零输出。
	buf.Reset()
	off := &Server{cfg: ServerConfig{}} // ProtocolDebug nil=禁用
	off.engine = gin.New()
	off.engine.Use(off.entryMiddleware(), off.httpDebugMiddleware())
	off.engine.GET("/u23probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	w2 := httptest.NewRecorder()
	off.engine.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/u23probe", nil))
	if w2.Code != http.StatusOK || buf.Len() != 0 {
		t.Fatalf("nil 注入禁用态应 200+零输出，实际 code=%d out=%s", w2.Code, buf.String())
	}
}
