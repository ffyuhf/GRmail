// U17 富文本编辑器 web 侧测试（NFR-015 全离线——组件渲染直驱+静态端点）。
// 覆盖：①ComposeView 渲染断言（Quill vendor 资源引用/编辑器容器/工具栏容器/
// 隐藏 body input/初始内容携带/全屏按钮双语）②vendor 资源端点（/static/quill.js
// 200+text/javascript 与 /static/quill.snow.css 200+text/css——embed 通道锚）。
// 依据：U17 计划书 1.5①②③④⑪（Q2/Q3 裁决断言锚）；契约 v1.13.0 3.2/3.4。
// 发送链 e2e（登录→POST HTML 态→Sent 副本 HTML 断言）沿 U16 登记先例归下次
// 触碰批次补强（构造层 BuildOutgoingMail 矩阵+fillFromDraft 编译级接线覆盖）。
// U19 增量：工具栏 title 快捷键提示断言（四键 Ctrl+B/I/U/K——Quill 2.0.3 内置绑定，
// U17 登记项④收口；无绑定九键 title 保持——回归锚）。
// 修改历史：
//
//	2026-09-24 23:10:00 | 新建 | U17 富文本编辑器（计划书步骤 5，G2 批准 2026-09-24 22:51:39）
//	2026-09-26 17:12:00 | 扩展 | U19 编辑器体验收尾：title 快捷键断言（四键追加+九键零触碰锚）
//	（依据：U19 计划书 v1.0.0 步骤 3/1.5④，G2 批准 2026-09-26 16:45:48）
package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"GRmail/web/templates"
)

// TestU17ComposeEditorRender ComposeView 渲染断言：编辑器集成要素全量呈现。
func TestU17ComposeEditorRender(t *testing.T) {
	w := httptest.NewRecorder()
	data := &templates.ComposeData{
		Lang: "zh", IsAdmin: false, CSRF: "csrf-token-x",
		To: "to@x.com", Subject: "渲染主题", Body: "<p>初始正文</p>",
	}
	if err := templates.ComposeView(data).Render(context.Background(), w); err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	s := w.Body.String()
	for _, want := range []string{
		`href="/static/quill.snow.css"`,
		`src="/static/quill.js"`,
		`id="compose-toolbar"`,
		`id="editor-container"`,
		`id="f-body"`,
		`id="editor-initial"`,
		`id="compose-page"`,
		`id="fullscreen-btn"`,
		`onsubmit="return grmailComposeSync();"`,
		"初始正文", // 初始内容经隐藏 textarea 文本携带（转义细节不锚）
		"ql-bold", "ql-image", "ql-clean",
		"全屏书写", "退出全屏", // 全屏按钮双语 data 属性
		"插入图片（base64 内联）",                                           // 工具栏 title（zh——无内置快捷键键零触碰锚）
		"加粗 (Ctrl+B)", "斜体 (Ctrl+I)", "下划线 (Ctrl+U)", "链接 (Ctrl+K)", // U19 title 快捷键提示（zh）
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("渲染缺少要素: %q", want)
		}
	}
	// en 态工具栏 title
	w2 := httptest.NewRecorder()
	dataEN := &templates.ComposeData{Lang: "en", Body: "<p>x</p>"}
	if err := templates.ComposeView(dataEN).Render(context.Background(), w2); err != nil {
		t.Fatalf("en 渲染失败: %v", err)
	}
	if !strings.Contains(w2.Body.String(), "Bold") || !strings.Contains(w2.Body.String(), "Insert image (base64 inline)") {
		t.Fatalf("en 工具栏 title 双语缺失")
	}
	// U19：en 态快捷键提示（四键——Quill 2.0.3 内置绑定 Ctrl+B/I/U/K）
	for _, want := range []string{"Bold (Ctrl+B)", "Italic (Ctrl+I)", "Underline (Ctrl+U)", "Link (Ctrl+K)"} {
		if !strings.Contains(w2.Body.String(), want) {
			t.Fatalf("en 工具栏快捷键提示缺失: %q", want)
		}
	}
}

// TestU17VendorEndpoints vendor 资源端点：quill.js/quill.snow.css 经 staticHandler
// 可达且 MIME 正确（embed 通道锚——CON-001 单二进制承载）。
func TestU17VendorEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{engine: gin.New()}
	for _, tc := range []struct {
		path string
		mime string
		body string
	}{
		{"/static/quill.js", "text/javascript; charset=utf-8", "Quill"},
		{"/static/quill.snow.css", "text/css; charset=utf-8", "ql-"},
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = gin.Params{{Key: "filepath", Value: strings.TrimPrefix(tc.path, "/static")}}
		c.Request = httptest.NewRequest("GET", tc.path, nil)
		s.staticHandler(c)
		if w.Code != 200 {
			t.Fatalf("%s 状态码不符: %d", tc.path, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, tc.mime) {
			t.Fatalf("%s MIME 不符: %q", tc.path, ct)
		}
		if !strings.Contains(w.Body.String(), tc.body) {
			t.Fatalf("%s 内容特征缺失: %q", tc.path, tc.body)
		}
	}
}
