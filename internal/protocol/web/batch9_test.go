// Webmail前端品牌焕新批（δ 批·墨石方向——审计实施批）web 侧测试（计划书 v1.0.0
// 第三章步骤 1~5 验收锚；G2 批准 2026-10-15 16:28:59；样张方向裁决 2026-10-15
// 13:40:34 AGREE）。
// 覆盖：①D-1 墨石令牌迁移（CSS 文件锚——primary 族新值在位+旧蓝值全文件清零+
// 功能色四值零变化锚）②D-2 Geist vendor（@font-face+--font-brand+woff2 文件在位）
// ③D-4 品牌资产（favicon/manifest theme_color+description）④D-3/D-8 品牌区与字标族
// （登录页双视图+错误页+占位首页组件直驱——wordmark/brandline/品牌语）。浏览器视觉
// 走查属干系人实机域（样张即批准实物参照——历批口径）。
package web

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"GRmail/web/templates"
)

// b9Static 读取 web/static 下静态资产源（CWD=包目录——b7AppCSS 同款路径形态）。
func b9Static(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", name))
	if err != nil {
		t.Fatalf("读取 %s: %v", name, err)
	}
	return string(b)
}

// ───────────────────────── D-1：墨石令牌迁移（CSS 文件锚） ─────────────────────────

// TestBatch9D1MonolithTokens D-1：品牌色令牌从 Material 蓝迁移为墨石（亮档 #17181c+
// 暗档对偶反转 #f0f0f2）；旧蓝值全文件清零；danger/success/warning/info 四功能色
// 零变化锚（功能语义豁免红线——计划书 4.2 失败判定②）。
func TestBatch9D1MonolithTokens(t *testing.T) {
	css := b9Static(t, filepath.Join("app.css"))
	// 亮档墨石主色族在位。
	for _, tok := range []string{
		"--primary: #17181c;",
		"--primary-hover: #2a2b32;",
		"--primary-fg: #fafafa;",
		"--primary-soft: rgba(23, 24, 28, 0.08);",
		"--surface-active: rgba(23, 24, 28, 0.12);",
		"--selected: rgba(23, 24, 28, 0.08);",
		"--accent: #17181c;",
	} {
		if !strings.Contains(css, tok) {
			t.Fatalf("D-1 亮档墨石令牌缺失: %s", tok)
		}
	}
	// 暗档对偶反转在位（按钮白底墨字——可用性同等）。
	for _, tok := range []string{
		"--primary: #f0f0f2;",
		"--primary-hover: #ffffff;",
		"--primary-fg: #101113;",
		"--bg: #101113;",
		"--selected: rgba(240, 240, 242, 0.10);",
	} {
		if !strings.Contains(css, tok) {
			t.Fatalf("D-1 暗档对偶令牌缺失: %s", tok)
		}
	}
	// 旧 Material 蓝值全文件清零（品牌色迁移完整性锚）。
	for _, legacy := range []string{
		"#1976d2", "#1565c0", "#e3f2fd", "#64b5f6", "#bbdefb",
		"#90caf9", "#a9d5f9", "#1e3a5f", "#2b4a68",
		"rgba(25, 118, 210", "rgba(144, 202, 249",
	} {
		if strings.Contains(css, legacy) {
			t.Fatalf("D-1 旧 Material 蓝值应全文件清零: %s", legacy)
		}
	}
	// 功能色四值零变化锚（δ 批红线——功能语义豁免）。
	for _, fn := range []string{
		"--danger: #d32f2f;", "--success: #2e7d32;",
		"--warning: #ed6c02;", "--info: #0288d1;",
		"--danger: #f44336;", // 暗档
	} {
		if !strings.Contains(css, fn) {
			t.Fatalf("功能色零变化锚失败（δ 批红线）: %s", fn)
		}
	}
	// D-5：未读点 danger 红借用（全局唯一暖色点缀——样张②批准形态）。
	if !strings.Contains(css, "border-radius: 50%;\n\tbackground: var(--danger);") {
		t.Fatal("D-5 未读点应改用 var(--danger)（样张②批准形态）")
	}
}

// ───────────────────────── D-2：Geist vendor 字标基座 ─────────────────────────

// TestBatch9D2GeistVendor D-2：@font-face 声明+--font-brand 令牌+woff2/OFL 文件在位
// （CON-001 单二进制——vendor embed 形态；零 CDN 外链运行时加载）。
func TestBatch9D2GeistVendor(t *testing.T) {
	css := b9Static(t, filepath.Join("app.css"))
	if !strings.Contains(css, `font-family: "Geist";`) {
		t.Fatal("D-2 @font-face font-family 声明缺失")
	}
	if !strings.Contains(css, "/static/fonts/geist-latin-var.woff2") {
		t.Fatal("D-2 woff2 vendor 引用缺失（CON-001——须本地路径禁 CDN）")
	}
	if strings.Contains(css, "fonts.googleapis.com") || strings.Contains(css, "fonts.gstatic.com") {
		t.Fatal("D-2 运行时 CSS 禁止 CDN 外链字体（CON-001 红线）")
	}
	if !strings.Contains(css, `--font-brand: "Geist", var(--font-sans);`) {
		t.Fatal("D-2 --font-brand 令牌缺失")
	}
	// woff2 与授权文件在位（embed 资产实体）。
	for _, f := range []string{
		filepath.Join("fonts", "geist-latin-var.woff2"),
		filepath.Join("fonts", "OFL.txt"),
	} {
		if _, err := os.Stat(filepath.Join("..", "..", "..", "web", "static", f)); err != nil {
			t.Fatalf("D-2 vendor 资产缺失: %s: %v", f, err)
		}
	}
	// 字标族样式在位（.wordmark+.app-bar-brand 消费——四位一体）。
	if !strings.Contains(css, "font-family: var(--font-brand);") {
		t.Fatal("D-2/D-8 字标族消费缺失（.wordmark/.app-bar-brand）")
	}
	if !strings.Contains(css, "--ls-brand: -0.02em;") {
		t.Fatal("D-2 品牌负字距令牌缺失（样张批准形态）")
	}
}

// ───────────────────────── D-4：品牌资产三联动 ─────────────────────────

// TestBatch9D4BrandAssets D-4：favicon stroke 墨色+manifest theme_color/description
// （theme-color meta 由 batch7 A1 用例承载——适配后新值锚）。
func TestBatch9D4BrandAssets(t *testing.T) {
	fav := b9Static(t, filepath.Join("favicon.svg"))
	if !strings.Contains(fav, "#17181c") {
		t.Fatal("D-4 favicon stroke 应为墨色 #17181c")
	}
	if strings.Contains(fav, "#1976d2") {
		t.Fatal("D-4 favicon 旧蓝值应清零")
	}
	man := b9Static(t, filepath.Join("manifest.webmanifest"))
	if !strings.Contains(man, `"theme_color": "#17181c"`) {
		t.Fatal("D-4 manifest theme_color 应为 #17181c")
	}
	if !strings.Contains(man, `"description": "Self-hosted. Self-owned."`) {
		t.Fatal("D-4/D-7 manifest description 品牌语缺失")
	}
}

// ───────────────────────── D-3/D-8：品牌区与字标族（组件直驱） ─────────────────────────

// TestBatch9D3D8WordmarkFamily D-3：登录页双视图品牌区（wordmark+brandline 品牌语+hr
// ——样张①批准形态）；D-8：错误页/占位首页卡片头字标族四位一体。
func TestBatch9D3D8WordmarkFamily(t *testing.T) {
	// 登录页 admin 视图。
	w := httptest.NewRecorder()
	if err := templates.AdminLoginView(templates.LangZH, "").Render(context.Background(), w); err != nil {
		t.Fatalf("AdminLoginView 渲染: %v", err)
	}
	admin := w.Body.String()
	for _, anchor := range []string{
		`<h1 class="wordmark">GRmail</h1>`,
		`class="brandline"`,
		"自有服务器，自持信箱",
		"<hr>", // templ 序列化 void 元素规范形态（自纠：初版 "<hr/>" 断言锚错误——测试自身缺陷非实现缺陷）
	} {
		if !strings.Contains(admin, anchor) {
			t.Fatalf("D-3 AdminLoginView 品牌区锚缺失: %s", anchor)
		}
	}
	// 登录页 mailbox 视图（同构）。
	w2 := httptest.NewRecorder()
	if err := templates.MailboxLoginView(templates.LangEN, "").Render(context.Background(), w2); err != nil {
		t.Fatalf("MailboxLoginView 渲染: %v", err)
	}
	mailbox := w2.Body.String()
	if !strings.Contains(mailbox, `<h1 class="wordmark">GRmail</h1>`) {
		t.Fatal("D-3 MailboxLoginView 字标锚缺失")
	}
	if !strings.Contains(mailbox, "Self-hosted. Self-owned.") {
		t.Fatal("D-3/D-7 MailboxLoginView 英文品牌语缺失（双语承载）")
	}
	// 错误页字标族（h1 为状态文案——字体族消费）。
	w3 := httptest.NewRecorder()
	if err := templates.ErrorPageView(templates.LangZH, 404, "x").Render(context.Background(), w3); err != nil {
		t.Fatalf("ErrorPageView 渲染: %v", err)
	}
	if !strings.Contains(w3.Body.String(), `<h1 class="wordmark">`) {
		t.Fatal("D-8 ErrorPageView 字标族锚缺失")
	}
	// 占位首页字标族。
	w4 := httptest.NewRecorder()
	if err := templates.HomeView(templates.LangZH, "lbl", "kind", "csrf").Render(context.Background(), w4); err != nil {
		t.Fatalf("HomeView 渲染: %v", err)
	}
	if !strings.Contains(w4.Body.String(), `<h1 class="wordmark">GRmail</h1>`) {
		t.Fatal("D-8 HomeView 字标族锚缺失")
	}
}
