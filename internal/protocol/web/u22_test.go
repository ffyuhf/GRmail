// U22 富文本高级特性 web 侧测试（NFR-015 全离线——组件渲染直驱）。
// 覆盖：①工具栏八组内置控件渲染断言（color/background 色板+size/font 档位下拉+
// align×4/indent×2/undo/redo——Quill 2.0.3 toolbar/uploader 源码双源核对形态）
// ②双语 title（zh/en 两态）③图片统一压缩注入锚（uploader.handler 一处覆盖三路径
// ——选择/粘贴/拖放；常量 1920/0.85 与纯函数名）④undo/redo 经 history 模块 handler
// 桥接锚（源码核对无 ql-undo 内置注册）。
// 依据：U22 计划书 v1.0.0 步骤 4/1.5⑤（S3-W 候选 B 裁决 2026-09-27 10:36:05）；
// 契约 v1.13.0 零改动（3.2 /compose 注记语义不变）；U19 登记项③收口链。
// 浏览器行为域（压缩实际重采样/色板交互）归部署批次实机（沿 TC-013 既有口径）。
// 修改历史：
//
//	2026-09-27 11:05:00 | 新建 | U22 富文本高级特性（计划书步骤 4，G2 批准 2026-09-27 10:38:20）
package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"GRmail/web/templates"
)

// TestU22ToolbarControlsRender U22 八组控件渲染断言：类名+色板 option+档位文案+
// 双语 title+压缩注入锚+history 桥接锚+既有按钮零回归。
func TestU22ToolbarControlsRender(t *testing.T) {
	w := httptest.NewRecorder()
	data := &templates.ComposeData{
		Lang: "zh", IsAdmin: false, CSRF: "csrf-token-u22",
		To: "to@x.com", Subject: "u22", Body: "<p>初始</p>",
	}
	if err := templates.ComposeView(data).Render(context.Background(), w); err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	s := w.Body.String()
	// 八组新控件类名（源码核对形态：select.ql-color/ql-background/ql-size/ql-font；
	// button.ql-align×4 值集 ""/center/right/justify；button.ql-indent±1；ql-undo/ql-redo）
	for _, want := range []string{
		`class="ql-color"`, `class="ql-background"`, `class="ql-size"`, `class="ql-font"`,
		`class="ql-align" value=""`, `class="ql-align" value="center"`,
		`class="ql-align" value="right"`, `class="ql-align" value="justify"`,
		`class="ql-indent" value="-1"`, `class="ql-indent" value="+1"`,
		`class="ql-undo"`, `class="ql-redo"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("渲染缺少控件: %q", want)
		}
	}
	// 色板 option（清色空值+代表色——12 色板抽两色锚）
	for _, want := range []string{
		`<option value=""></option>`, `value="#dc2626"`, `value="#2563eb"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("色板 option 缺失: %q", want)
		}
	}
	// size/font 档位文案（zh——whitelist 源码核对：small/large/huge+serif/monospace）
	for _, want := range []string{
		`value="small">小<`, `value="large">大<`, `value="huge">特大<`,
		`value="serif">衬线<`, `value="monospace">等宽<`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("档位 option 文案缺失: %q", want)
		}
	}
	// 双语 title（zh 代表键——全量 19 新键由 en 态与键表承载）
	for _, want := range []string{
		"文字颜色", "背景色", "字号", "字体",
		"左对齐", "居中对齐", "右对齐", "两端对齐",
		"减少缩进", "增加缩进", "撤销 (Ctrl+Z)", "重做 (Ctrl+Y)",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("zh title 缺失: %q", want)
		}
	}
	// 压缩注入锚：data-* 注入（D8#11——config 承载后常量字面量废止，断言面随
	// 承载形态更新：缺省档经 applyEditorConf 渲染为 data 属性）+纯函数+uploader
	// 一处接线+mimetypes 扩展（svg 排除）+gif 跳过压缩（D8#14）
	for _, want := range []string{
		`data-img-max-edge="1920"`, `data-jpeg-quality="0.85"`,
		"file.type === 'image/gif'",
		"grmailCompressImage", "grmailUploaderHandler", "grmailReadAsDataURL",
		"uploader:", `'image/png'`, `'image/webp'`, "createImageBitmap",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("压缩注入锚缺失: %q", want)
		}
	}
	// undo/redo history 桥接锚（源码核对无 ql-undo 内置注册——handler 两行桥接）
	for _, want := range []string{"history.undo()", "history.redo()"} {
		if !strings.Contains(s, want) {
			t.Fatalf("history 桥接锚缺失: %q", want)
		}
	}
	// 既有控件零回归锚（U17 十二按钮代表+U19 快捷键 title 保持）
	for _, want := range []string{"ql-bold", "ql-header", "ql-image", "ql-clean", "加粗 (Ctrl+B)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("既有控件回归缺失: %q", want)
		}
	}
	// U17 自定义 image handler 移除锚（收敛至默认路径→uploader 统一压缩——源码语义）
	if strings.Contains(s, "grmailImageHandler") {
		t.Fatalf("U17 手写 image handler 应已移除（默认路径经 uploader.upload 收敛）")
	}
}

// TestU22ToolbarControlsRenderEN en 态代表键双语断言。
func TestU22ToolbarControlsRenderEN(t *testing.T) {
	w := httptest.NewRecorder()
	data := &templates.ComposeData{Lang: "en", Body: "<p>x</p>"}
	if err := templates.ComposeView(data).Render(context.Background(), w); err != nil {
		t.Fatalf("en 渲染失败: %v", err)
	}
	s := w.Body.String()
	for _, want := range []string{
		"Font size", "Text color", "Background color", "Font",
		"Align left", "Align center", "Align right", "Justify",
		"Decrease indent", "Increase indent", "Undo (Ctrl+Z)", "Redo (Ctrl+Y)",
		`value="small">Small<`, `value="serif">Serif<`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("en 态要素缺失: %q", want)
		}
	}
}
