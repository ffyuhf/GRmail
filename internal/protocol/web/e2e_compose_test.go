// 编辑器收尾与e2e批次 web 侧测试（D8 处置池 #10/#13/#15 收口——计划书 v1.0.0）。
// 覆盖：①E-C HTTP 级 e2e 富文本写信全链（渲染→HTML 态提交→MIME multipart/alternative
// 递增序+MIME-Version 断言→草稿 HTML 态回填——u17_test 头注预言的「发送链 e2e 归下次
// 触碰批次补强」义务兑现）；②E-B 表格按钮渲染锚（双语 title+工具栏按钮类）；
// ③E-A ⌘ 自适应脚本锚（grmailAdaptShortcutTitles 函数存在+title Ctrl 初值锚——
// u17/u22 既有断言零触碰回归）。
// 依据：编辑器收尾与e2e_计划 v1.0.0（G2 批准 2026-10-03 07:34:18）；S4-W Q1 候选 B
// （零依赖 HTTP 级——编辑器 JS 交互面归 TC-013 浏览器实机）；SRS FR-013/NFR-015；
// rfc2046 §5.1.4（alternative 递增序——plain 派生在前/html 原文在后）。
// 修改历史：
//
//	2026-10-03 07:40:00 | 新建 | 编辑器收尾与e2e批次（计划书步骤 4/5，G2 批准 2026-10-03 07:34:18）
package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// TestE2EComposeRichTextFlow E-C：富文本写信 HTTP 级全链 e2e（S4-W Q1 候选 B——
// httptest 真实 Server：渲染→HTML 态提交→MIME 产物断言→草稿 HTML 态回填闭环）。
func TestE2EComposeRichTextFlow(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-e2e")

	// ①写信页渲染：编辑器集成锚+E-B 表格按钮+E-A ⌘ 自适应脚本锚（zh 缺省态）
	res := env.get(t, "/compose", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("写信页状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	for _, want := range []string{
		`id="compose-toolbar"`,
		"ql-code-block",             // 既有（#13 代码块半面——U22 已承载实证锚）
		`class="ql-table"`,          // E-B：表格按钮（D8#13 新增半面）
		"插入表格 (2×2)",                // E-B：表格 title（zh）
		"grmailAdaptShortcutTitles", // E-A：⌘ 记法自适应函数（D8#10）
		"加粗 (Ctrl+B)",               // E-A：title Ctrl 初值锚（服务端渲染断言锚零触碰）
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("渲染缺少要素: %q", want)
		}
	}

	// ②HTML 态提交→stub 捕获 MIME：multipart/alternative 递增序（rfc2046 §5.1.4——
	// text/plain 派生 part 在前+text/html 原文 part 在后）+MIME-Version 头（F-L6）
	htmlBody := "<p>富文本<strong>加粗</strong>正文</p>"
	res = env.postForm(t, "/compose", cookie, "csrf-e2e", map[string][]string{
		"action": {"send"}, "to": {"ext@x.io"}, "subject": {"e2e富文本"},
		"body": {htmlBody},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("发送应 303: %d body=%s", res.StatusCode, bodyOf(t, res))
	}
	_ = bodyOf(t, res)
	if len(env.submit.Captured) != 1 {
		t.Fatalf("提交管道应捕获 1 次: %d", len(env.submit.Captured))
	}
	raw := string(env.submit.Raws[0])
	if !strings.Contains(raw, "MIME-Version: 1.0") {
		t.Fatalf("MIME 应含版本头（F-L6 合规形态）: %s", raw)
	}
	pi := strings.Index(raw, "text/plain")
	hi := strings.Index(raw, "text/html")
	if pi < 0 || hi < 0 || pi > hi {
		t.Fatalf("multipart/alternative 递增序应 plain 在前 html 在后: pi=%d hi=%d", pi, hi)
	}
	// plain 派生内容（htmlToPlain 剥标签产物）与 html 原文双 part 共存
	if !strings.Contains(raw, "加粗") {
		t.Fatalf("派生 plain part 应含正文文字: %s", raw)
	}
	if !strings.Contains(raw, "<strong>") {
		t.Fatalf("html 原文 part 应保留标签: %s", raw)
	}

	// ③草稿 HTML 态闭环：保存→Drafts 落位→回填（fillFromDraft HTML 优先——U17 既有）
	htmlDraft := "<p>草稿<strong>加粗态</strong></p>"
	res = env.postForm(t, "/compose", cookie, "csrf-e2e", map[string][]string{
		"action": {"save_draft"}, "to": {"draft@ext.io"}, "subject": {"e2e草稿"},
		"body": {htmlDraft},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("存草稿应 303: %d", res.StatusCode)
	}
	_ = bodyOf(t, res)
	items, total, err := env.db.PageList(context.Background(), storage.ListQuery{
		MailboxID: env.mailbox.ID, FolderID: env.draftsID(t, env.mailbox.ID), Limit: 5})
	if err != nil || total != 1 {
		t.Fatalf("草稿应 1 封: total=%d err=%v", total, err)
	}
	draftID := items[0].ID
	draftPage := bodyOf(t, env.get(t, "/compose?draft="+fmt.Sprint(draftID), cookie))
	if !strings.Contains(draftPage, "加粗态") {
		t.Fatalf("草稿回填应含 HTML 态正文文字")
	}
}

// TestE2EEditorToolbarEN E-B en 态表格 title（双语锚独立直驱——组件渲染，沿 u17 先例）。
func TestE2EEditorToolbarEN(t *testing.T) {
	w := httptest.NewRecorder()
	data := &templates.ComposeData{Lang: "en", Body: "<p>x</p>"}
	if err := templates.ComposeView(data).Render(context.Background(), w); err != nil {
		t.Fatalf("en 渲染失败: %v", err)
	}
	s := w.Body.String()
	for _, want := range []string{"Insert table (2×2)", "Code block", "Bold (Ctrl+B)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("en 工具栏要素缺失: %q", want)
		}
	}
}
