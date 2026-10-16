// 前端报告缺陷修复与向导MX子域批 web 侧测试（计划书 v1.0.0 第三章步骤 1~3 验收锚）。
// A-3 时间列零值占位「—」（HTTP 层——StoreAppend 零值 SentAt 直落→列表渲染占位）；
// B-1 向导 MX 建议 smtp. 子域（包内直测——沿 batch6 C5 buildDNSRecords 先例）；
// A-1/A-2/A-4/A-5/A-6/A-7/A-8/A-9 静态结构锚（CSS/JS/templ 源文件断言——沿 batch9
// vendor 文件断言先例；JS 交互行为属浏览器域，HTTP 层断言注入/结构锚承载）。
// 依据：前端报告缺陷修复与向导MX子域_计划_20261016_02-45-00_v1.0.0（G2 批准
// 2026-10-16 10:51——INV-26 三要素：E-1-A/E-2-A/E-3-A/E-4-B/E-5-A/E-6-A/E-7-A/E-8-B）。
package web

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// TestBatch11A3TimePlaceholder A-3（E-3-A——G2 2026-10-16 10:51）：Date 头缺失
// （SentAt 零值→NULL 落库）邮件的列表时间列呈「—」占位（原空单元格——第三方报告
// P0-2 呈现面；对齐详情页 fmtDateTime 零值「—」既有形态）。
func TestBatch11A3TimePlaceholder(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b11")

	inboxID := int64(0)
	folders, ferr := env.fds.List(ctx, env.mailbox.ID)
	if ferr != nil {
		t.Fatalf("查询文件夹: %v", ferr)
	}
	for _, f := range folders {
		if f.Kind == storage.FolderKindInbox {
			inboxID = f.ID
			break
		}
	}
	if inboxID == 0 {
		t.Fatal("收件箱文件夹缺失")
	}
	// 零值 SentAt（Date 头缺失语义——MessageMeta.SentAt 零值映射 NULL 落库）。
	if _, err := env.srv.messages.StoreAppend(ctx, env.mailbox.ID, inboxID, &storage.AppendMeta{
		Message: storage.MessageMeta{
			MessageID: "b11-nodate", BlobKey: "b11key-nodate", RawSize: 60,
			Subject: "无Date占位锚", FromAddr: "from@test.local", ToAddrs: `["to@test.local"]`,
			BodyCache: "正文",
		},
	}); err != nil {
		t.Fatalf("入零值 SentAt 邮件: %v", err)
	}
	res := env.get(t, "/mails?page=1&pagesize=15", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("列表状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "无Date占位锚") {
		t.Fatal("测试邮件应出现在列表")
	}
	if !strings.Contains(page, "—") {
		t.Fatal("零值 SentAt 时间列应呈「—」占位（A-3/E-3-A——原空单元格收口）")
	}
}

// TestBatch11B1MXSubdomain B-1（E-7-A）：向导 MX 建议值为 smtp. 连接子域形态
// （`10 smtp.<主域>`——与策略通配 `*.<主域>` 匹配一致化；裸域不匹配 rfc8461 §4.1）。
func TestBatch11B1MXSubdomain(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Domain = "x.io"
	recs := buildDNSRecords(cfg, "zh")
	found := false
	for _, r := range recs {
		if r.Type == "MX" {
			found = true
			if r.Name != "x.io" || r.Value != "10 smtp.x.io" {
				t.Fatalf("B-1 MX 建议应为 smtp. 子域形态（实际 Name=%q Value=%q）", r.Name, r.Value)
			}
		}
	}
	if !found {
		t.Fatal("MX 建议行缺失")
	}
}

// TestBatch11StaticAnchors 批次一静态结构锚（A-1/A-2/A-4~A-9——源文件断言；
// JS 行为属浏览器域，结构/注入锚承载沿历批口径）。
func TestBatch11StaticAnchors(t *testing.T) {
	readFile := func(rel string) string {
		b, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("读 %s: %v", rel, err)
		}
		return string(b)
	}
	css := readFile("../../../web/static/app.css")
	grjs := readFile("../../../web/static/grmail.js")
	cpjs := readFile("../../../web/static/compose.js")
	templ := readFile("../../../web/templates/compose.templ")

	// A-2（E-2-A）：管理员表首列显式声明+操作列 18rem。
	if !strings.Contains(css, `table.mails.admin-mailboxes th:nth-child(1) { width: auto; min-width: 14rem; }`) {
		t.Fatal("A-2 首列 min-width 声明缺失")
	}
	if !strings.Contains(css, `table.mails.admin-mailboxes th:nth-child(5) { width: 18rem;`) {
		t.Fatal("A-2 操作列 18rem 收窄缺失")
	}
	// A-5（E-5-A）：侧栏 border-box（收起残留 16px 收口）。
	if !strings.Contains(css, "A-5（前端报告批 E-5-A") || !strings.Contains(css, "box-sizing: border-box;") {
		t.Fatal("A-5 sidebar border-box 缺失")
	}
	// A-6：批量条目标下拉 :has 联动。
	if !strings.Contains(css, `:has(select[name="action"] option[value="move"]:checked)) select[name="target"] { display: none; }`) {
		t.Fatal("A-6 :has 联动规则缺失")
	}
	// A-7：移动端触控补齐（44px+16px 字号）。
	if !strings.Contains(css, "min-height: var(--touch-min); font-size: 16px;") {
		t.Fatal("A-7 移动端输入 44px+16px 提升档缺失")
	}
	// A-9（E-6-A）：origin/位移收敛/悬停门控。
	if !strings.Contains(css, "transform-origin: top right;") {
		t.Fatal("A-9 菜单 transform-origin 缺失")
	}
	if !strings.Contains(css, "transform: translateX(16px);") {
		t.Fatal("A-9 进入位移 16px 收敛缺失")
	}
	if hoverN := strings.Count(css, "@media (hover: hover)"); hoverN < 30 {
		t.Fatalf("A-9 悬停门控覆盖不足（实际 %d 处，期望 ≥30）", hoverN)
	}
	// A-4（E-4-B）：侧栏高亮 afterSwap 同步。
	if !strings.Contains(grjs, "grmailSyncSidebarActive") || !strings.Contains(grjs, "htmx:afterSwap") {
		t.Fatal("A-4 侧栏同步逻辑缺失（grmail.js）")
	}
	// A-1（E-1-A）：action 记录+隐藏域承载（B10 禁用保持）。
	if !strings.Contains(cpjs, "grmailSubmitAction") || !strings.Contains(cpjs, "h.name = 'action';") {
		t.Fatal("A-1 action 隐藏域承载逻辑缺失（compose.js）")
	}
	if !strings.Contains(cpjs, "btns[i].disabled = true;") {
		t.Fatal("A-1 B10 防重复提交防线应保持（仅承载形态修正）")
	}
	// A-8：sr-only 首字段+附件自定义控件。
	if !strings.Contains(templ, `compose.attachBrowse`) || !strings.Contains(templ, `class="file-pick"`) {
		t.Fatal("A-8 附件自定义控件缺失（compose.templ）")
	}
	if !strings.Contains(templ, `data-files-fmt=`) {
		t.Fatal("A-8 filesFmt 注入缺失（compose.templ main data-*）")
	}
}
