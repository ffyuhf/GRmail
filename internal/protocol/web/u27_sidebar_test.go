// 侧栏交互缺陷修复批次集成测试（计划书阶段 5；NFR-015 全离线：httptest+临时 SQLite，
// 复用 u9Env 基建——沿 u12_web_test.go 先例）。
// 覆盖：D2 筛选链接 HTMX 局部更新化（hx-get/hx-target 属性）、D5 系统文件夹名 zh/en
// 本地化（folderDisplayName——zh 中文呈现+en 规范名等价）、D3 设置页全站侧栏渲染
// （.layout+.sidebar 结构——汉堡按钮 checkbox-hack 联动目标存在性锚）。
// 修改历史：
//
//	2026-10-05 19:05:00 | 新建 | 侧栏交互缺陷修复批次（G2 批准 2026-10-05 18:41:43）
package web

import (
	"net/http"
	"strings"
	"testing"

	"GRmail/internal/storage"
)

// TestSidebarUnreadFilterHTMX D2 回归锚：「只看未读」筛选链接必须为 hx-get 局部更新
// 形态（原裸 href 整页导航至片段端点 /mails——无布局无 htmx 运行时致显示错误与后续
// 交互失效）；href 保留作降级锚（noscript/中键语义）。
func TestSidebarUnreadFilterHTMX(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf1")

	res := env.get(t, "/", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET / 期望 200 得 %d", res.StatusCode)
	}
	body := bodyOf(t, res)
	if !strings.Contains(body, `hx-get="/mails?`) || !strings.Contains(body, "unread=1") {
		t.Error("「只看未读」应为 hx-get 局部更新链接（D2——禁裸 href 整页导航）")
	}
	if !strings.Contains(body, `hx-target="#mail-list"`) {
		t.Error("筛选链接应指定 hx-target=\"#mail-list\"（片段替换目标）")
	}
}

// TestSidebarFolderLocalization D5 回归锚：zh 态系统文件夹名本地化（收件箱/已发送——
// folders.name 英文规范名不外露）；en 态规范名等价呈现（INBOX/Sent）。
func TestSidebarFolderLocalization(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf1")

	res := env.get(t, "/", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET / 期望 200 得 %d", res.StatusCode)
	}
	body := bodyOf(t, res)
	for _, want := range []string{"收件箱", "已发送"} {
		if !strings.Contains(body, want) {
			t.Errorf("zh 态侧栏应含本地化文件夹名 %q", want)
		}
	}
	if strings.Contains(body, ">INBOX<") || strings.Contains(body, ">Sent<") {
		t.Error("zh 态侧栏不应直渲英文规范名（D5——folderDisplayName 按 kind 映射）")
	}

	// en 态（cookie lang=en）：规范名等价（Tr 键 en 侧=INBOX/Sent——双语义保持）。
	// 双 cookie 直构请求（会话 cookie+语言 cookie 分立 AddCookie——get() 单 cookie 形态不适用）
	reqEN, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/", nil)
	reqEN.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	reqEN.AddCookie(&http.Cookie{Name: "lang", Value: "en"})
	resEN, err := env.ts.Client().Do(reqEN)
	if err != nil {
		t.Fatalf("GET / (en): %v", err)
	}
	defer resEN.Body.Close()
	if resEN.StatusCode != http.StatusOK {
		t.Fatalf("GET / (en) 期望 200 得 %d", resEN.StatusCode)
	}
	bodyEN := bodyOf(t, resEN)
	if !strings.Contains(bodyEN, ">INBOX<") || !strings.Contains(bodyEN, ">Sent<") {
		t.Error("en 态侧栏应含规范名 INBOX/Sent（folder.* 键 en 侧）")
	}
}

// TestSettingsSidebarRendered D3 回归锚：设置页（/settings 枢纽）应渲染 .layout 容器与
// sidebar 侧栏——汉堡按钮 checkbox-hack 联动选择器（#nav-toggle…~ .layout .sidebar）
// 的目标存在性（B 形态：全站侧栏导航，设置页汉堡可展开侧栏返回邮箱）。
func TestSettingsSidebarRendered(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf1")

	res := env.get(t, "/settings", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings 期望 200 得 %d", res.StatusCode)
	}
	body := bodyOf(t, res)
	if !strings.Contains(body, `class="layout"`) {
		t.Error("设置页应含 .layout 容器（D3——AppFrame B 形态承载）")
	}
	if !strings.Contains(body, `class="sidebar"`) {
		t.Error("设置页应渲染侧栏（D3 B 形态——汉堡按钮联动目标）")
	}
	if !strings.Contains(body, "收件箱") {
		t.Error("设置页侧栏应含本地化文件夹名（sidebarDataFor 装配链）")
	}
}
