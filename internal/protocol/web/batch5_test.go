// Webmail前端缺陷修复批·批五 web 侧测试（计划书 v1.0.0 第三章步骤 1~12 验收锚；
// G2 批准 2026-10-13 08:42:57 五组候选全 A——E-1-A 外层列表区滚动/E-2-A empty-state
// 组件化/E-3-A 草稿前置+D2 指示「Ctrl+回车发送 直接回车是换行处理」/E-4-A 常驻条+
// JS 兜底/E-5-A 按主体区分入口+C8 两端点 XFO SAMEORIGIN 例外）。
// 覆盖：①B10 五页 main 地标+id ②B8 邮箱列表空态专用键（aggEmptyTitle 错用清零锚）
// ③B11 三表 th scope+sr-only caption ④C2/C4 可访问名（compose 工具栏 aria-label+
// 空 label sr-only+admin 过滤控件）⑤C6/E-2-A tokens 空态组件化 ⑥C8 两端点 XFO 覆盖
// 与全域 DENY 保持 ⑦D2/E-3-A 草稿按钮 DOM 前置+E-5-A 超时落点按主体分流。
// 弱测如实登记：B5/B6 CSS 滚动容器形态与 E-4-A batch-active JS 兜底/C3 菜单方向键
// 与抽屉焦点/D2 回车拦截均为静态资源行为——HTTP 层无断言面，由源码在位+实机冒烟
// 承载（沿批四 C1 先例）。
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"GRmail/internal/storage"
)

// ───────────────────── B10：五页 main 地标 + id ─────────────────────

// TestBatch5B10MainLandmarks B10：settings_hub/twofactor/compose（mailbox 主体三页）
// 与 admin_2fa/unregistered（admin 主体两页）自本批为 main 标签+id="main-content"
// （skip-link 跳转目标生效；批二 G1 实施不完整收尾）。向导页核对结论（步骤 0）：
// Layout 单卡片骨架无侧栏——skip-link/main 语义不适用，不在补齐面。
func TestBatch5B10MainLandmarks(t *testing.T) {
	env := newU9Env(t)
	mbCookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b5a")

	for _, tc := range []struct {
		path   string
		anchor string
	}{
		{"/settings", `id="main-content"`},
		{"/compose", `<main class="main" id="compose-page"`},
	} {
		res := env.get(t, tc.path, mbCookie)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s 状态: %d", tc.path, res.StatusCode)
		}
		if page := bodyOf(t, res); !strings.Contains(page, tc.anchor) {
			t.Fatalf("%s 应含 main 地标锚 %s（B10）", tc.path, tc.anchor)
		}
	}

	// /settings/2fa：TwoFactor 注入环境（batch3Env 复用——u9Env 未注入 2FA 服务为
	// 503 渐进态，测试环境前置自纠）——登录直通会话 GET 断言地标。
	b3 := newBatch3Env(t)
	b3Cookie := b3.b3MailboxLogin(t)
	res2fa := b3.getWithCookie(t, "/settings/2fa", b3Cookie)
	if res2fa.StatusCode != http.StatusOK {
		t.Fatalf("/settings/2fa 状态: %d", res2fa.StatusCode)
	}
	if page := bodyOf(t, res2fa); !strings.Contains(page, `id="main-content"`) {
		t.Fatal("/settings/2fa 应含 main 地标 id（B10）")
	}

	adminCookie := env.u9Session(t, storage.SubjectTypeAdmin, 999, "csrf-b5a2")
	resUnreg := env.get(t, "/admin/mailboxes/unregistered", adminCookie)
	if resUnreg.StatusCode != http.StatusOK {
		t.Fatalf("/admin/mailboxes/unregistered 状态: %d", resUnreg.StatusCode)
	}
	if page := bodyOf(t, resUnreg); !strings.Contains(page, `id="main-content"`) {
		t.Fatal("/admin/mailboxes/unregistered 应含 main 地标 id（B10）")
	}

	// /admin/2fa：AdminTwoFactor 注入环境（batch3Env——u9Env 未注入为 503 渐进态）
	// ——admin 登录直通（未绑定 2FA）取会话后断言地标。
	b3Admin := b3.b3PostLogin(t, "/login", url.Values{"username": {"admin"}, "password": {b3.adminPass}})
	if b3Admin.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin 登录直通应 303: %d", b3Admin.StatusCode)
	}
	b3AdminCk := sessionCookieOf(b3Admin)
	if b3AdminCk == nil {
		t.Fatal("admin 登录直通应签发会话 cookie")
	}
	resAdmin2FA := b3.getWithCookie(t, "/admin/2fa", b3AdminCk.Value)
	if resAdmin2FA.StatusCode != http.StatusOK {
		t.Fatalf("/admin/2fa 状态: %d", resAdmin2FA.StatusCode)
	}
	if page := bodyOf(t, resAdmin2FA); !strings.Contains(page, `id="main-content"`) {
		t.Fatal("/admin/2fa 应含 main 地标 id（B10）")
	}
}

// ───────────────────── B8：邮箱列表空态专用键 ─────────────────────

// TestBatch5B8EmptyStateKey B8①：admin 邮箱管理页空态文案使用专用键
// admin.emptyMailboxes（zh「暂无邮箱（在下方创建第一行开始管理）」）——原错用聚合
// 视图键 admin.aggEmptyTitle（「暂无未注册来信」语义错位）清零锚。
func TestBatch5B8EmptyStateKey(t *testing.T) {
	env := newU9Env(t)
	adminCookie := env.u9Session(t, storage.SubjectTypeAdmin, 999, "csrf-b5b")
	res := env.get(t, "/admin/mailboxes", adminCookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin 页状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "暂无邮箱（在下方创建第一行开始管理）") {
		t.Fatal("邮箱列表空态应使用专用键 admin.emptyMailboxes（B8①）")
	}
	if strings.Contains(page, "暂无未注册来信") {
		t.Fatal("邮箱列表空态不得错用聚合视图键 admin.aggEmptyTitle（B8① 清零锚）")
	}
}

// ───────────── B11：三表 th scope + sr-only caption ─────────────

// TestBatch5B11ScopeCaption B11：admin 邮箱表/聚合视图表与 tokens 表 th 补
// scope="col"+关键数据表 sr-only caption（视觉零变化——读屏表头关联与表用途播报；
// 对照 mail_list.templ 既有形态）。C6/E-2-A：tokens 空态 empty-state 组件
// （原 empty-cell 表格空行形态废止）。
func TestBatch5B11ScopeCaption(t *testing.T) {
	env := newU9Env(t)
	adminCookie := env.u9Session(t, storage.SubjectTypeAdmin, 999, "csrf-b5c")

	res := env.get(t, "/admin/mailboxes", adminCookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin 页状态: %d", res.StatusCode)
	}
	adminPage := bodyOf(t, res)
	if !strings.Contains(adminPage, `<th scope="col">`) || !strings.Contains(adminPage, `<caption class="sr-only">`) {
		t.Fatal("admin 邮箱表应补 th scope+sr-only caption（B11）")
	}

	res2 := env.get(t, "/admin/mailboxes/unregistered", adminCookie)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("聚合视图页状态: %d", res2.StatusCode)
	}
	// 环境前置：新环境无 shadow 邮箱→聚合视图走空态分支（表未渲染）——scope 断言
	// 语义由 admin 主表+tokens 表承载（同一模板形态），此处锚空态+main 地标呈现。
	if page := bodyOf(t, res2); !strings.Contains(page, `id="main-content"`) {
		t.Fatal("聚合视图页应含 main 地标（B10/B11 空态语境）")
	}

	// tokens 页：Tokens 注入环境（u14Env withTokens=true——u9Env 未注入为 503 渐进态）。
	u14 := newU14Env(t, true)
	tkRes := u14Get(t, u14, "/admin/tokens")
	if tkRes.StatusCode != http.StatusOK {
		t.Fatalf("tokens 页状态: %d", tkRes.StatusCode)
	}
	tokensPage := bodyOf(t, tkRes)
	if !strings.Contains(tokensPage, `<th scope="col">`) || !strings.Contains(tokensPage, `<caption class="sr-only">`) {
		t.Fatal("tokens 表应补 th scope+sr-only caption（B11）")
	}
	// C6/E-2-A：空态归一 empty-state 组件（empty-cell 表格行废止锚）
	if !strings.Contains(tokensPage, `<div class="empty-state">`) {
		t.Fatal("tokens 空表应渲染 empty-state 组件（C6/E-2-A）")
	}
	if strings.Contains(tokensPage, `class="empty-cell"`) {
		t.Fatal("tokens 空态不得残留 empty-cell 表格行形态（C6/E-2-A 废止锚）")
	}
}

// u14Get u14Env 环境带 admin 会话 GET（B11 tokens 段环境桥接）。
func u14Get(t *testing.T, e *u14Env, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	req.AddCookie(e.adminCookie(t))
	res, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return res
}

// ───────── C2/C4：可访问名（compose 工具栏+空 label+admin 过滤控件） ─────────

// TestBatch5C2C4AriaLabels C2：compose 主题/附件空 label 补 sr-only 文本+Quill 工具栏
// 控件补 aria-label（抽查加粗/颜色两锚——title 保留）；C4：admin 状态筛选/地址过滤/
// 2FA 强制策略地址三控件补 aria-label。
func TestBatch5C2C4AriaLabels(t *testing.T) {
	env := newU9Env(t)
	mbCookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b5d")

	res := env.get(t, "/compose", mbCookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("compose 页状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, `<span class="sr-only">主题</span>`) {
		t.Fatal("主题输入应有 sr-only label 文本（C2）")
	}
	// A-8（前端报告批——G2 批准 2026-10-16 10:51）：附件控件经 sr-only label 改为
	// file-pick 自定义形态（可见双语按钮+文件名回显）——读屏控件名经 aria-label
	// 承载（键值意图锚「附件（可多选）」保持——读屏可达等价；批准行为变化的
	// 机械适配，沿 u13 mx/batch7 色值锚适配先例；形态披露落本批 CHANGE5 专章）。
	if !strings.Contains(page, `aria-label="附件（可多选）"`) {
		t.Fatal("附件输入应有 aria-label 控件名（C2 键值含多选提示——A-8 形态适配）")
	}
	if !strings.Contains(page, `aria-label="加粗`) {
		t.Fatal("工具栏控件应补 aria-label（C2 抽查——加粗；键值含 Ctrl+B 后缀为前缀匹配）")
	}
	if !strings.Contains(page, `aria-label="文字颜色"`) && !strings.Contains(page, `aria-label="颜色"`) {
		t.Fatal("工具栏颜色选择应补 aria-label（C2 抽查）")
	}

	adminCookie := env.u9Session(t, storage.SubjectTypeAdmin, 999, "csrf-b5d2")
	res2 := env.get(t, "/admin/mailboxes", adminCookie)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("admin 页状态: %d", res2.StatusCode)
	}
	adminPage := bodyOf(t, res2)
	for _, label := range []string{`aria-label="按状态筛选"`, `aria-label="按地址筛选"`, `aria-label="邮箱地址"`} {
		if !strings.Contains(adminPage, label) {
			t.Fatalf("admin 过滤控件应补 %s（C4）", label)
		}
	}
}

// ───────── C8：两端点 XFO 覆盖与全域 DENY 保持 ─────────

// TestBatch5C8XFOOverride C8（G2 例外修订 2026-10-13 08:42:57）：/mails/{id}/body
// 成功响应 XFO=SAMEORIGIN（正文 iframe 同源消费——旧浏览器兼容收口）；全域其余端点
// （/login 200）与附件 404 错误路径 XFO=DENY 保持（B-S 批 F2 修订面边界锚）。
func TestBatch5C8XFOOverride(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b5e")

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
	sum := sha256.Sum256([]byte("b5-c8-body"))
	blobKey := hex.EncodeToString(sum[:]) // BlobStore key 校验=64hex（SHA-256 形态）
	raw := "Subject: b5-c8\r\nFrom: from@test.local\r\nTo: to@test.local\r\nDate: " +
		time.Now().UTC().Format(time.RFC1123Z) + "\r\n\r\nC8 正文锚"
	if err := env.srv.blobs.Write(ctx, blobKey, []byte(raw)); err != nil {
		t.Fatalf("写 blob: %v", err)
	}
	msgID, err := env.srv.messages.StoreAppend(ctx, env.mailbox.ID, inboxID, &storage.AppendMeta{
		Message: storage.MessageMeta{
			MessageID: "b5-c8", BlobKey: blobKey, RawSize: int64(len(raw)),
			Subject: "C8 锚", FromAddr: "from@test.local", ToAddrs: `["to@test.local"]`,
			BodyCache: "C8 正文锚", SentAt: time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("入邮件: %v", err)
	}

	// 正文端点成功路径：XFO 覆盖 SAMEORIGIN（C8 核心）
	res := env.get(t, fmt.Sprintf("/mails/%d/body", msgID), cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("正文端点状态: %d", res.StatusCode)
	}
	if got := res.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("正文端点 XFO 应 SAMEORIGIN（C8）: %q", got)
	}

	// 全域保持：公开页 200 中间件头 DENY（F2 修订面边界）
	res2 := env.get(t, "/login", "")
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("登录页状态: %d", res2.StatusCode)
	}
	if got := res2.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("全域其余端点 XFO 应保持 DENY（C8 边界锚）: %q", got)
	}

	// 附件 404 错误路径：无覆盖（handler 覆盖仅成功路径）——DENY 保持
	res3 := env.get(t, "/attachments/99999", cookie)
	if res3.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在附件应 404: %d", res3.StatusCode)
	}
	if got := res3.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("附件错误路径 XFO 应保持 DENY（C8 边界锚）: %q", got)
	}
}

// ───────── D2/E-3-A 草稿前置 + E-5-A 超时落点分流 ─────────

// TestBatch5D2OrderAndE5Redirect D2/E-3-A：compose 动作栏 save_draft 按钮 DOM 序
// 前置（回车隐式提交兜底命中草稿——视觉主位由 CSS order 恢复）；E-5-A：会话失效
// 落点按 grmail_login_kind 记忆分流（mailbox→/webmail/login、无记忆/未知→/login
// 契约缺省保持）。
func TestBatch5D2OrderAndE5Redirect(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b5f")

	res := env.get(t, "/compose", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("compose 页状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	draftIdx := strings.Index(page, `value="save_draft"`)
	sendIdx := strings.Index(page, `value="send"`)
	if draftIdx < 0 || sendIdx < 0 {
		t.Fatal("compose 动作栏两按钮应在位（D2 前置断言前提）")
	}
	if draftIdx > sendIdx {
		t.Fatal("save_draft 应 DOM 序前置（D2/E-3-A——回车兜底命中草稿）")
	}

	// E-5-A：302 直测（noFollow——env.get 默认客户端跟随重定向，测试形态自纠）。
	// 无记忆 cookie——契约缺省 /login 保持。
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/mails", nil)
	res2, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("无会话 GET: %v", err)
	}
	if res2.StatusCode != http.StatusFound {
		t.Fatalf("无会话 /mails 应 302: %d", res2.StatusCode)
	}
	if loc := res2.Header.Get("Location"); loc != "/login" {
		t.Fatalf("无记忆场景落点应保持 /login（E-5-A 缺省锚）: %q", loc)
	}
	// E-5-A：mailbox 记忆——分流 /webmail/login
	req2, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/mails", nil)
	req2.AddCookie(&http.Cookie{Name: loginKindCookie, Value: "mailbox"})
	res3, err := noFollow.Do(req2)
	if err != nil {
		t.Fatalf("mailbox 记忆 GET: %v", err)
	}
	if res3.StatusCode != http.StatusFound {
		t.Fatalf("mailbox 记忆 /mails 应 302: %d", res3.StatusCode)
	}
	if loc := res3.Header.Get("Location"); loc != "/webmail/login" {
		t.Fatalf("mailbox 记忆落点应 /webmail/login（E-5-A）: %q", loc)
	}
	_ = url.Values{} // 保持 url 导入（b3PostLogin 形态族一致性）
}
