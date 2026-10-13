// Webmail前端缺陷修复批·批四 web 侧测试（计划书 v1.0.0 第三章步骤 1~5 验收锚；
// G2 批准 2026-10-13 04:27:33 两组候选全 A——E-1-A 钳制末页/E-2-A 附件族全并入）。
// 覆盖：①B3/E-1-A 越界页码钳制末页（原空集误报「此文件夹暂无邮件」收口）+B1
// aria-current 条件输出（字面量 {page false} 清零锚）+B4 搜索表单 hx-push-url 锚
// ②B2 未读筛选下 pagesize 链接保持 unread 参数 ③B9 四族错误双态呈现（adminsettings
// 403 整页/batch 400/CSRF 403/附件 404——E-2-A 附件族并入锚；Bearer 401 纯状态码
// 红线由 u14_test 既有回归承载）④B13 顶栏标签 Tr 化（zh 零变化+en 呈现锚）⑤B14
// 用户侧 2FA 二维码 alt Tr 化（复用 twofactor.qrAlt 键）。
// C1（详情返回 a 化）：href 降级锚由模板编译保证，深链整页可达性归实机冒烟（HTTP
// 层弱测如实登记——列表页局部更新行为由既有 u9 回归承载）。
package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"GRmail/internal/storage"
)

// ───────────────────────── B3/E-1-A：越界钳制 + B1/B4 渲染锚 ─────────────────────────

// TestBatch4B3ClampAndListAnchors B3/E-1-A（G2 裁决 2026-10-13 04:27:33）：page=999
// 越界时服务端钳制末页重查——呈现末页邮件内容（含主题），不再误报「此文件夹暂无
// 邮件」；顺带锚 B1（当前每页条数 aria-current="page" 有效输出、字面量 {page false}
// 清零）与 B4（搜索表单 hx-push-url 在位）。
func TestBatch4B3ClampAndListAnchors(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b4a")

	// 入两封邮件（StoreAppend 直落收件箱——blob 不读仅占位，列表渲染不触 blob）
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
	for i, subj := range []string{"批四钳制测试A", "批四钳制测试B"} {
		if _, err := env.srv.messages.StoreAppend(ctx, env.mailbox.ID, inboxID, &storage.AppendMeta{
			Message: storage.MessageMeta{
				MessageID: "b4-" + subj, BlobKey: "b4key" + subj, RawSize: 100,
				Subject: subj, FromAddr: "from@test.local", ToAddrs: `["to@test.local"]`,
				BodyCache: "正文", SentAt: time.Now(),
			},
		}); err != nil {
			t.Fatalf("入第 %d 封: %v", i, err)
		}
	}

	// 越界页码（URL page=999 远超单页数据）：应钳制呈现末页内容
	res := env.get(t, "/mails?page=999&pagesize=15", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("越界页码状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if strings.Contains(page, "此文件夹暂无邮件") {
		t.Fatal("越界页码不得误报空文件夹（B3/E-1-A 钳制收口锚）")
	}
	if !strings.Contains(page, "批四钳制测试A") {
		t.Fatal("越界页码应钳制呈现末页邮件内容（E-1-A）")
	}

	// B1：当前每页条数（15=默认）有效 aria-current；字面量 {page false} 清零
	if !strings.Contains(page, `aria-current="page"`) {
		t.Fatal("当前每页条数应输出有效 aria-current=\"page\"（B1）")
	}
	if strings.Contains(page, "{page false}") {
		t.Fatal("不得残留 aria-current 字面量 {page false}（B1 收口锚）")
	}

	// B4：搜索表单携带 hx-push-url（批一 D5-A 第十锚）
	if !strings.Contains(page, `hx-push-url`) || !strings.Contains(page, `/search`) {
		t.Fatal("搜索表单应携带 hx-push-url（B4——刷新/分享保持结果）")
	}
}

// ───────────────────────── B2：pagesize 链接保持未读筛选 ─────────────────────────

// TestBatch4B2PagesizeKeepsUnread B2：未读筛选态（unread=1）下每页条数切换链接
// 应保留 unread 参数（原三分支均丢失回全量；与翻页链接 pageHref 同语义对齐）。
// 前置数据：一封未读邮件（StoreAppend 标志零值=未读——unread 筛选命中非空渲染分页区；
// 首版设计缺陷自纠：空邮箱走空态分支无分页区，断言形态错误非实现缺陷）。
func TestBatch4B2PagesizeKeepsUnread(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b4b")
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
	if _, err := env.srv.messages.StoreAppend(ctx, env.mailbox.ID, inboxID, &storage.AppendMeta{
		Message: storage.MessageMeta{
			MessageID: "b4-unread", BlobKey: "b4key-unread", RawSize: 80,
			Subject: "B2未读锚", FromAddr: "from@test.local", ToAddrs: `["to@test.local"]`,
			BodyCache: "正文", SentAt: time.Now(),
		},
	}); err != nil {
		t.Fatalf("入未读邮件: %v", err)
	}
	res := env.get(t, "/mails?unread=1&pagesize=15", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("未读筛选态状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "B2未读锚") {
		t.Fatal("未读邮件应在筛选态呈现（环境前置自检锚）")
	}
	// 属性中 & 经 templ 转义为 &（needle 以拼接构造规避编辑器实体解码）——
	// 非当前档（25）链接应含 unread=1（B2 收口锚；首跑失败根因=needle 传输被实体
	// 解码为单 &——实现经诊断输出证实正确，断言字符串修正非断言语义改写）
	if !strings.Contains(page, "pagesize=25&"+"amp;unread=1") {
		t.Fatalf("每页条数链接应保留未读筛选参数（B2）: %s", page[:min(300, len(page))])
	}
}

// ───────────────────────── B9：四族错误双态呈现 ─────────────────────────

// TestBatch4B9ErrorFamily B9：四族空体错误统一双态呈现（批一 A4 设施复用）——
// ①adminsettings 403（mailbox 主体误入管理端——adminGuard 复用整页）②batch 400
// （空 ids——fragError 整页分支）③CSRF 403（token 失配——fragError，文案模糊化）
// ④附件 404（E-2-A 附件族并入——人直访得可读错误页）。状态码全部保持。
func TestBatch4B9ErrorFamily(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b4c")

	// ①mailbox 主体访问 /admin/settings：403 错误整页（原空体）
	res := env.get(t, "/admin/settings", cookie)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("admin 设置页应 403: %d", res.StatusCode)
	}
	if page := bodyOf(t, res); !strings.Contains(page, "无权访问") {
		t.Fatalf("403 应呈现错误整页文案（B9①）: %s", page[:min(200, len(page))])
	}

	// ②批量操作空 ids：400 错误呈现（原空体）
	res2 := env.postForm(t, "/mails/batch", cookie, "csrf-b4c", map[string][]string{"action": {"mark-read"}})
	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("空 ids 批量应 400: %d", res2.StatusCode)
	}
	if page := bodyOf(t, res2); !strings.Contains(page, "请求无效") {
		t.Fatalf("批量 400 应呈现可读错误（B9②）: %s", page[:min(200, len(page))])
	}

	// ③CSRF token 失配：403 双态呈现（原空体；文案模糊化不暴露内部细节）
	res3 := env.postForm(t, "/folders", cookie, "wrong-csrf-b4", map[string][]string{"name": {"x"}})
	if res3.StatusCode != http.StatusForbidden {
		t.Fatalf("CSRF 失配应 403: %d", res3.StatusCode)
	}
	if page := bodyOf(t, res3); !strings.Contains(page, "无权执行该操作") {
		t.Fatalf("CSRF 403 应呈现可读错误（B9③）: %s", page[:min(200, len(page))])
	}

	// ④附件不存在（E-2-A）：404 可读错误页（原空体）
	res4 := env.get(t, "/attachments/99999", cookie)
	if res4.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在附件应 404: %d", res4.StatusCode)
	}
	if page := bodyOf(t, res4); !strings.Contains(page, "邮件不存在或已被删除") {
		t.Fatalf("附件 404 应呈现可读错误页（B9④/E-2-A）: %s", page[:min(200, len(page))])
	}
}

// ───────────────────────── B13：顶栏主体标签 Tr 化 ─────────────────────────

// TestBatch4B13LabelTr B13：mailbox 主体顶栏标签双语——zh 界面「我的邮箱」零变化锚
// （原文案承接）；en 界面呈现 "My Mailbox"（原硬编码中文残留收口）。
func TestBatch4B13LabelTr(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b4d")

	// zh（缺省）：原文案零变化
	res := env.get(t, "/", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("zh 列表页状态: %d", res.StatusCode)
	}
	if !strings.Contains(bodyOf(t, res), "我的邮箱") {
		t.Fatal("zh 界面应保持「我的邮箱」原文案（B13 零变化锚）")
	}

	// en（lang cookie 切换）：英文呈现（原硬编码中文收口）
	res2 := env.getWithHeaders(t, "/", cookie, map[string]string{"Cookie": sessionCookieName + "=" + cookie + "; lang=en"})
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("en 列表页状态: %d", res2.StatusCode)
	}
	page2 := bodyOf(t, res2)
	if !strings.Contains(page2, "My Mailbox") {
		t.Fatal("en 界面应呈现 My Mailbox（B13 Tr 化收口锚）")
	}
	if strings.Contains(page2, ">我的邮箱<") {
		t.Fatal("en 界面不得残留硬编码中文标签（B13）")
	}
}

// ───────────────────────── B14：用户侧 2FA 二维码 alt Tr 化 ─────────────────────────

// TestBatch4B14QRAltTr B14：用户侧 /settings/2fa pending 态二维码 alt 经 Tr 渲染
// （复用 admin 侧 twofactor.qrAlt 键——批二 E5 双侧声明用户侧漏改收口）。
func TestBatch4B14QRAltTr(t *testing.T) {
	e := newBatch3Env(t)
	ctx := context.Background()
	cookie := e.b3MailboxLogin(t)
	if _, err := e.twoFA.InitiateBinding(ctx, e.mailbox.ID, e.mailbox.Address, "test.local"); err != nil {
		t.Fatalf("发起绑定: %v", err)
	}
	res := e.getWithCookie(t, "/settings/2fa", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("pending 态 GET 状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, `alt="TOTP 绑定二维码"`) {
		t.Fatal("用户侧二维码 alt 应经 Tr 渲染（B14——原硬编码 TOTP QR 收口）")
	}
	if strings.Contains(page, `alt="TOTP QR"`) {
		t.Fatal("不得残留硬编码英文 alt（B14）")
	}
}
